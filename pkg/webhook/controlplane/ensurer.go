// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/coreos/go-systemd/v22/unit"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/component/nodemanagement/machinecontrollermanager"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	kubeletconfigv1 "k8s.io/kubelet/config/v1"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/imagevector"
	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	ecrCredentialConfigLocation = "/opt/gardener/ecr-credential-provider-config.json"
	ecrCredentialBinLocation    = "/opt/bin/"
)

// NewEnsurer creates a new controlplane ensurer.
func NewEnsurer(logger logr.Logger, client client.Client) genericmutator.Ensurer {
	return &ensurer{
		logger: logger.WithName("aws-controlplane-ensurer"),
		client: client,
	}
}

type ensurer struct {
	genericmutator.NoopEnsurer
	logger logr.Logger
	client client.Client
}

// ImageVector is exposed for testing.
var ImageVector = imagevector.ImageVector()

// EnsureMachineControllerManagerDeployment ensures that the machine-controller-manager deployment conforms to the provider requirements.
func (e *ensurer) EnsureMachineControllerManagerDeployment(_ context.Context, _ gcontext.GardenContext, newObj, _ *appsv1.Deployment) error {
	image, err := ImageVector.FindImage(aws.MachineControllerManagerProviderAWSImageName)
	if err != nil {
		return err
	}

	newObj.Spec.Template.Spec.Containers = extensionswebhook.EnsureContainerWithName(
		newObj.Spec.Template.Spec.Containers,
		machinecontrollermanager.ProviderSidecarContainer(newObj.Namespace, aws.Name, image.String()),
	)
	return nil
}

// EnsureMachineControllerManagerVPA ensures that the machine-controller-manager VPA conforms to the provider requirements.
func (e *ensurer) EnsureMachineControllerManagerVPA(_ context.Context, _ gcontext.GardenContext, newObj, _ *vpaautoscalingv1.VerticalPodAutoscaler) error {
	var (
		minAllowed = corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		}
		maxAllowed = corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("2"),
			corev1.ResourceMemory: resource.MustParse("5G"),
		}
	)

	if newObj.Spec.ResourcePolicy == nil {
		newObj.Spec.ResourcePolicy = &vpaautoscalingv1.PodResourcePolicy{}
	}

	newObj.Spec.ResourcePolicy.ContainerPolicies = extensionswebhook.EnsureVPAContainerResourcePolicyWithName(
		newObj.Spec.ResourcePolicy.ContainerPolicies,
		machinecontrollermanager.ProviderSidecarVPAContainerPolicy(aws.Name, minAllowed, maxAllowed),
	)
	return nil
}

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, gctx gcontext.GardenContext, newObj, _ *appsv1.Deployment) error {
	template := &newObj.Spec.Template
	ps := &template.Spec

	// TODO: This label approach is deprecated and no longer needed in the future. Remove it as soon as gardener/gardener@v1.75 has been released.
	metav1.SetMetaDataLabel(&newObj.Spec.Template.ObjectMeta, gutil.NetworkPolicyLabel(aws.CSISnapshotValidationName, 443), v1beta1constants.LabelNetworkPolicyAllowed)
	metav1.SetMetaDataLabel(&newObj.Spec.Template.ObjectMeta, gutil.NetworkPolicyLabel(aws.AWSLoadBalancerControllerName+"-webhook-service", 9443), v1beta1constants.LabelNetworkPolicyAllowed)

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	k8sVersion, err := semver.NewVersion(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return err
	}

	if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-apiserver"); c != nil {
		ensureKubeAPIServerCommandLineArgs(c, k8sVersion)
		ensureEnvVars(c)
	}

	return e.ensureChecksumAnnotations(&newObj.Spec.Template)
}

// EnsureKubeControllerManagerDeployment ensures that the kube-controller-manager deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeControllerManagerDeployment(ctx context.Context, gctx gcontext.GardenContext, newObj, _ *appsv1.Deployment) error {
	template := &newObj.Spec.Template
	ps := &template.Spec

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	k8sVersion, err := semver.NewVersion(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return err
	}

	cpConfig := &api.ControlPlaneConfig{}
	if cluster.Shoot.Spec.Provider.ControlPlaneConfig != nil {
		err = json.Unmarshal(cluster.Shoot.Spec.Provider.ControlPlaneConfig.Raw, cpConfig)
		if err != nil {
			return err
		}
	}

	if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-controller-manager"); c != nil {
		allocateNodeCIDRs := true
		if cpConfig.IPAMController != nil && cpConfig.IPAMController.Enabled {
			allocateNodeCIDRs = false
		}
		ensureKubeControllerManagerCommandLineArgs(c, k8sVersion, allocateNodeCIDRs)
		ensureEnvVars(c)
		ensureKubeControllerManagerVolumeMounts(c)
	}

	ensureKubeControllerManagerLabels(template)
	ensureKubeControllerManagerVolumes(ps)
	return e.ensureChecksumAnnotations(&newObj.Spec.Template)
}

// EnsureKubeSchedulerDeployment ensures that the kube-scheduler deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeSchedulerDeployment(ctx context.Context, gctx gcontext.GardenContext, newObj, _ *appsv1.Deployment) error {
	template := &newObj.Spec.Template
	ps := &template.Spec

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	k8sVersion, err := semver.NewVersion(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return err
	}

	if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-scheduler"); c != nil {
		ensureKubeSchedulerCommandLineArgs(c, k8sVersion)
	}
	return nil
}

// EnsureClusterAutoscalerDeployment ensures that the cluster-autoscaler deployment conforms to the provider requirements.
func (e *ensurer) EnsureClusterAutoscalerDeployment(ctx context.Context, gctx gcontext.GardenContext, newObj, _ *appsv1.Deployment) error {
	template := &newObj.Spec.Template
	ps := &template.Spec

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	k8sVersion, err := semver.NewVersion(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return err
	}

	if c := extensionswebhook.ContainerWithName(ps.Containers, "cluster-autoscaler"); c != nil {
		ensureClusterAutoscalerCommandLineArgs(c, k8sVersion)
	}
	return nil
}

func ensureKubeAPIServerCommandLineArgs(c *corev1.Container, k8sVersion *semver.Version) {
	if versionutils.ConstraintK8sLess127.Check(k8sVersion) {
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
			"CSIMigration=true", ",")
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
			"CSIMigrationAWS=true", ",")
	}

	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"InTreePluginAWSUnregister=true", ",")
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, "--cloud-provider=")
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, "--cloud-config=")
	c.Command = extensionswebhook.EnsureNoStringWithPrefixContains(c.Command, "--enable-admission-plugins=",
		"PersistentVolumeLabel", ",")
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--disable-admission-plugins=",
		"PersistentVolumeLabel", ",")
}

func ensureKubeControllerManagerCommandLineArgs(c *corev1.Container, k8sVersion *semver.Version, allocateNodeCIDRs bool) {
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--cloud-provider=", "external")

	if versionutils.ConstraintK8sLess127.Check(k8sVersion) {
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
			"CSIMigration=true", ",")
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
			"CSIMigrationAWS=true", ",")
	}

	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"InTreePluginAWSUnregister=true", ",")
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, "--cloud-config=")
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, "--external-cloud-volume-plugin=")

	if !allocateNodeCIDRs {
		for i, v := range c.Command {
			if v == "--allocate-node-cidrs=true" {
				c.Command = append(c.Command[:i], c.Command[i+1:]...)
			}
		}
		c.Command = append(c.Command, "--allocate-node-cidrs=false")
	}
}

func ensureKubeSchedulerCommandLineArgs(c *corev1.Container, k8sVersion *semver.Version) {
	if versionutils.ConstraintK8sLess127.Check(k8sVersion) {
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
			"CSIMigration=true", ",")
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
			"CSIMigrationAWS=true", ",")
	}

	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"InTreePluginAWSUnregister=true", ",")
}

func ensureClusterAutoscalerCommandLineArgs(c *corev1.Container, k8sVersion *semver.Version) {
	if versionutils.ConstraintK8sLess127.Check(k8sVersion) {
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
			"CSIMigration=true", ",")
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
			"CSIMigrationAWS=true", ",")
	}

	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"InTreePluginAWSUnregister=true", ",")
}

func ensureKubeControllerManagerLabels(t *corev1.PodTemplateSpec) {
	// make sure to always remove this label
	delete(t.Labels, v1beta1constants.LabelNetworkPolicyToBlockedCIDRs)

	delete(t.Labels, v1beta1constants.LabelNetworkPolicyToPublicNetworks)
	delete(t.Labels, v1beta1constants.LabelNetworkPolicyToPrivateNetworks)
}

var (
	accessKeyIDEnvVar = corev1.EnvVar{
		Name: "AWS_ACCESS_KEY_ID",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				Key:                  aws.AccessKeyID,
				LocalObjectReference: corev1.LocalObjectReference{Name: v1beta1constants.SecretNameCloudProvider},
			},
		},
	}
	secretAccessKeyEnvVar = corev1.EnvVar{
		Name: "AWS_SECRET_ACCESS_KEY",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				Key:                  aws.SecretAccessKey,
				LocalObjectReference: corev1.LocalObjectReference{Name: v1beta1constants.SecretNameCloudProvider},
			},
		},
	}

	etcSSLName        = "etc-ssl"
	etcSSLVolumeMount = corev1.VolumeMount{
		Name:      etcSSLName,
		MountPath: "/etc/ssl",
		ReadOnly:  true,
	}
	etcSSLVolume = corev1.Volume{
		Name: etcSSLName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/etc/ssl",
				Type: &directoryOrCreate,
			},
		},
	}

	usrShareCaCerts            = "usr-share-cacerts"
	directoryOrCreate          = corev1.HostPathDirectoryOrCreate
	usrShareCaCertsVolumeMount = corev1.VolumeMount{
		Name:      usrShareCaCerts,
		MountPath: "/usr/share/ca-certificates",
		ReadOnly:  true,
	}
	usrShareCaCertsVolume = corev1.Volume{
		Name: usrShareCaCerts,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/usr/share/ca-certificates",
				Type: &directoryOrCreate,
			},
		},
	}
)

func ensureEnvVars(c *corev1.Container) {
	c.Env = extensionswebhook.EnsureNoEnvVarWithName(c.Env, accessKeyIDEnvVar.Name)
	c.Env = extensionswebhook.EnsureNoEnvVarWithName(c.Env, secretAccessKeyEnvVar.Name)
}

func ensureKubeControllerManagerVolumeMounts(c *corev1.Container) {
	c.VolumeMounts = extensionswebhook.EnsureNoVolumeMountWithName(c.VolumeMounts, etcSSLVolumeMount.Name)
	c.VolumeMounts = extensionswebhook.EnsureNoVolumeMountWithName(c.VolumeMounts, usrShareCaCertsVolumeMount.Name)
}

func ensureKubeControllerManagerVolumes(ps *corev1.PodSpec) {
	ps.Volumes = extensionswebhook.EnsureNoVolumeWithName(ps.Volumes, etcSSLVolume.Name)
	ps.Volumes = extensionswebhook.EnsureNoVolumeWithName(ps.Volumes, usrShareCaCertsVolume.Name)
}

func (e *ensurer) ensureChecksumAnnotations(template *corev1.PodTemplateSpec) error {
	delete(template.Annotations, "checksum/secret-"+v1beta1constants.SecretNameCloudProvider)
	delete(template.Annotations, "checksum/configmap-"+aws.CloudProviderConfigName)
	return nil
}

// EnsureKubeletServiceUnitOptions ensures that the kubelet.service unit options conform to the provider requirements.
func (e *ensurer) EnsureKubeletServiceUnitOptions(ctx context.Context, gctx gcontext.GardenContext, kubeletVersion *semver.Version, newObj, _ []*unit.UnitOption) ([]*unit.UnitOption, error) {
	if opt := extensionswebhook.UnitOptionWithSectionAndName(newObj, "Service", "ExecStart"); opt != nil {
		command := extensionswebhook.DeserializeCommandLine(opt.Value)
		command = extensionswebhook.EnsureStringWithPrefix(command, "--cloud-provider=", "external")

		cluster, err := gctx.GetCluster(ctx)
		if err != nil {
			return nil, err
		}

		k8sGreaterEqual127, err := versionutils.CompareVersions(kubeletVersion.String(), ">=", "1.27")
		if err != nil {
			return nil, err
		}

		if k8sGreaterEqual127 {
			infra := &extensionsv1alpha1.Infrastructure{}
			if err := e.client.Get(ctx, client.ObjectKey{
				Namespace: cluster.ObjectMeta.Name,
				Name:      cluster.Shoot.Name,
			}, infra); err != nil {
				return nil, err
			}
			infraConfig, err := helper.InfrastructureConfigFromInfrastructure(infra)
			if err != nil {
				return nil, err
			}

			if ptr.Deref(infraConfig.EnableECRAccess, true) {
				command = ensureKubeletECRProviderCommandLineArgs(command)
			}
		}

		opt.Value = extensionswebhook.SerializeCommandLine(command, 1, " \\\n    ")
	}

	newObj = extensionswebhook.EnsureUnitOption(newObj, &unit.UnitOption{
		Section: "Service",
		Name:    "ExecStartPre",
		Value:   `/bin/sh -c 'hostnamectl set-hostname $(hostname -f)'`,
	})

	return newObj, nil
}

func ensureKubeletECRProviderCommandLineArgs(command []string) []string {
	command = extensionswebhook.EnsureStringWithPrefix(command, "--image-credential-provider-config=", ecrCredentialConfigLocation)
	command = extensionswebhook.EnsureStringWithPrefix(command, "--image-credential-provider-bin-dir=", ecrCredentialBinLocation)
	return command
}

// EnsureKubeletConfiguration ensures that the kubelet configuration conforms to the provider requirements.
func (e *ensurer) EnsureKubeletConfiguration(_ context.Context, _ gcontext.GardenContext, kubeletVersion *semver.Version, newObj, _ *kubeletconfigv1beta1.KubeletConfiguration) error {
	if newObj.FeatureGates == nil {
		newObj.FeatureGates = make(map[string]bool)
	}

	if versionutils.ConstraintK8sLess127.Check(kubeletVersion) {
		newObj.FeatureGates["CSIMigration"] = true
		newObj.FeatureGates["CSIMigrationAWS"] = true
	}

	newObj.FeatureGates["InTreePluginAWSUnregister"] = true
	newObj.EnableControllerAttachDetach = ptr.To(true)

	return nil
}

var regexFindProperty = regexp.MustCompile("net.ipv4.neigh.default.gc_thresh1[[:space:]]*=[[:space:]]*([[:alnum:]]+)")

// EnsureKubernetesGeneralConfiguration ensures that the kubernetes general configuration conforms to the provider requirements.
func (e *ensurer) EnsureKubernetesGeneralConfiguration(_ context.Context, _ gcontext.GardenContext, newObj, _ *string) error {
	// If the needed property exists, ensure the correct value
	if regexFindProperty.MatchString(*newObj) {
		res := regexFindProperty.ReplaceAll([]byte(*newObj), []byte("net.ipv4.neigh.default.gc_thresh1 = 0"))
		*newObj = string(res)
		return nil
	}

	// If the property do not exist, append it in the end of the string
	buf := bytes.Buffer{}
	buf.WriteString(*newObj)
	buf.WriteString("\n")
	buf.WriteString("# AWS specific settings\n")
	buf.WriteString("# See https://github.com/kubernetes/kubernetes/issues/23395\n")
	buf.WriteString("net.ipv4.neigh.default.gc_thresh1 = 0")

	*newObj = buf.String()
	return nil
}

// EnsureAdditionalUnits ensures that additional required system units are added.
func (e *ensurer) EnsureAdditionalUnits(_ context.Context, _ gcontext.GardenContext, newObj, _ *[]extensionsv1alpha1.Unit) error {
	var (
		customMTUUnitContent = `[Unit]
Description=Apply a custom MTU to network interfaces
After=network.target
Wants=network.target

[Install]
WantedBy=kubelet.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/bin/mtu-customizer.sh
`
	)

	extensionswebhook.AppendUniqueUnit(newObj, extensionsv1alpha1.Unit{
		Name:    "custom-mtu.service",
		Enable:  ptr.To(true),
		Command: ptr.To(extensionsv1alpha1.CommandStart),
		Content: &customMTUUnitContent,
	})
	return nil
}

func (e *ensurer) credentialProviderBinaryFile() (*extensionsv1alpha1.File, error) {
	image, err := imagevector.ImageVector().FindImage(aws.ECRCredentialProviderImageName)
	if err != nil {
		return nil, err
	}
	config := &extensionsv1alpha1.File{
		Path:        v1beta1constants.OperatingSystemConfigFilePathBinaries + "/ecr-credential-provider",
		Permissions: ptr.To[int32](0755),
		Content: extensionsv1alpha1.FileContent{
			ImageRef: &extensionsv1alpha1.FileContentImageRef{

				Image:           image.String(),
				FilePathInImage: "/bin/ecr-credential-provider",
			},
		},
	}
	return config, nil
}

func (e *ensurer) credentialProviderConfigFile() (*extensionsv1alpha1.File, error) {
	var (
		permissions int32 = 0755
	)
	cacheDuration, err := time.ParseDuration("1h")
	if err != nil {
		return nil, err
	}
	credentialProvider := kubeletconfigv1.CredentialProvider{
		APIVersion: "credentialprovider.kubelet.k8s.io/v1",
		Name:       "ecr-credential-provider",
		// The hardcoded list is generated from the set between the official documentation and some kubernetes files:
		// https://cloud-provider-aws.sigs.k8s.io/credential_provider/
		// https://github.com/kubernetes/kubernetes/blob/master/test/e2e_node/remote/utils.go#L65
		MatchImages: []string{
			"*.dkr.ecr.*.amazonaws.com",
			"*.dkr.ecr.*.amazonaws.com.cn",
			"*.dkr.ecr-fips.*.amazonaws.com",
			"*.dkr.ecr.us-iso-east-1.c2s.ic.gov",
			"*.dkr.ecr.us-isob-east-1.sc2s.sgov.gov",
		},
		DefaultCacheDuration: &metav1.Duration{Duration: cacheDuration},
	}
	config := kubeletconfigv1.CredentialProviderConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: kubeletconfigv1.SchemeGroupVersion.String(),
			Kind:       "CredentialProviderConfig",
		},
		Providers: []kubeletconfigv1.CredentialProvider{
			credentialProvider,
		},
	}

	configJson, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return &extensionsv1alpha1.File{
		Path:        ecrCredentialConfigLocation,
		Permissions: &permissions,
		Content: extensionsv1alpha1.FileContent{
			Inline: &extensionsv1alpha1.FileContentInline{
				Data: string(configJson),
			},
		},
	}, nil
}

func (e *ensurer) ensureMTUFiles() extensionsv1alpha1.File {
	var (
		permissions       int32 = 0755
		customFileContent       = `#!/bin/sh

for interface_path in $(find /sys/class/net  -type l -print)
do
	interface=$(basename ${interface_path})

	if ls -l ${interface_path} | grep -q virtual
	then
		echo skipping virtual interface: ${interface}
		continue
	fi

	echo changing mtu of non-virtual interface: ${interface}
	ip link set dev ${interface} mtu 1460
done
`
	)

	return extensionsv1alpha1.File{
		Path:        "/opt/bin/mtu-customizer.sh",
		Permissions: &permissions,
		Content: extensionsv1alpha1.FileContent{
			Inline: &extensionsv1alpha1.FileContentInline{
				Encoding: "",
				Data:     customFileContent,
			},
		},
	}
}

// EnsureAdditionalFiles ensures that additional required system files are added.
func (e *ensurer) EnsureAdditionalFiles(ctx context.Context, gctx gcontext.GardenContext, newObj, _ *[]extensionsv1alpha1.File) error {
	*newObj = extensionswebhook.EnsureFileWithPath(*newObj, e.ensureMTUFiles())

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	k8sGreaterEqual127, err := versionutils.CompareVersions(cluster.Shoot.Spec.Kubernetes.Version, ">=", "1.27")
	if err != nil {
		return err
	}

	// return early
	if !k8sGreaterEqual127 {
		return nil
	}

	infra := &extensionsv1alpha1.Infrastructure{}
	if err := e.client.Get(ctx, client.ObjectKey{
		Namespace: cluster.ObjectMeta.Name,
		Name:      cluster.Shoot.Name,
	}, infra); err != nil {
		return err
	}

	infraConfig, err := helper.InfrastructureConfigFromInfrastructure(infra)
	if err != nil {
		return err
	}

	if ptr.Deref(infraConfig.EnableECRAccess, true) {
		binConfig, err := e.credentialProviderBinaryFile()
		if err != nil {
			return err
		}
		credConfig, err := e.credentialProviderConfigFile()
		if err != nil {
			return err
		}

		*newObj = extensionswebhook.EnsureFileWithPath(*newObj, *binConfig)
		*newObj = extensionswebhook.EnsureFileWithPath(*newObj, *credConfig)
	}

	return nil
}
