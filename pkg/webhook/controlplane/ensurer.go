// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplane

import (
	"bytes"
	"context"
	"regexp"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"

	"github.com/Masterminds/semver"
	"github.com/coreos/go-systemd/v22/unit"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewEnsurer creates a new controlplane ensurer.
func NewEnsurer(logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		logger: logger.WithName("aws-controlplane-ensurer"),
	}
}

type ensurer struct {
	genericmutator.NoopEnsurer
	client client.Client
	logger logr.Logger
}

// InjectClient injects the given client into the ensurer.
func (e *ensurer) InjectClient(client client.Client) error {
	e.client = client
	return nil
}

func computeCSIMigrationCompleteFeatureGate(version string) (string, error) {
	k8sGreaterEqual121, err := versionutils.CompareVersions(version, ">=", "1.21")
	if err != nil {
		return "", err
	}

	if k8sGreaterEqual121 {
		return "InTreePluginAWSUnregister", nil
	}
	return "CSIMigrationAWSComplete", nil
}

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, gctx gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	template := &new.Spec.Template
	ps := &template.Spec

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	csiMigrationCompleteFeatureGate, err := computeCSIMigrationCompleteFeatureGate(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return err
	}

	if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-apiserver"); c != nil {
		ensureKubeAPIServerCommandLineArgs(c, csiMigrationCompleteFeatureGate)
		ensureEnvVars(c)
		ensureKubeAPIServerVolumeMounts(c)
	}

	ensureKubeAPIServerVolumes(ps)
	return e.ensureChecksumAnnotations(&new.Spec.Template)
}

// EnsureKubeControllerManagerDeployment ensures that the kube-controller-manager deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeControllerManagerDeployment(ctx context.Context, gctx gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	template := &new.Spec.Template
	ps := &template.Spec

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	csiMigrationCompleteFeatureGate, err := computeCSIMigrationCompleteFeatureGate(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return err
	}

	if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-controller-manager"); c != nil {
		ensureKubeControllerManagerCommandLineArgs(c, csiMigrationCompleteFeatureGate)
		ensureEnvVars(c)
		ensureKubeControllerManagerVolumeMounts(c)
	}

	ensureKubeControllerManagerLabels(template)
	ensureKubeControllerManagerVolumes(ps)
	return e.ensureChecksumAnnotations(&new.Spec.Template)
}

// EnsureKubeSchedulerDeployment ensures that the kube-scheduler deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeSchedulerDeployment(ctx context.Context, gctx gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	template := &new.Spec.Template
	ps := &template.Spec

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	csiMigrationCompleteFeatureGate, err := computeCSIMigrationCompleteFeatureGate(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return err
	}

	if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-scheduler"); c != nil {
		ensureKubeSchedulerCommandLineArgs(c, csiMigrationCompleteFeatureGate)
	}
	return nil
}

// EnsureClusterAutoscalerDeployment ensures that the cluster-autoscaler deployment conforms to the provider requirements.
func (e *ensurer) EnsureClusterAutoscalerDeployment(ctx context.Context, gctx gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	template := &new.Spec.Template
	ps := &template.Spec

	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	// cluster-autoscaler supports the "--feature-gates" flag starting 1.20.
	// Exit early and do not add the "--feature-gates" flag for K8s < 1.20 Shoots.
	k8sLessThan120, err := versionutils.CompareVersions(cluster.Shoot.Spec.Kubernetes.Version, "<", "1.20")
	if err != nil {
		return err
	}
	if k8sLessThan120 {
		return nil
	}

	// At this point K8s >= 1.20. As CSIMigrationKubernetesVersion is 1.18, we can assume that CSI is enabled and CSI migration is complete.
	csiMigrationCompleteFeatureGate, err := computeCSIMigrationCompleteFeatureGate(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return err
	}

	if c := extensionswebhook.ContainerWithName(ps.Containers, "cluster-autoscaler"); c != nil {
		ensureClusterAutoscalerCommandLineArgs(c, csiMigrationCompleteFeatureGate)
	}
	return nil
}

func ensureKubeAPIServerCommandLineArgs(c *corev1.Container, csiMigrationCompleteFeatureGate string) {
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"CSIMigration=true", ",")
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"CSIMigrationAWS=true", ",")

	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		csiMigrationCompleteFeatureGate+"=true", ",")
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, "--cloud-provider=")
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, "--cloud-config=")
	c.Command = extensionswebhook.EnsureNoStringWithPrefixContains(c.Command, "--enable-admission-plugins=",
		"PersistentVolumeLabel", ",")
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--disable-admission-plugins=",
		"PersistentVolumeLabel", ",")
}

func ensureKubeControllerManagerCommandLineArgs(c *corev1.Container, csiMigrationCompleteFeatureGate string) {
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--cloud-provider=", "external")

	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"CSIMigration=true", ",")
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"CSIMigrationAWS=true", ",")

	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		csiMigrationCompleteFeatureGate+"=true", ",")
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, "--cloud-config=")
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, "--external-cloud-volume-plugin=")
}

func ensureKubeSchedulerCommandLineArgs(c *corev1.Container, csiMigrationCompleteFeatureGate string) {
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"CSIMigration=true", ",")
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"CSIMigrationAWS=true", ",")

	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		csiMigrationCompleteFeatureGate+"=true", ",")
}

// ensureClusterAutoscalerCommandLineArgs ensures the cluster-autoscaler command line args.
// cluster-autoscaler supports the "--feature-gates" flag starting 1.20. This func assumes that
// the K8s version is >= 1.20 which means that CSI is enabled and CSI migration is complete.
func ensureClusterAutoscalerCommandLineArgs(c *corev1.Container, csiMigrationCompleteFeatureGate string) {
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"CSIMigration=true", ",")
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		"CSIMigrationAWS=true", ",")
	c.Command = extensionswebhook.EnsureStringWithPrefixContains(c.Command, "--feature-gates=",
		csiMigrationCompleteFeatureGate+"=true", ",")
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

	cloudProviderConfigVolumeMount = corev1.VolumeMount{
		Name:      aws.CloudProviderConfigName,
		MountPath: "/etc/kubernetes/cloudprovider",
	}
	cloudProviderConfigVolume = corev1.Volume{
		Name: aws.CloudProviderConfigName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: aws.CloudProviderConfigName},
			},
		},
	}
)

func ensureEnvVars(c *corev1.Container) {
	c.Env = extensionswebhook.EnsureNoEnvVarWithName(c.Env, accessKeyIDEnvVar.Name)
	c.Env = extensionswebhook.EnsureNoEnvVarWithName(c.Env, secretAccessKeyEnvVar.Name)
}

func ensureKubeAPIServerVolumeMounts(c *corev1.Container) {
	c.VolumeMounts = extensionswebhook.EnsureNoVolumeMountWithName(c.VolumeMounts, cloudProviderConfigVolumeMount.Name)
}

func ensureKubeControllerManagerVolumeMounts(c *corev1.Container) {
	c.VolumeMounts = extensionswebhook.EnsureNoVolumeMountWithName(c.VolumeMounts, cloudProviderConfigVolumeMount.Name)
	c.VolumeMounts = extensionswebhook.EnsureNoVolumeMountWithName(c.VolumeMounts, etcSSLVolumeMount.Name)
	c.VolumeMounts = extensionswebhook.EnsureNoVolumeMountWithName(c.VolumeMounts, usrShareCaCertsVolumeMount.Name)
}

func ensureKubeAPIServerVolumes(ps *corev1.PodSpec) {
	ps.Volumes = extensionswebhook.EnsureNoVolumeWithName(ps.Volumes, cloudProviderConfigVolume.Name)
}

func ensureKubeControllerManagerVolumes(ps *corev1.PodSpec) {
	ps.Volumes = extensionswebhook.EnsureNoVolumeWithName(ps.Volumes, cloudProviderConfigVolume.Name)
	ps.Volumes = extensionswebhook.EnsureNoVolumeWithName(ps.Volumes, etcSSLVolume.Name)
	ps.Volumes = extensionswebhook.EnsureNoVolumeWithName(ps.Volumes, usrShareCaCertsVolume.Name)
}

func (e *ensurer) ensureChecksumAnnotations(template *corev1.PodTemplateSpec) error {
	delete(template.Annotations, "checksum/secret-"+v1beta1constants.SecretNameCloudProvider)
	delete(template.Annotations, "checksum/configmap-"+aws.CloudProviderConfigName)
	return nil
}

// EnsureKubeletServiceUnitOptions ensures that the kubelet.service unit options conform to the provider requirements.
func (e *ensurer) EnsureKubeletServiceUnitOptions(_ context.Context, _ gcontext.GardenContext, kubeletVersion *semver.Version, new, _ []*unit.UnitOption) ([]*unit.UnitOption, error) {
	if opt := extensionswebhook.UnitOptionWithSectionAndName(new, "Service", "ExecStart"); opt != nil {
		command := extensionswebhook.DeserializeCommandLine(opt.Value)
		command = ensureKubeletCommandLineArgs(command, kubeletVersion)
		opt.Value = extensionswebhook.SerializeCommandLine(command, 1, " \\\n    ")
	}

	new = extensionswebhook.EnsureUnitOption(new, &unit.UnitOption{
		Section: "Service",
		Name:    "ExecStartPre",
		Value:   `/bin/sh -c 'hostnamectl set-hostname $(hostname -f)'`,
	})

	return new, nil
}

func ensureKubeletCommandLineArgs(command []string, kubeletVersion *semver.Version) []string {
	command = extensionswebhook.EnsureStringWithPrefix(command, "--cloud-provider=", "external")
	if !versionutils.ConstraintK8sGreaterEqual123.Check(kubeletVersion) {
		command = extensionswebhook.EnsureStringWithPrefix(command, "--enable-controller-attach-detach=", "true")
	}
	return command
}

// EnsureKubeletConfiguration ensures that the kubelet configuration conforms to the provider requirements.
func (e *ensurer) EnsureKubeletConfiguration(_ context.Context, _ gcontext.GardenContext, kubeletVersion *semver.Version, new, _ *kubeletconfigv1beta1.KubeletConfiguration) error {
	csiMigrationCompleteFeatureGate, err := computeCSIMigrationCompleteFeatureGate(kubeletVersion.String())
	if err != nil {
		return err
	}

	if new.FeatureGates == nil {
		new.FeatureGates = make(map[string]bool)
	}

	new.FeatureGates["CSIMigration"] = true
	new.FeatureGates["CSIMigrationAWS"] = true
	// kubelets of new worker nodes can directly be started with the the <csiMigrationCompleteFeatureGate> feature gate
	new.FeatureGates[csiMigrationCompleteFeatureGate] = true

	if versionutils.ConstraintK8sGreaterEqual123.Check(kubeletVersion) {
		new.EnableControllerAttachDetach = pointer.Bool(true)
	}

	return nil
}

var regexFindProperty = regexp.MustCompile("net.ipv4.neigh.default.gc_thresh1[[:space:]]*=[[:space:]]*([[:alnum:]]+)")

// EnsureKubernetesGeneralConfiguration ensures that the kubernetes general configuration conforms to the provider requirements.
func (e *ensurer) EnsureKubernetesGeneralConfiguration(_ context.Context, _ gcontext.GardenContext, new, _ *string) error {
	// If the needed property exists, ensure the correct value
	if regexFindProperty.MatchString(*new) {
		res := regexFindProperty.ReplaceAll([]byte(*new), []byte("net.ipv4.neigh.default.gc_thresh1 = 0"))
		*new = string(res)
		return nil
	}

	// If the property do not exist, append it in the end of the string
	buf := bytes.Buffer{}
	buf.WriteString(*new)
	buf.WriteString("\n")
	buf.WriteString("# AWS specific settings\n")
	buf.WriteString("# See https://github.com/kubernetes/kubernetes/issues/23395\n")
	buf.WriteString("net.ipv4.neigh.default.gc_thresh1 = 0")

	*new = buf.String()
	return nil
}

// EnsureAdditionalUnits ensures that additional required system units are added.
func (e *ensurer) EnsureAdditionalUnits(_ context.Context, _ gcontext.GardenContext, new, _ *[]extensionsv1alpha1.Unit) error {
	var (
		command              = "start"
		trueVar              = true
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

	extensionswebhook.AppendUniqueUnit(new, extensionsv1alpha1.Unit{
		Name:    "custom-mtu.service",
		Enable:  &trueVar,
		Command: &command,
		Content: &customMTUUnitContent,
	})
	return nil
}

// EnsureAdditionalFiles ensures that additional required system files are added.
func (e *ensurer) EnsureAdditionalFiles(_ context.Context, _ gcontext.GardenContext, new, _ *[]extensionsv1alpha1.File) error {
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

	appendUniqueFile(new, extensionsv1alpha1.File{
		Path:        "/opt/bin/mtu-customizer.sh",
		Permissions: &permissions,
		Content: extensionsv1alpha1.FileContent{
			Inline: &extensionsv1alpha1.FileContentInline{
				Encoding: "",
				Data:     customFileContent,
			},
		},
	})
	return nil
}

// appendUniqueFile appends a unit file only if it does not exist, otherwise overwrite content of previous files
func appendUniqueFile(files *[]extensionsv1alpha1.File, file extensionsv1alpha1.File) {
	resFiles := make([]extensionsv1alpha1.File, 0, len(*files))

	for _, f := range *files {
		if f.Path != file.Path {
			resFiles = append(resFiles, f)
		}
	}

	*files = append(resFiles, file)
}
