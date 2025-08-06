// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane/genericactuator"
	extensionssecretmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	securityv1alpha1constants "github.com/gardener/gardener/pkg/apis/security/v1alpha1/constants"
	"github.com/gardener/gardener/pkg/utils/chart"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/charts"
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	caNameControlPlane               = "ca-" + aws.Name + "-controlplane"
	cloudControllerManagerServerName = "cloud-controller-manager-server"
	awsLoadBalancerControllerWebhook = aws.AWSLoadBalancerControllerName + "-webhook-service"
)

func secretConfigsFunc(namespace string) []extensionssecretmanager.SecretConfigWithOptions {
	return []extensionssecretmanager.SecretConfigWithOptions{
		{
			Config: &secretutils.CertificateSecretConfig{
				Name:       caNameControlPlane,
				CommonName: caNameControlPlane,
				CertType:   secretutils.CACert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.Persist()},
		},
		{
			Config: &secretutils.CertificateSecretConfig{
				Name:                        cloudControllerManagerServerName,
				CommonName:                  aws.CloudControllerManagerName,
				DNSNames:                    kutil.DNSNamesForService(aws.CloudControllerManagerName, namespace),
				CertType:                    secretutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(caNameControlPlane)},
		},
		{
			Config: &secretutils.CertificateSecretConfig{
				Name:                        awsLoadBalancerControllerWebhook,
				CommonName:                  awsLoadBalancerControllerWebhook,
				DNSNames:                    kutil.DNSNamesForService(awsLoadBalancerControllerWebhook, namespace),
				CertType:                    secretutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			// use current CA for signing server cert to prevent mismatches when dropping the old CA from the webhook
			// config in phase Completing
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(caNameControlPlane, secretsmanager.UseCurrentCA)},
		},
	}
}

func shootAccessSecretsFunc(namespace string) []*gutil.AccessSecret {
	return []*gutil.AccessSecret{
		gutil.NewShootAccessSecret(aws.CloudControllerManagerName, namespace),
		gutil.NewShootAccessSecret(aws.AWSCustomRouteControllerName, namespace),
		gutil.NewShootAccessSecret(aws.AWSIPAMControllerName, namespace),
		gutil.NewShootAccessSecret(aws.AWSLoadBalancerControllerName, namespace),
		gutil.NewShootAccessSecret(aws.CSIProvisionerName, namespace),
		gutil.NewShootAccessSecret(aws.CSIAttacherName, namespace),
		gutil.NewShootAccessSecret(aws.CSISnapshotterName, namespace),
		gutil.NewShootAccessSecret(aws.CSIResizerName, namespace),
		gutil.NewShootAccessSecret(aws.CSISnapshotControllerName, namespace),
		gutil.NewShootAccessSecret(aws.CSIVolumeModifierName, namespace),
	}
}

var (
	configChart = &chart.Chart{
		Name:       "cloud-provider-config",
		EmbeddedFS: charts.InternalChart,
		Path:       filepath.Join(charts.InternalChartsPath, "cloud-provider-config"),
		Objects: []*chart.Object{
			{
				Type: &corev1.ConfigMap{},
				Name: aws.CloudProviderConfigName,
			},
		},
	}

	controlPlaneChart = &chart.Chart{
		Name:       "seed-controlplane",
		EmbeddedFS: charts.InternalChart,
		Path:       filepath.Join(charts.InternalChartsPath, "seed-controlplane"),
		SubCharts: []*chart.Chart{
			{
				Name:   aws.CloudControllerManagerName,
				Images: []string{aws.CloudControllerManagerImageName},
				Objects: []*chart.Object{
					{Type: &corev1.Service{}, Name: aws.CloudControllerManagerName},
					{Type: &appsv1.Deployment{}, Name: aws.CloudControllerManagerName},
					{Type: &monitoringv1.ServiceMonitor{}, Name: "shoot-cloud-controller-manager"},
					{Type: &monitoringv1.PrometheusRule{}, Name: "shoot-cloud-controller-manager"},
					{Type: &vpaautoscalingv1.VerticalPodAutoscaler{}, Name: aws.CloudControllerManagerName + "-vpa"},
				},
			},
			{
				Name:   aws.AWSCustomRouteControllerName,
				Images: []string{aws.AWSCustomRouteControllerImageName},
				Objects: []*chart.Object{
					{Type: &appsv1.Deployment{}, Name: aws.AWSCustomRouteControllerName},
					{Type: &rbacv1.Role{}, Name: aws.AWSCustomRouteControllerName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.AWSCustomRouteControllerName},
					{Type: &corev1.ServiceAccount{}, Name: aws.AWSCustomRouteControllerName},
					{Type: &vpaautoscalingv1.VerticalPodAutoscaler{}, Name: aws.AWSCustomRouteControllerName + "-vpa"},
				},
				SubCharts: nil,
			},
			{
				Name:   aws.AWSIPAMControllerName,
				Images: []string{aws.AWSIPAMControllerImageName},
				Objects: []*chart.Object{
					{Type: &appsv1.Deployment{}, Name: aws.AWSIPAMControllerName},
					{Type: &rbacv1.Role{}, Name: aws.AWSIPAMControllerName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.AWSIPAMControllerName},
					{Type: &corev1.ServiceAccount{}, Name: aws.AWSIPAMControllerName},
					{Type: &vpaautoscalingv1.VerticalPodAutoscaler{}, Name: aws.AWSIPAMControllerName + "-vpa"},
				},
				SubCharts: nil,
			},
			{
				Name:   aws.AWSLoadBalancerControllerName,
				Images: []string{aws.AWSLoacBalancerControllerImageName},
				Objects: []*chart.Object{
					{Type: &appsv1.Deployment{}, Name: aws.AWSLoadBalancerControllerName},
					{Type: &vpaautoscalingv1.VerticalPodAutoscaler{}, Name: aws.AWSLoadBalancerControllerName},
					{Type: &corev1.Service{}, Name: awsLoadBalancerControllerWebhook},
					{Type: &corev1.Service{}, Name: aws.AWSLoadBalancerControllerName},
				},
			},
			{
				Name: aws.CSIControllerName,
				Images: []string{
					aws.CSIDriverImageName,
					aws.CSIProvisionerImageName,
					aws.CSIAttacherImageName,
					aws.CSISnapshotterImageName,
					aws.CSIResizerImageName,
					aws.CSILivenessProbeImageName,
					aws.CSISnapshotControllerImageName,
					aws.CSIVolumeModifierImageName,
				},
				Objects: []*chart.Object{
					// csi-driver-controller
					{Type: &appsv1.Deployment{}, Name: aws.CSIControllerName},
					{Type: &vpaautoscalingv1.VerticalPodAutoscaler{}, Name: aws.CSIControllerName + "-vpa"},
					// csi-snapshot-controller
					{Type: &appsv1.Deployment{}, Name: aws.CSISnapshotControllerName},
					{Type: &vpaautoscalingv1.VerticalPodAutoscaler{}, Name: aws.CSISnapshotControllerName + "-vpa"},
				},
			},
		},
	}

	controlPlaneShootChart = &chart.Chart{
		Name:       "shoot-system-components",
		EmbeddedFS: charts.InternalChart,
		Path:       filepath.Join(charts.InternalChartsPath, "shoot-system-components"),
		SubCharts: []*chart.Chart{
			{
				Name: aws.CloudControllerManagerName,
				Objects: []*chart.Object{
					{Type: &rbacv1.ClusterRoleBinding{}, Name: "extensions.gardener.cloud:provider-aws:cloud-controller-manager"},
				},
			},
			{
				Name: aws.AWSCustomRouteControllerName,
				Objects: []*chart.Object{
					{Type: &rbacv1.ClusterRole{}, Name: "extensions.gardener.cloud:provider-aws:aws-custom-route-controller"},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: "extensions.gardener.cloud:provider-aws:aws-custom-route-controller"},
				},
			},
			{
				Name: aws.AWSIPAMControllerName,
				Objects: []*chart.Object{
					{Type: &rbacv1.ClusterRole{}, Name: "extensions.gardener.cloud:provider-aws:aws-ipam-controller"},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: "extensions.gardener.cloud:provider-aws:aws-ipam-controller"},
				},
			},
			{
				Name: aws.AWSLoadBalancerControllerName,
				Objects: []*chart.Object{
					{Type: &rbacv1.Role{}, Name: aws.AWSLoadBalancerControllerName + "-leader-election-role"},
					{Type: &rbacv1.RoleBinding{}, Name: aws.AWSLoadBalancerControllerName + "-leader-election-rolebinding"},
					{Type: &rbacv1.ClusterRole{}, Name: aws.AWSLoadBalancerControllerName + "-role"},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.AWSLoadBalancerControllerName + "-rolebinding"},
					{Type: &corev1.ServiceAccount{}, Name: aws.AWSLoadBalancerControllerName},
					{Type: &admissionregistrationv1.MutatingWebhookConfiguration{}, Name: aws.AWSLoadBalancerControllerName + "-webhook"},
					{Type: &admissionregistrationv1.ValidatingWebhookConfiguration{}, Name: aws.AWSLoadBalancerControllerName + "-webhook"},
					{Type: &policyv1.PodDisruptionBudget{}, Name: aws.AWSLoadBalancerControllerName},
				},
			},
			{
				Name: aws.CSINodeName,
				Images: []string{
					aws.CSIDriverImageName,
					aws.CSINodeDriverRegistrarImageName,
					aws.CSILivenessProbeImageName,
				},
				Objects: []*chart.Object{
					// csi-driver
					{Type: &appsv1.DaemonSet{}, Name: aws.CSINodeName},
					{Type: &storagev1.CSIDriver{}, Name: "ebs.csi.aws.com"},
					{Type: &corev1.ServiceAccount{}, Name: aws.CSIDriverName},
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSIDriverName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSIDriverName},
					// csi-provisioner
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSIProvisionerName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSIProvisionerName},
					{Type: &rbacv1.Role{}, Name: aws.UsernamePrefix + aws.CSIProvisionerName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.UsernamePrefix + aws.CSIProvisionerName},
					// csi-attacher
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSIAttacherName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSIAttacherName},
					{Type: &rbacv1.Role{}, Name: aws.UsernamePrefix + aws.CSIAttacherName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.UsernamePrefix + aws.CSIAttacherName},
					// csi-snapshot-controller
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSISnapshotControllerName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSISnapshotControllerName},
					{Type: &rbacv1.Role{}, Name: aws.UsernamePrefix + aws.CSISnapshotControllerName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.UsernamePrefix + aws.CSISnapshotControllerName},
					// csi-snapshotter
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSISnapshotterName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSISnapshotterName},
					{Type: &rbacv1.Role{}, Name: aws.UsernamePrefix + aws.CSISnapshotterName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.UsernamePrefix + aws.CSISnapshotterName},
					// csi-resizer
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSIResizerName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSIResizerName},
					{Type: &rbacv1.Role{}, Name: aws.UsernamePrefix + aws.CSIResizerName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.UsernamePrefix + aws.CSIResizerName},
					// csi-volume-modifier
					{Type: &corev1.ServiceAccount{}, Name: aws.CSIVolumeModifierName},
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSIVolumeModifierName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSIVolumeModifierName},
					{Type: &rbacv1.Role{}, Name: aws.UsernamePrefix + aws.CSIVolumeModifierName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.UsernamePrefix + aws.CSIVolumeModifierName},
				},
			},
			{
				Name: aws.CSIEfsNodeName,
				Images: []string{
					aws.CSIDriverEfsImageName,
					aws.CSINodeDriverRegistrarImageName,
					aws.CSILivenessProbeImageName,
					aws.CSIProvisionerImageName,
				},
				Objects: []*chart.Object{
					// csi-driver-efs-node
					{Type: &appsv1.DaemonSet{}, Name: aws.CSIEfsNodeName},
					{Type: &storagev1.CSIDriver{}, Name: "efs.csi.aws.com"},
					{Type: &corev1.ServiceAccount{}, Name: "efs-csi-node-sa"},
					{Type: &rbacv1.ClusterRole{}, Name: "efs-csi-node-role"},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: "efs-csi-node-binding"},
					// csi-driver-efs-controller
					{Type: &appsv1.Deployment{}, Name: "efs-csi-controller"},
					{Type: &corev1.ServiceAccount{}, Name: "efs-csi-controller-sa"},
					{Type: &rbacv1.ClusterRole{}, Name: "efs-csi-external-provisioner-role"},
					{Type: &rbacv1.ClusterRole{}, Name: "efs-csi-external-provisioner-role-describe-secrets"},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: "efs-csi-provisioner-binding"},
					{Type: &rbacv1.RoleBinding{}, Name: "efs-csi-provisioner-binding"},
				},
			},
		},
	}

	controlPlaneShootCRDsChart = &chart.Chart{
		Name:       "shoot-crds",
		EmbeddedFS: charts.InternalChart,
		Path:       filepath.Join(charts.InternalChartsPath, "shoot-crds"),
		SubCharts: []*chart.Chart{
			{
				Name: "volumesnapshots",
				Objects: []*chart.Object{
					{Type: &apiextensionsv1.CustomResourceDefinition{}, Name: "volumesnapshotclasses.snapshot.storage.k8s.io"},
					{Type: &apiextensionsv1.CustomResourceDefinition{}, Name: "volumesnapshotcontents.snapshot.storage.k8s.io"},
					{Type: &apiextensionsv1.CustomResourceDefinition{}, Name: "volumesnapshots.snapshot.storage.k8s.io"},
				},
			},
			{
				Name: "aws-load-balancer-controller",
				Objects: []*chart.Object{
					{Type: &apiextensionsv1.CustomResourceDefinition{}, Name: "ingressclassparams.elbv2.k8s.aws"},
					{Type: &apiextensionsv1.CustomResourceDefinition{}, Name: "targetgroupbindings.elbv2.k8s.aws"},
				},
			},
		},
	}

	storageClassChart = &chart.Chart{
		Name:       "shoot-storageclasses",
		EmbeddedFS: charts.InternalChart,
		Path:       filepath.Join(charts.InternalChartsPath, "shoot-storageclasses"),
	}
)

// NewValuesProvider creates a new ValuesProvider for the generic actuator.
func NewValuesProvider(mgr manager.Manager) genericactuator.ValuesProvider {
	return &valuesProvider{
		client:  mgr.GetClient(),
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
	}
}

// valuesProvider is a ValuesProvider that provides AWS-specific values for the 2 charts applied by the generic actuator.
type valuesProvider struct {
	genericactuator.NoopValuesProvider
	client  k8sclient.Client
	decoder runtime.Decoder
}

// GetConfigChartValues returns the values for the config chart applied by the generic actuator.
func (vp *valuesProvider) GetConfigChartValues(
	_ context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
) (map[string]interface{}, error) {
	// Decode infrastructureProviderStatus
	infraStatus := &apisaws.InfrastructureStatus{}
	if cp.Spec.InfrastructureProviderStatus != nil {
		if _, _, err := vp.decoder.Decode(cp.Spec.InfrastructureProviderStatus.Raw, nil, infraStatus); err != nil {
			return nil, fmt.Errorf("could not decode infrastructureProviderStatus of controlplane '%s': %w", k8sclient.ObjectKeyFromObject(cp), err)
		}
	}

	ipFamilies := cluster.Shoot.Spec.Networking.IPFamilies

	// Get config chart values
	return getConfigChartValues(infraStatus, cp, ipFamilies)
}

// GetControlPlaneChartValues returns the values for the control plane chart applied by the generic actuator.
func (vp *valuesProvider) GetControlPlaneChartValues(
	ctx context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
) (map[string]interface{}, error) {
	cpConfig, err := vp.decodeControlPlaneConfig(cp)
	if err != nil {
		return nil, err
	}

	infraStatus, err := vp.decodeInfrastructureStatus(cp)
	if err != nil {
		return nil, err
	}

	// TODO(AndreasBurger): rm in future release.
	if err := cleanupSeedLegacyCSISnapshotValidation(ctx, vp.client, cp.Namespace); err != nil {
		return nil, err
	}

	useWorkloadIdentity, err := shouldUseWorkloadIdentity(ctx, vp.client, cp.Spec.SecretRef.Name, cp.Spec.SecretRef.Namespace)
	if err != nil {
		return nil, err
	}

	return getControlPlaneChartValues(cpConfig, cp, infraStatus, cluster, secretsReader, checksums, scaledDown, useWorkloadIdentity)
}

// GetControlPlaneShootChartValues returns the values for the control plane shoot chart applied by the generic actuator.
func (vp *valuesProvider) GetControlPlaneShootChartValues(
	ctx context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	_ map[string]string,
) (map[string]interface{}, error) {
	cpConfig, err := vp.decodeControlPlaneConfig(cp)
	if err != nil {
		return nil, err
	}

	infraStatus, err := vp.decodeInfrastructureStatus(cp)
	if err != nil {
		return nil, err
	}

	infraConfig, err := helper.InfrastructureConfigFromCluster(cluster)
	if err != nil {
		return nil, err
	}

	useWorkloadIdentity, err := shouldUseWorkloadIdentity(ctx, vp.client, cp.Spec.SecretRef.Name, cp.Spec.SecretRef.Namespace)
	if err != nil {
		return nil, err
	}

	return getControlPlaneShootChartValues(cluster, cpConfig, cp, secretsReader, infraConfig, infraStatus, useWorkloadIdentity)
}

// GetControlPlaneShootCRDsChartValues returns the values for the control plane shoot CRDs chart applied by the generic actuator.
// Currently, the provider extension does not specify a control plane shoot CRDs chart. That's why we simply return empty values.
func (vp *valuesProvider) GetControlPlaneShootCRDsChartValues(
	_ context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	_ *extensionscontroller.Cluster,
) (map[string]interface{}, error) {
	cpConfig := &apisaws.ControlPlaneConfig{}
	if cp.Spec.ProviderConfig != nil {
		if _, _, err := vp.decoder.Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig); err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", k8sclient.ObjectKeyFromObject(cp), err)
		}
	}

	return map[string]interface{}{
		"volumesnapshots": map[string]interface{}{
			"enabled": true,
		},
		"aws-load-balancer-controller": map[string]interface{}{
			"enabled": isLoadBalancerControllerEnabled(cpConfig),
		},
	}, nil
}

// GetStorageClassesChartValues returns the values for the storage classes chart applied by the generic actuator.
func (vp *valuesProvider) GetStorageClassesChartValues(
	_ context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	_ *extensionscontroller.Cluster,
) (map[string]interface{}, error) {
	managedDefaultClass := true

	if cp.Spec.ProviderConfig != nil {
		cpConfig := &apisaws.ControlPlaneConfig{}
		_, _, err := vp.decoder.Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig)
		if err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", k8sclient.ObjectKeyFromObject(cp), err)
		}

		// internal types should NOT be used when embeding.
		// There should not be any defaulting for internal types.
		// This check is to be 100% sure that we won't hit nil dereference.
		if cpConfig.Storage != nil && cpConfig.Storage.ManagedDefaultClass != nil {
			managedDefaultClass = *cpConfig.Storage.ManagedDefaultClass
		}
	}

	return map[string]interface{}{
		"managedDefaultClass": managedDefaultClass,
	}, nil
}

func (vp *valuesProvider) decodeControlPlaneConfig(cp *extensionsv1alpha1.ControlPlane) (*apisaws.ControlPlaneConfig, error) {
	cpConfig := &apisaws.ControlPlaneConfig{}
	if cp.Spec.ProviderConfig != nil {
		if _, _, err := vp.decoder.Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig); err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", k8sclient.ObjectKeyFromObject(cp), err)
		}
	}
	return cpConfig, nil
}

func (vp *valuesProvider) decodeInfrastructureStatus(cp *extensionsv1alpha1.ControlPlane) (*apisaws.InfrastructureStatus, error) {
	infraStatus := &apisaws.InfrastructureStatus{}
	if cp.Spec.InfrastructureProviderStatus != nil {
		if _, _, err := vp.decoder.Decode(cp.Spec.InfrastructureProviderStatus.Raw, nil, infraStatus); err != nil {
			return nil, fmt.Errorf("could not decode infrastructureProviderStatus of controlplane '%s': %w", k8sclient.ObjectKeyFromObject(cp), err)
		}
	}
	return infraStatus, nil
}

// getConfigChartValues collects and returns the configuration chart values.
func getConfigChartValues(
	infraStatus *apisaws.InfrastructureStatus,
	cp *extensionsv1alpha1.ControlPlane,
	ipFamilies []v1beta1.IPFamily,
) (map[string]interface{}, error) {
	// Get the first subnet with purpose "public"
	subnet, err := helper.FindSubnetForPurpose(infraStatus.VPC.Subnets, apisaws.PurposePublic)
	if err != nil {
		return nil, fmt.Errorf("could not determine subnet from infrastructureProviderStatus of controlplane '%s': %w", k8sclient.ObjectKeyFromObject(cp), err)
	}

	// Collect config chart values
	config := map[string]interface{}{
		"vpcID":       infraStatus.VPC.ID,
		"subnetID":    subnet.ID,
		"clusterName": cp.Namespace,
		"zone":        subnet.Zone,
	}

	if ipFamilies != nil && slices.Contains(ipFamilies, v1beta1.IPFamilyIPv6) {
		config["nodeIPFamilyIPv6"] = "ipv6"
	}
	if ipFamilies != nil && slices.Contains(ipFamilies, v1beta1.IPFamilyIPv4) {
		config["nodeIPFamilyIPv4"] = "ipv4"
	}

	return config, nil
}

// getControlPlaneChartValues collects and returns the control plane chart values.
func getControlPlaneChartValues(
	cpConfig *apisaws.ControlPlaneConfig,
	cp *extensionsv1alpha1.ControlPlane,
	infraStatus *apisaws.InfrastructureStatus,
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
	useWorkloadIdentity bool,
) (map[string]interface{}, error) {
	ccm, err := getCCMChartValues(cpConfig, cp, cluster, secretsReader, checksums, scaledDown, useWorkloadIdentity)
	if err != nil {
		return nil, err
	}

	crc := getCRCChartValues(cpConfig, cp, cluster, checksums, scaledDown, useWorkloadIdentity)

	ipam, err := getIPAMChartValues(cp, cluster, checksums, scaledDown, useWorkloadIdentity)
	if err != nil {
		return nil, err
	}

	alb, err := getALBChartValues(cpConfig, cp, cluster, secretsReader, checksums, scaledDown, infraStatus, useWorkloadIdentity)
	if err != nil {
		return nil, err
	}

	csi, err := getCSIControllerChartValues(cp, cluster, secretsReader, checksums, scaledDown, useWorkloadIdentity)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"global": map[string]interface{}{
			"genericTokenKubeconfigSecretName": extensionscontroller.GenericTokenKubeconfigSecretNameFromCluster(cluster),
		},
		aws.CloudControllerManagerName:    ccm,
		aws.AWSCustomRouteControllerName:  crc,
		aws.AWSIPAMControllerImageName:    ipam,
		aws.AWSLoadBalancerControllerName: alb,
		aws.CSIControllerName:             csi,
	}, nil
}

// getCCMChartValues collects and returns the CCM chart values.
func getCCMChartValues(
	cpConfig *apisaws.ControlPlaneConfig,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
	useWorkloadIdentity bool,
) (map[string]interface{}, error) {
	serverSecret, found := secretsReader.Get(cloudControllerManagerServerName)
	if !found {
		return nil, fmt.Errorf("secret %q not found", cloudControllerManagerServerName)
	}

	values := map[string]interface{}{
		"enabled":           true,
		"replicas":          extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"clusterName":       cp.Namespace,
		"kubernetesVersion": cluster.Shoot.Spec.Kubernetes.Version,
		"podNetwork":        strings.Join(extensionscontroller.GetPodNetwork(cluster), ","),
		"podAnnotations": map[string]interface{}{
			"checksum/secret-cloudprovider":            checksums[v1beta1constants.SecretNameCloudProvider],
			"checksum/configmap-cloud-provider-config": checksums[aws.CloudProviderConfigName],
		},
		"podLabels": map[string]interface{}{
			v1beta1constants.LabelPodMaintenanceRestart: "true",
		},
		"tlsCipherSuites": kutil.TLSCipherSuites,
		"secrets": map[string]interface{}{
			"server": serverSecret.Name,
		},
		"useWorkloadIdentity": useWorkloadIdentity,
		"region":              cp.Spec.Region,
	}

	if cpConfig.CloudControllerManager != nil {
		values["featureGates"] = cpConfig.CloudControllerManager.FeatureGates
	}

	return values, nil
}

// getCRCChartValues collects and returns the custom-route-controller chart values.
func getCRCChartValues(
	cpConfig *apisaws.ControlPlaneConfig,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	checksums map[string]string,
	scaledDown bool,
	useWorkloadIdentity bool,
) map[string]interface{} {
	mode := "ipv4"
	if networkingConfig := cluster.Shoot.Spec.Networking; networkingConfig != nil {
		if slices.Contains(networkingConfig.IPFamilies, v1beta1.IPFamilyIPv6) && !slices.Contains(networkingConfig.IPFamilies, v1beta1.IPFamilyIPv4) {
			mode = "ipv6"
		}
	}
	values := map[string]interface{}{
		"enabled":     true,
		"replicas":    extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"clusterName": cp.Namespace,
		"podNetwork":  strings.Join(extensionscontroller.GetPodNetwork(cluster), ","),
		"podAnnotations": map[string]interface{}{
			"checksum/secret-cloudprovider": checksums[v1beta1constants.SecretNameCloudProvider],
		},
		"podLabels": map[string]interface{}{
			v1beta1constants.LabelPodMaintenanceRestart: "true",
		},
		"region":              cp.Spec.Region,
		"useWorkloadIdentity": useWorkloadIdentity,
	}
	enabled := cpConfig.CloudControllerManager != nil &&
		cpConfig.CloudControllerManager.UseCustomRouteController != nil &&
		*cpConfig.CloudControllerManager.UseCustomRouteController
	if !enabled || mode == "ipv6" {
		values["replicas"] = 0
	}

	return values
}

// getIPAMChartValues collects and returns the ipam-controller chart values.
func getIPAMChartValues(
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	checksums map[string]string,
	scaledDown bool,
	useWorkloadIdentity bool,
) (map[string]interface{}, error) {
	mode := "ipv4"
	primaryIPFamily := "ipv4"
	if networkingConfig := cluster.Shoot.Spec.Networking; networkingConfig != nil {
		if len(networkingConfig.IPFamilies) == 2 {
			mode = "dual-stack"
			primaryIPFamily = strings.ToLower(string(cluster.Shoot.Spec.Networking.IPFamilies[0]))
		} else if slices.Contains(networkingConfig.IPFamilies, v1beta1.IPFamilyIPv6) {
			mode = "ipv6"
		}
	}

	nodeCidrMaskSizeIPv4 := int32(24)
	nodeCidrMaskSizeIPv6 := int32(64)
	if cluster.Shoot.Spec.Kubernetes.KubeControllerManager != nil && cluster.Shoot.Spec.Kubernetes.KubeControllerManager.NodeCIDRMaskSize != nil {
		if len(cluster.Shoot.Spec.Networking.IPFamilies) == 1 && cluster.Shoot.Spec.Networking.IPFamilies[0] == v1beta1.IPFamilyIPv4 {
			nodeCidrMaskSizeIPv4 = *cluster.Shoot.Spec.Kubernetes.KubeControllerManager.NodeCIDRMaskSize
		}
		if len(cluster.Shoot.Spec.Networking.IPFamilies) == 1 && cluster.Shoot.Spec.Networking.IPFamilies[0] == v1beta1.IPFamilyIPv6 {
			nodeCidrMaskSizeIPv6 = *cluster.Shoot.Spec.Kubernetes.KubeControllerManager.NodeCIDRMaskSize
		}
	}

	podNetwork := "192.168.0.0/16"
	if slices.Contains(cluster.Shoot.Spec.Networking.IPFamilies, v1beta1.IPFamilyIPv4) {
		for _, podCIDR := range extensionscontroller.GetPodNetwork(cluster) {
			_, cidr, err := net.ParseCIDR(podCIDR)
			if err != nil {
				return nil, err
			}
			if cidr.IP.To4() != nil {
				podNetwork = podCIDR
			}
		}
	}

	values := map[string]interface{}{
		"enabled":     true,
		"replicas":    extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"clusterName": cp.Namespace,
		"podNetwork":  podNetwork,
		"podAnnotations": map[string]interface{}{
			"checksum/secret-cloudprovider": checksums[v1beta1constants.SecretNameCloudProvider],
		},
		"podLabels": map[string]interface{}{
			v1beta1constants.LabelPodMaintenanceRestart: "true",
		},
		"region":               cp.Spec.Region,
		"mode":                 mode,
		"primaryIPFamily":      primaryIPFamily,
		"nodeCIDRMaskSizeIPv4": nodeCidrMaskSizeIPv4,
		"nodeCIDRMaskSizeIPv6": nodeCidrMaskSizeIPv6,
		"useWorkloadIdentity":  useWorkloadIdentity,
	}
	enabled := mode != "ipv4"
	if !enabled {
		values["replicas"] = 0
	}

	return values, nil
}

// getALBChartValues collects and returns the aws-load-balancer-controller chart values.
func getALBChartValues(
	cpConfig *apisaws.ControlPlaneConfig,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
	infraStatus *apisaws.InfrastructureStatus,
	useWorkloadIdentity bool,
) (map[string]interface{}, error) {
	shootChart := infraStatus == nil
	if shootChart && !isLoadBalancerControllerEnabled(cpConfig) {
		return map[string]interface{}{"enabled": false}, nil
	}

	secret, found := secretsReader.Get(awsLoadBalancerControllerWebhook)
	if !found {
		return nil, fmt.Errorf("secret %q not found", awsLoadBalancerControllerWebhook)
	}
	caSecret, found := secretsReader.Get(caNameControlPlane)
	if !found {
		return nil, fmt.Errorf("secret %q not found", caNameControlPlane)
	}

	// ALB chart is always enabled and deployment is controlled by the replicaCount
	// to avoid similar issue like https://github.com/gardener/gardener-extension-provider-aws/issues/628
	values := map[string]interface{}{
		"enabled":               true,
		"replicaCount":          extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"region":                cp.Spec.Region,
		"clusterName":           cp.Namespace,
		"webhookCertSecretName": secret.Name,
		"webhookURL":            fmt.Sprintf("https://%s-webhook-service.%s:443", aws.AWSLoadBalancerControllerName, cp.Namespace),
		"webhookTLS": map[string]interface{}{
			"caCert": string(caSecret.Data[secretutils.DataKeyCertificateBundle]),
		},
		"defaultTags": map[string]interface{}{
			"KubernetesCluster":                     cp.Namespace,
			"kubernetes.io/cluster/" + cp.Namespace: "owned",
		},
		"useWorkloadIdentity": useWorkloadIdentity,
	}
	if cpConfig.LoadBalancerController != nil && cpConfig.LoadBalancerController.IngressClassName != nil {
		values["ingressClass"] = *cpConfig.LoadBalancerController.IngressClassName
	}

	if len(checksums) > 0 {
		values["podAnnotations"] = map[string]interface{}{
			"checksum/secret-cloudprovider": checksums[v1beta1constants.SecretNameCloudProvider],
		}
	}
	if !shootChart {
		values["vpcId"] = infraStatus.VPC.ID
	}

	if !isLoadBalancerControllerEnabled(cpConfig) {
		values["replicaCount"] = 0
	}

	return values, nil
}

func isLoadBalancerControllerEnabled(cpConfig *apisaws.ControlPlaneConfig) bool {
	return cpConfig.LoadBalancerController != nil && cpConfig.LoadBalancerController.Enabled
}

// getCSIControllerChartValues collects and returns the CSIController chart values.
func getCSIControllerChartValues(
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	_ secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
	useWorkloadIdentity bool,
) (map[string]interface{}, error) {
	values := map[string]interface{}{
		"enabled":  true,
		"replicas": extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"region":   cp.Spec.Region,
		"podAnnotations": map[string]interface{}{
			"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
		},
		"csiSnapshotController": map[string]interface{}{
			"replicas": extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		},
		"useWorkloadIdentity": useWorkloadIdentity,
	}

	k8sVersion, err := semver.NewVersion(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return nil, err
	}
	if versionutils.ConstraintK8sGreaterEqual131.Check(k8sVersion) {
		if _, ok := cluster.Shoot.Annotations[aws.AnnotationEnableVolumeAttributesClass]; ok {
			values["csiResizer"] = map[string]interface{}{
				"featureGates": map[string]string{
					"VolumeAttributesClass": "true",
				},
			}
			values["csiProvisioner"] = map[string]interface{}{
				"featureGates": map[string]string{
					"VolumeAttributesClass": "true",
				},
			}
		}
	}

	return values, nil
}

// getControlPlaneShootChartValues collects and returns the control plane shoot chart values.
func getControlPlaneShootChartValues(
	cluster *extensionscontroller.Cluster,
	cpConfig *apisaws.ControlPlaneConfig,
	cp *extensionsv1alpha1.ControlPlane,
	secretsReader secretsmanager.Reader,
	infraConfig *apisaws.InfrastructureConfig,
	infraStatus *apisaws.InfrastructureStatus,
	useWorkloadIdentity bool,
) (map[string]interface{}, error) {
	kubernetesVersion := cluster.Shoot.Spec.Kubernetes.Version

	customRouteControllerEnabled := cpConfig.CloudControllerManager != nil &&
		cpConfig.CloudControllerManager.UseCustomRouteController != nil &&
		*cpConfig.CloudControllerManager.UseCustomRouteController

	ipamControllerEnabled := false
	if networkingConfig := cluster.Shoot.Spec.Networking; networkingConfig != nil && slices.Contains(networkingConfig.IPFamilies, v1beta1.IPFamilyIPv6) {
		ipamControllerEnabled = true
	}

	csiDriverNodeValues := map[string]interface{}{
		"enabled":           true,
		"kubernetesVersion": kubernetesVersion,
	}

	driver := map[string]interface{}{}
	if value, ok := cluster.Shoot.Annotations[aws.VolumeAttachLimit]; ok {
		driver["volumeAttachLimit"] = value
	}
	if value, ok := cluster.Shoot.Annotations[aws.ReservedVolumeAttachements]; ok {
		driver["reservedVolumeAttachments"] = value
	}

	if value, ok := cluster.Shoot.Annotations[aws.LegacyXFS]; ok {
		driver["legacyXFS"] = value
	}
	csiDriverNodeValues["driver"] = driver

	albValues, err := getALBChartValues(cpConfig, cp, cluster, secretsReader, nil, false, nil, useWorkloadIdentity)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		aws.CloudControllerManagerName:    map[string]interface{}{"enabled": true},
		aws.AWSCustomRouteControllerName:  map[string]interface{}{"enabled": customRouteControllerEnabled},
		aws.AWSIPAMControllerImageName:    map[string]interface{}{"enabled": ipamControllerEnabled},
		aws.AWSLoadBalancerControllerName: albValues,
		aws.CSINodeName:                   csiDriverNodeValues,
		aws.CSIEfsNodeName:                getControlPlaneShootChartCSIEfsValues(infraConfig, infraStatus),
	}, nil
}

func cleanupSeedLegacyCSISnapshotValidation(
	ctx context.Context,
	client k8sclient.Client,
	namespace string,
) error {
	if err := kutil.DeleteObjects(ctx, client,
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: aws.CSISnapshotValidationName, Namespace: namespace}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: aws.CSISnapshotValidationName, Namespace: namespace}},
		&vpaautoscalingv1.VerticalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "csi-snapshot-webhook-vpa", Namespace: namespace}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: aws.CSISnapshotValidationName, Namespace: namespace}},
	); err != nil {
		return fmt.Errorf("failed to delete legacy csi-snapshot-validation resources: %w", err)
	}

	return nil
}

func shouldUseWorkloadIdentity(ctx context.Context, c k8sclient.Client, secretName, secretNamespace string) (bool, error) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: secretNamespace}}
	if err := c.Get(ctx, k8sclient.ObjectKeyFromObject(secret), secret); err != nil {
		return false, fmt.Errorf("failed getting controlplane secret: %w", err)
	}

	return secret.Labels[securityv1alpha1constants.LabelPurpose] == securityv1alpha1constants.LabelPurposeWorkloadIdentityTokenRequestor, nil
}

func isCSIEfsEnabled(infraConfig *apisaws.InfrastructureConfig) bool {
	return infraConfig != nil && infraConfig.ElasticFileSystem != nil && infraConfig.ElasticFileSystem.Enabled
}

func getControlPlaneShootChartCSIEfsValues(
	infraConfig *apisaws.InfrastructureConfig,
	infraStatus *apisaws.InfrastructureStatus,
) map[string]interface{} {
	csiEfsEnabled := isCSIEfsEnabled(infraConfig)
	values := map[string]interface{}{
		"enabled": csiEfsEnabled,
	}

	if csiEfsEnabled {
		values["fileSystemID"] = infraStatus.ElasticFileSystem.ID
	}

	return values
}
