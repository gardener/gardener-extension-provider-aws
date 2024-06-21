// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"fmt"
	"path/filepath"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane/genericactuator"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/chart"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	autoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/charts"
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	caNameControlPlane               = "ca-" + aws.Name + "-controlplane"
	cloudControllerManagerServerName = "cloud-controller-manager-server"
	csiSnapshotValidationServerName  = aws.CSISnapshotValidationName + "-server"
	awsLoadBalancerControllerWebhook = aws.AWSLoadBalancerControllerName + "-webhook-service"
)

func secretConfigsFunc(namespace string) []extensionssecretsmanager.SecretConfigWithOptions {
	return []extensionssecretsmanager.SecretConfigWithOptions{
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
				Name:                        csiSnapshotValidationServerName,
				CommonName:                  aws.UsernamePrefix + aws.CSISnapshotValidationName,
				DNSNames:                    kutil.DNSNamesForService(aws.CSISnapshotValidationName, namespace),
				CertType:                    secretutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			// use current CA for signing server cert to prevent mismatches when dropping the old CA from the webhook
			// config in phase Completing
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(caNameControlPlane, secretsmanager.UseCurrentCA)},
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
		gutil.NewShootAccessSecret(aws.CSISnapshotValidationName, namespace),
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
					{Type: &corev1.ConfigMap{}, Name: aws.CloudControllerManagerName + "-observability-config"},
					{Type: &monitoringv1.ServiceMonitor{}, Name: "shoot-cloud-controller-manager"},
					{Type: &monitoringv1.PrometheusRule{}, Name: "shoot-cloud-controller-manager"},
					{Type: &autoscalingv1.VerticalPodAutoscaler{}, Name: aws.CloudControllerManagerName + "-vpa"},
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
					{Type: &autoscalingv1.VerticalPodAutoscaler{}, Name: aws.AWSCustomRouteControllerName + "-vpa"},
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
					{Type: &autoscalingv1.VerticalPodAutoscaler{}, Name: aws.AWSIPAMControllerName + "-vpa"},
				},
				SubCharts: nil,
			},
			{
				Name:   aws.AWSLoadBalancerControllerName,
				Images: []string{aws.AWSLoacBalancerControllerImageName},
				Objects: []*chart.Object{
					{Type: &appsv1.Deployment{}, Name: aws.AWSLoadBalancerControllerName},
					{Type: &autoscalingv1.VerticalPodAutoscaler{}, Name: aws.AWSLoadBalancerControllerName},
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
					aws.CSISnapshotValidationWebhookImageName,
					aws.CSIVolumeModifierImageName,
				},
				Objects: []*chart.Object{
					// csi-driver-controller
					{Type: &appsv1.Deployment{}, Name: aws.CSIControllerName},
					{Type: &autoscalingv1.VerticalPodAutoscaler{}, Name: aws.CSIControllerName + "-vpa"},
					{Type: &corev1.ConfigMap{}, Name: aws.CSIControllerName + "-observability-config"},
					// csi-snapshot-controller
					{Type: &appsv1.Deployment{}, Name: aws.CSISnapshotControllerName},
					{Type: &autoscalingv1.VerticalPodAutoscaler{}, Name: aws.CSISnapshotControllerName + "-vpa"},
					// csi-snapshot-validation-webhook
					{Type: &appsv1.Deployment{}, Name: aws.CSISnapshotValidationName},
					{Type: &corev1.Service{}, Name: aws.CSISnapshotValidationName},
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
					{Type: &v1.PodDisruptionBudget{}, Name: aws.AWSLoadBalancerControllerName},
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
					{Type: extensionscontroller.GetVerticalPodAutoscalerObject(), Name: aws.CSINodeName},
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
					// csi-snapshot-validation-webhook
					{Type: &admissionregistrationv1.ValidatingWebhookConfiguration{}, Name: aws.CSISnapshotValidationName},
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSISnapshotValidationName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSISnapshotValidationName},
					// csi-volume-modifier
					{Type: &corev1.ServiceAccount{}, Name: aws.CSIVolumeModifierName},
					{Type: &rbacv1.ClusterRole{}, Name: aws.UsernamePrefix + aws.CSIVolumeModifierName},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: aws.UsernamePrefix + aws.CSIVolumeModifierName},
					{Type: &rbacv1.Role{}, Name: aws.UsernamePrefix + aws.CSIVolumeModifierName},
					{Type: &rbacv1.RoleBinding{}, Name: aws.UsernamePrefix + aws.CSIVolumeModifierName},
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
	client  client.Client
	decoder runtime.Decoder
}

// GetConfigChartValues returns the values for the config chart applied by the generic actuator.
func (vp *valuesProvider) GetConfigChartValues(
	_ context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	_ *extensionscontroller.Cluster,
) (map[string]interface{}, error) {
	// Decode infrastructureProviderStatus
	infraStatus := &apisaws.InfrastructureStatus{}
	if cp.Spec.InfrastructureProviderStatus != nil {
		if _, _, err := vp.decoder.Decode(cp.Spec.InfrastructureProviderStatus.Raw, nil, infraStatus); err != nil {
			return nil, fmt.Errorf("could not decode infrastructureProviderStatus of controlplane '%s': %w", kutil.ObjectName(cp), err)
		}
	}

	// Get config chart values
	return getConfigChartValues(infraStatus, cp)
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
	// Decode providerConfig
	cpConfig := &apisaws.ControlPlaneConfig{}
	if cp.Spec.ProviderConfig != nil {
		if _, _, err := vp.decoder.Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig); err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", kutil.ObjectName(cp), err)
		}
	}

	// Decode infrastructureProviderStatus
	infraStatus := &apisaws.InfrastructureStatus{}
	if cp.Spec.InfrastructureProviderStatus != nil {
		if _, _, err := vp.decoder.Decode(cp.Spec.InfrastructureProviderStatus.Raw, nil, infraStatus); err != nil {
			return nil, fmt.Errorf("could not decode infrastructureProviderStatus of controlplane '%s': %w", kutil.ObjectName(cp), err)
		}
	}

	// TODO(rfranzke): Delete this in a future release.
	if err := kutil.DeleteObject(ctx, vp.client, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "csi-driver-controller-observability-config", Namespace: cp.Namespace}}); err != nil {
		return nil, fmt.Errorf("failed deleting legacy csi-driver-controller-observability-config ConfigMap: %w", err)
	}

	// TODO(rfranzke): Delete this after August 2024.
	gep19Monitoring := vp.client.Get(ctx, client.ObjectKey{Name: "prometheus-shoot", Namespace: cp.Namespace}, &appsv1.StatefulSet{}) == nil
	if gep19Monitoring {
		if err := kutil.DeleteObject(ctx, vp.client, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cloud-controller-manager-observability-config", Namespace: cp.Namespace}}); err != nil {
			return nil, fmt.Errorf("failed deleting cloud-controller-manager-observability-config ConfigMap: %w", err)
		}
	}

	return getControlPlaneChartValues(cpConfig, cp, infraStatus, cluster, secretsReader, checksums, scaledDown, gep19Monitoring)
}

// GetControlPlaneShootChartValues returns the values for the control plane shoot chart applied by the generic actuator.
func (vp *valuesProvider) GetControlPlaneShootChartValues(
	_ context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	_ map[string]string,
) (map[string]interface{}, error) {
	// Decode providerConfig
	cpConfig := &apisaws.ControlPlaneConfig{}
	if cp.Spec.ProviderConfig != nil {
		if _, _, err := vp.decoder.Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig); err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", kutil.ObjectName(cp), err)
		}
	}

	return getControlPlaneShootChartValues(cluster, cpConfig, cp, secretsReader)
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
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", kutil.ObjectName(cp), err)
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
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", kutil.ObjectName(cp), err)
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

// getConfigChartValues collects and returns the configuration chart values.
func getConfigChartValues(
	infraStatus *apisaws.InfrastructureStatus,
	cp *extensionsv1alpha1.ControlPlane,
) (map[string]interface{}, error) {
	// Get the first subnet with purpose "public"
	subnet, err := helper.FindSubnetForPurpose(infraStatus.VPC.Subnets, apisaws.PurposePublic)
	if err != nil {
		return nil, fmt.Errorf("could not determine subnet from infrastructureProviderStatus of controlplane '%s': %w", kutil.ObjectName(cp), err)
	}

	// Collect config chart values
	return map[string]interface{}{
		"vpcID":       infraStatus.VPC.ID,
		"subnetID":    subnet.ID,
		"clusterName": cp.Namespace,
		"zone":        subnet.Zone,
	}, nil
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
	gep19Monitoring bool,
) (map[string]interface{}, error) {
	ccm, err := getCCMChartValues(cpConfig, cp, cluster, secretsReader, checksums, scaledDown, gep19Monitoring)
	if err != nil {
		return nil, err
	}

	crc, err := getCRCChartValues(cpConfig, cp, cluster, checksums, scaledDown)
	if err != nil {
		return nil, err
	}

	ipam, err := getIPAMChartValues(cpConfig, cp, cluster, checksums, scaledDown)
	if err != nil {
		return nil, err
	}

	alb, err := getALBChartValues(cpConfig, cp, cluster, secretsReader, checksums, scaledDown, infraStatus)
	if err != nil {
		return nil, err
	}

	csi, err := getCSIControllerChartValues(cp, cluster, secretsReader, checksums, scaledDown)
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
	gep19Monitoring bool,
) (map[string]interface{}, error) {
	serverSecret, found := secretsReader.Get(cloudControllerManagerServerName)
	if !found {
		return nil, fmt.Errorf("secret %q not found", cloudControllerManagerServerName)
	}

	ipamControllerEnabled := cpConfig.IPAMController != nil &&
		cpConfig.IPAMController.Enabled

	values := map[string]interface{}{
		"enabled":           true,
		"replicas":          extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"clusterName":       cp.Namespace,
		"kubernetesVersion": cluster.Shoot.Spec.Kubernetes.Version,
		"podNetwork":        extensionscontroller.GetPodNetwork(cluster),
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
		"gep19Monitoring":       gep19Monitoring,
		"ipamControllerEnabled": ipamControllerEnabled,
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
) (map[string]interface{}, error) {
	values := map[string]interface{}{
		"enabled":     true,
		"replicas":    extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"clusterName": cp.Namespace,
		"podNetwork":  extensionscontroller.GetPodNetwork(cluster),
		"podAnnotations": map[string]interface{}{
			"checksum/secret-cloudprovider": checksums[v1beta1constants.SecretNameCloudProvider],
		},
		"podLabels": map[string]interface{}{
			v1beta1constants.LabelPodMaintenanceRestart: "true",
		},
		"region": cp.Spec.Region,
	}
	enabled := cpConfig.CloudControllerManager != nil &&
		cpConfig.CloudControllerManager.UseCustomRouteController != nil &&
		*cpConfig.CloudControllerManager.UseCustomRouteController
	if !enabled {
		values["replicas"] = 0
	}

	return values, nil
}

// getIPAMChartValues collects and returns the ipam-controller chart values.
func getIPAMChartValues(
	cpConfig *apisaws.ControlPlaneConfig,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	checksums map[string]string,
	scaledDown bool,
) (map[string]interface{}, error) {

	mode := "ipv4"
	if len(cluster.Shoot.Spec.Networking.IPFamilies) == 1 && cluster.Shoot.Spec.Networking.IPFamilies[0] == v1beta1.IPFamilyIPv6 {
		mode = "ipv6"
	}
	if len(cluster.Shoot.Spec.Networking.IPFamilies) == 2 {
		mode = "dual-stack"
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

	values := map[string]interface{}{
		"enabled":     true,
		"replicas":    extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"clusterName": cp.Namespace,
		"podNetwork":  extensionscontroller.GetPodNetwork(cluster),
		"podAnnotations": map[string]interface{}{
			"checksum/secret-cloudprovider": checksums[v1beta1constants.SecretNameCloudProvider],
		},
		"podLabels": map[string]interface{}{
			v1beta1constants.LabelPodMaintenanceRestart: "true",
		},
		"region":               cp.Spec.Region,
		"mode":                 mode,
		"nodeCIDRMaskSizeIPv4": nodeCidrMaskSizeIPv4,
		"nodeCIDRMaskSizeIPv6": nodeCidrMaskSizeIPv6,
	}
	enabled := cpConfig.IPAMController != nil &&
		cpConfig.IPAMController.Enabled
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
	secretsReader secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
) (map[string]interface{}, error) {
	serverSecret, found := secretsReader.Get(csiSnapshotValidationServerName)
	if !found {
		return nil, fmt.Errorf("secret %q not found", csiSnapshotValidationServerName)
	}

	return map[string]interface{}{
		"enabled":  true,
		"replicas": extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"region":   cp.Spec.Region,
		"podAnnotations": map[string]interface{}{
			"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
		},
		"csiSnapshotController": map[string]interface{}{
			"replicas": extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		},
		"csiSnapshotValidationWebhook": map[string]interface{}{
			"replicas": extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
			"secrets": map[string]interface{}{
				"server": serverSecret.Name,
			},
			"topologyAwareRoutingEnabled": gardencorev1beta1helper.IsTopologyAwareRoutingForShootControlPlaneEnabled(cluster.Seed, cluster.Shoot),
		},
	}, nil
}

// getControlPlaneShootChartValues collects and returns the control plane shoot chart values.
func getControlPlaneShootChartValues(
	cluster *extensionscontroller.Cluster,
	cpConfig *apisaws.ControlPlaneConfig,
	cp *extensionsv1alpha1.ControlPlane,
	secretsReader secretsmanager.Reader,
) (map[string]interface{}, error) {
	kubernetesVersion := cluster.Shoot.Spec.Kubernetes.Version

	caSecret, found := secretsReader.Get(caNameControlPlane)
	if !found {
		return nil, fmt.Errorf("secret %q not found", caNameControlPlane)
	}

	customRouteControllerEnabled := cpConfig.CloudControllerManager != nil &&
		cpConfig.CloudControllerManager.UseCustomRouteController != nil &&
		*cpConfig.CloudControllerManager.UseCustomRouteController

	ipamControllerEnabled := cpConfig.IPAMController != nil &&
		cpConfig.IPAMController.Enabled

	csiDriverNodeValues := map[string]interface{}{
		"enabled":           true,
		"kubernetesVersion": kubernetesVersion,
		"vpaEnabled":        gardencorev1beta1helper.ShootWantsVerticalPodAutoscaler(cluster.Shoot),
		"webhookConfig": map[string]interface{}{
			"url":      "https://" + aws.CSISnapshotValidationName + "." + cp.Namespace + "/volumesnapshot",
			"caBundle": string(caSecret.Data[secretutils.DataKeyCertificateBundle]),
		},
	}

	if value, ok := cluster.Shoot.Annotations[aws.VolumeAttachLimit]; ok {
		csiDriverNodeValues["driver"] = map[string]interface{}{
			"volumeAttachLimit": value,
		}
	}

	albValues, err := getALBChartValues(cpConfig, cp, cluster, secretsReader, nil, false, nil)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		aws.CloudControllerManagerName:    map[string]interface{}{"enabled": true},
		aws.AWSCustomRouteControllerName:  map[string]interface{}{"enabled": customRouteControllerEnabled},
		aws.AWSIPAMControllerImageName:    map[string]interface{}{"enabled": ipamControllerEnabled},
		aws.AWSLoadBalancerControllerName: albValues,
		aws.CSINodeName:                   csiDriverNodeValues,
	}, nil
}
