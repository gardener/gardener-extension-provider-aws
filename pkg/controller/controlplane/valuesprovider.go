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
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver"
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/common"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane/genericactuator"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/chart"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/gardener/gardener/pkg/utils/version"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	autoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
)

const (
	caNameControlPlane               = "ca-" + aws.Name + "-controlplane"
	cloudControllerManagerServerName = "cloud-controller-manager-server"
	csiSnapshotValidationServerName  = aws.CSISnapshotValidation + "-server"
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
				CommonName:                  aws.UsernamePrefix + aws.CSISnapshotValidation,
				DNSNames:                    kutil.DNSNamesForService(aws.CSISnapshotValidation, namespace),
				CertType:                    secretutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			// use current CA for signing server cert to prevent mismatches when dropping the old CA from the webhook
			// config in phase Completing
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(caNameControlPlane, secretsmanager.UseCurrentCA)},
		},
	}
}

func shootAccessSecretsFunc(namespace string) []*gutil.ShootAccessSecret {
	return []*gutil.ShootAccessSecret{
		gutil.NewShootAccessSecret(aws.CloudControllerManagerName, namespace),
		gutil.NewShootAccessSecret(aws.AWSCustomRouteControllerName, namespace),
		gutil.NewShootAccessSecret(aws.CSIProvisionerName, namespace),
		gutil.NewShootAccessSecret(aws.CSIAttacherName, namespace),
		gutil.NewShootAccessSecret(aws.CSISnapshotterName, namespace),
		gutil.NewShootAccessSecret(aws.CSIResizerName, namespace),
		gutil.NewShootAccessSecret(aws.CSISnapshotControllerName, namespace),
	}
}

func exposureShootAccessSecretsFunc(namespace string) []*gutil.ShootAccessSecret {
	return []*gutil.ShootAccessSecret{
		gutil.NewShootAccessSecret(aws.LBReadvertiserDeploymentName, namespace),
	}
}

var (
	configChart = &chart.Chart{
		Name: "cloud-provider-config",
		Path: filepath.Join(aws.InternalChartsPath, "cloud-provider-config"),
		Objects: []*chart.Object{
			{
				Type: &corev1.ConfigMap{},
				Name: aws.CloudProviderConfigName,
			},
		},
	}

	controlPlaneChart = &chart.Chart{
		Name: "seed-controlplane",
		Path: filepath.Join(aws.InternalChartsPath, "seed-controlplane"),
		SubCharts: []*chart.Chart{
			{
				Name:   aws.CloudControllerManagerName,
				Images: []string{aws.CloudControllerManagerImageName},
				Objects: []*chart.Object{
					{Type: &corev1.Service{}, Name: aws.CloudControllerManagerName},
					{Type: &appsv1.Deployment{}, Name: aws.CloudControllerManagerName},
					{Type: &corev1.ConfigMap{}, Name: aws.CloudControllerManagerName + "-observability-config"},
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
					{Type: &appsv1.Deployment{}, Name: aws.CSISnapshotValidation},
					{Type: &corev1.Service{}, Name: aws.CSISnapshotValidation},
					{Type: &networkingv1.NetworkPolicy{}, Name: "allow-kube-apiserver-to-csi-snapshot-validation"},
				},
			},
		},
	}

	controlPlaneShootChart = &chart.Chart{
		Name: "shoot-system-components",
		Path: filepath.Join(aws.InternalChartsPath, "shoot-system-components"),
		SubCharts: []*chart.Chart{
			{
				Name: "cloud-controller-manager",
				Path: filepath.Join(aws.InternalChartsPath, "cloud-controller-manager"),
				Objects: []*chart.Object{
					{Type: &rbacv1.ClusterRole{}, Name: "system:controller:cloud-node-controller"},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: "system:controller:cloud-node-controller"},
				},
			},
			{
				Name: aws.AWSCustomRouteControllerName,
				Path: filepath.Join(aws.InternalChartsPath, "aws-custom-route-controller"),
				Objects: []*chart.Object{
					{Type: &rbacv1.ClusterRole{}, Name: "extensions.gardener.cloud:provider-aws:aws-custom-route-controller"},
					{Type: &rbacv1.ClusterRoleBinding{}, Name: "extensions.gardener.cloud:provider-aws:aws-custom-route-controller"},
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
					{Type: &policyv1beta1.PodSecurityPolicy{}, Name: strings.Replace(aws.UsernamePrefix+aws.CSIDriverName, ":", ".", -1)},
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
					{Type: &admissionregistrationv1.ValidatingWebhookConfiguration{}, Name: aws.CSISnapshotValidation},
				},
			},
		},
	}

	controlPlaneShootCRDsChart = &chart.Chart{
		Name: "shoot-crds",
		Path: filepath.Join(aws.InternalChartsPath, "shoot-crds"),
		SubCharts: []*chart.Chart{
			{
				Name: "volumesnapshots",
				Objects: []*chart.Object{
					{Type: &apiextensionsv1.CustomResourceDefinition{}, Name: "volumesnapshotclasses.snapshot.storage.k8s.io"},
					{Type: &apiextensionsv1.CustomResourceDefinition{}, Name: "volumesnapshotcontents.snapshot.storage.k8s.io"},
					{Type: &apiextensionsv1.CustomResourceDefinition{}, Name: "volumesnapshots.snapshot.storage.k8s.io"},
				},
			},
		},
	}

	storageClassChart = &chart.Chart{
		Name: "shoot-storageclasses",
		Path: filepath.Join(aws.InternalChartsPath, "shoot-storageclasses"),
	}

	cpExposureChart = &chart.Chart{
		Name:   aws.LBReadvertiserDeploymentName,
		Path:   filepath.Join(aws.InternalChartsPath, aws.LBReadvertiserDeploymentName),
		Images: []string{aws.AWSLBReadvertiserImageName},
		Objects: []*chart.Object{
			{Type: &appsv1.Deployment{}, Name: aws.LBReadvertiserDeploymentName},
			{Type: extensionscontroller.GetVerticalPodAutoscalerObject(), Name: aws.LBReadvertiserDeploymentName + "-vpa"},
		},
	}
)

// NewValuesProvider creates a new ValuesProvider for the generic actuator.
func NewValuesProvider() genericactuator.ValuesProvider {
	return &valuesProvider{}
}

// valuesProvider is a ValuesProvider that provides AWS-specific values for the 2 charts applied by the generic actuator.
type valuesProvider struct {
	common.ClientContext
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
		if _, _, err := vp.Decoder().Decode(cp.Spec.InfrastructureProviderStatus.Raw, nil, infraStatus); err != nil {
			return nil, fmt.Errorf("could not decode infrastructureProviderStatus of controlplane '%s': %w", kutil.ObjectName(cp), err)
		}
	}

	// Get config chart values
	return getConfigChartValues(infraStatus, cp)
}

// GetControlPlaneChartValues returns the values for the control plane chart applied by the generic actuator.
func (vp *valuesProvider) GetControlPlaneChartValues(
	_ context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
) (map[string]interface{}, error) {
	// Decode providerConfig
	cpConfig := &apisaws.ControlPlaneConfig{}
	if cp.Spec.ProviderConfig != nil {
		if _, _, err := vp.Decoder().Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig); err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", kutil.ObjectName(cp), err)
		}
	}

	return getControlPlaneChartValues(cpConfig, cp, cluster, secretsReader, checksums, scaledDown)
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
		if _, _, err := vp.Decoder().Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig); err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", kutil.ObjectName(cp), err)
		}
	}

	return getControlPlaneShootChartValues(cluster, cpConfig, cp, secretsReader)
}

// GetControlPlaneShootCRDsChartValues returns the values for the control plane shoot CRDs chart applied by the generic actuator.
// Currently the provider extension does not specify a control plane shoot CRDs chart. That's why we simply return empty values.
func (vp *valuesProvider) GetControlPlaneShootCRDsChartValues(
	_ context.Context,
	_ *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
) (map[string]interface{}, error) {
	csiEnabled, err := version.CompareVersions(cluster.Shoot.Spec.Kubernetes.Version, ">=", aws.GetCSIMigrationKubernetesVersion(cluster))
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"volumesnapshots": map[string]interface{}{
			"enabled": csiEnabled,
		},
	}, nil
}

// GetStorageClassesChartValues returns the values for the storage classes chart applied by the generic actuator.
func (vp *valuesProvider) GetStorageClassesChartValues(
	_ context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
) (map[string]interface{}, error) {
	csiEnabled, err := version.CompareVersions(cluster.Shoot.Spec.Kubernetes.Version, ">=", aws.GetCSIMigrationKubernetesVersion(cluster))
	if err != nil {
		return nil, err
	}

	managedDefaultClass := true

	if cp.Spec.ProviderConfig != nil {
		cpConfig := &apisaws.ControlPlaneConfig{}
		_, _, err := vp.Decoder().Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig)
		if err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of controlplane '%s': %w", kutil.ObjectName(cp), err)
		}

		// internal types should NOT be used when embeding.
		// There should not be any defaulting for internal types.
		// This checks is to be 100% sure that we won't hit nil dereference.
		if cpConfig.Storage != nil && cpConfig.Storage.ManagedDefaultClass != nil {
			managedDefaultClass = *cpConfig.Storage.ManagedDefaultClass
		}
	}

	return map[string]interface{}{
		"useLegacyProvisioner": !csiEnabled,
		"managedDefaultClass":  managedDefaultClass,
	}, nil
}

// GetControlPlaneExposureChartValues deploys the aws-lb-readvertiser.
func (vp *valuesProvider) GetControlPlaneExposureChartValues(
	ctx context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	_ secretsmanager.Reader,
	_ map[string]string,
) (map[string]interface{}, error) {
	var address string

	if !controller.IsHibernated(cluster) {
		// Get load balancer address of the kube-apiserver service
		var err error
		address, err = kutil.GetLoadBalancerIngress(ctx, vp.Client(), &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: cp.Namespace, Name: v1beta1constants.DeploymentNameKubeAPIServer}})
		if err != nil {
			return nil, fmt.Errorf("could not get kube-apiserver service load balancer address: %w", err)
		}
	}

	return map[string]interface{}{
		"domain":                           address,
		"replicas":                         extensionscontroller.GetReplicas(cluster, 1),
		"genericTokenKubeconfigSecretName": extensionscontroller.GenericTokenKubeconfigSecretNameFromCluster(cluster),
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
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
) (map[string]interface{}, error) {
	ccm, err := getCCMChartValues(cpConfig, cp, cluster, secretsReader, checksums, scaledDown)
	if err != nil {
		return nil, err
	}

	crc, err := getCRCChartValues(cpConfig, cp, cluster, checksums, scaledDown)
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
		aws.CloudControllerManagerName:   ccm,
		aws.AWSCustomRouteControllerName: crc,
		aws.CSIControllerName:            csi,
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
) (map[string]interface{}, error) {
	kubeVersion, err := semver.NewVersion(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return nil, err
	}

	serverSecret, found := secretsReader.Get(cloudControllerManagerServerName)
	if !found {
		return nil, fmt.Errorf("secret %q not found", cloudControllerManagerServerName)
	}

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
		"tlsCipherSuites": kutil.TLSCipherSuites(kubeVersion),
		"secrets": map[string]interface{}{
			"server": serverSecret.Name,
		},
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
	enabled := cpConfig.CloudControllerManager != nil &&
		cpConfig.CloudControllerManager.UseCustomRouteController != nil &&
		*cpConfig.CloudControllerManager.UseCustomRouteController

	values := map[string]interface{}{
		"enabled":     enabled,
		"replicas":    extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown || !enabled, 1),
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

	return values, nil
}

// getCSIControllerChartValues collects and returns the CSIController chart values.
func getCSIControllerChartValues(
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	secretsReader secretsmanager.Reader,
	checksums map[string]string,
	scaledDown bool,
) (map[string]interface{}, error) {
	csiEnabled, err := version.CompareVersions(cluster.Shoot.Spec.Kubernetes.Version, ">=", aws.GetCSIMigrationKubernetesVersion(cluster))
	if err != nil {
		return nil, err
	}

	if !csiEnabled {
		return map[string]interface{}{"enabled": false}, nil
	}

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
	csiEnabled, err := version.CompareVersions(kubernetesVersion, ">=", aws.GetCSIMigrationKubernetesVersion(cluster))
	if err != nil {
		return nil, err
	}

	caSecret, found := secretsReader.Get(caNameControlPlane)
	if !found {
		return nil, fmt.Errorf("secret %q not found", caNameControlPlane)
	}

	customRouteControllerEnabled := cpConfig.CloudControllerManager != nil &&
		cpConfig.CloudControllerManager.UseCustomRouteController != nil &&
		*cpConfig.CloudControllerManager.UseCustomRouteController

	csiDriverNodeValues := map[string]interface{}{
		"enabled":           csiEnabled,
		"kubernetesVersion": kubernetesVersion,
		"vpaEnabled":        gardencorev1beta1helper.ShootWantsVerticalPodAutoscaler(cluster.Shoot),
		"webhookConfig": map[string]interface{}{
			"url":      "https://" + aws.CSISnapshotValidation + "." + cp.Namespace + "/volumesnapshot",
			"caBundle": string(caSecret.Data[secretutils.DataKeyCertificateBundle]),
		},
		"pspDisabled": gardencorev1beta1helper.IsPSPDisabled(cluster.Shoot),
	}

	if value, ok := cluster.Shoot.Annotations[aws.VolumeAttachLimit]; ok {
		csiDriverNodeValues["driver"] = map[string]interface{}{
			"volumeAttachLimit": value,
		}
	}

	return map[string]interface{}{
		aws.CloudControllerManagerName:   map[string]interface{}{"enabled": true},
		aws.AWSCustomRouteControllerName: map[string]interface{}{"enabled": customRouteControllerEnabled},
		aws.CSINodeName:                  csiDriverNodeValues,
	}, nil
}
