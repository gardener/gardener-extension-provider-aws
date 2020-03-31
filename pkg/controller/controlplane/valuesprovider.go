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
	"path/filepath"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extensions/pkg/controller"
	extensionscontroller "github.com/gardener/gardener-extensions/pkg/controller"
	"github.com/gardener/gardener-extensions/pkg/controller/common"
	"github.com/gardener/gardener-extensions/pkg/controller/controlplane"
	"github.com/gardener/gardener-extensions/pkg/controller/controlplane/genericactuator"
	"github.com/gardener/gardener-extensions/pkg/util"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/chart"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

// Object names
const (
	cloudControllerManagerServerName = "cloud-controller-manager-server"
)

var controlPlaneSecrets = &secrets.Secrets{
	CertificateSecretConfigs: map[string]*secrets.CertificateSecretConfig{
		v1beta1constants.SecretNameCACluster: {
			Name:       v1beta1constants.SecretNameCACluster,
			CommonName: "kubernetes",
			CertType:   secrets.CACert,
		},
	},
	SecretConfigsFunc: func(cas map[string]*secrets.Certificate, clusterName string) []secrets.ConfigInterface {
		return []secrets.ConfigInterface{
			&secrets.ControlPlaneSecretConfig{
				CertificateSecretConfig: &secrets.CertificateSecretConfig{
					Name:         aws.CloudControllerManagerName,
					CommonName:   "system:cloud-controller-manager",
					Organization: []string{user.SystemPrivilegedGroup},
					CertType:     secrets.ClientCert,
					SigningCA:    cas[v1beta1constants.SecretNameCACluster],
				},
				KubeConfigRequest: &secrets.KubeConfigRequest{
					ClusterName:  clusterName,
					APIServerURL: v1beta1constants.DeploymentNameKubeAPIServer,
				},
			},
			&secrets.ControlPlaneSecretConfig{
				CertificateSecretConfig: &secrets.CertificateSecretConfig{
					Name:       cloudControllerManagerServerName,
					CommonName: aws.CloudControllerManagerName,
					DNSNames:   controlplane.DNSNamesForService(aws.CloudControllerManagerName, clusterName),
					CertType:   secrets.ServerCert,
					SigningCA:  cas[v1beta1constants.SecretNameCACluster],
				},
			},
		}
	},
}

var controlPlaneExposureSecrets = &secrets.Secrets{
	CertificateSecretConfigs: map[string]*secrets.CertificateSecretConfig{
		v1beta1constants.SecretNameCACluster: {
			Name:       v1beta1constants.SecretNameCACluster,
			CommonName: "kubernetes",
			CertType:   secrets.CACert,
		},
	},
	SecretConfigsFunc: func(cas map[string]*secrets.Certificate, clusterName string) []secrets.ConfigInterface {
		return []secrets.ConfigInterface{
			&secrets.ControlPlaneSecretConfig{
				CertificateSecretConfig: &secrets.CertificateSecretConfig{
					Name:         aws.LBReadvertiserDeploymentName,
					CommonName:   aws.LBReadvertiserDeploymentName,
					Organization: []string{user.SystemPrivilegedGroup},
					DNSNames:     nil,
					IPAddresses:  nil,
					CertType:     secrets.ClientCert,
					SigningCA:    cas[v1beta1constants.SecretNameCACluster],
				},

				KubeConfigRequest: &secrets.KubeConfigRequest{
					ClusterName:  clusterName,
					APIServerURL: v1beta1constants.DeploymentNameKubeAPIServer,
				},
			},
		}
	},
}

var configChart = &chart.Chart{
	Name: "cloud-provider-config",
	Path: filepath.Join(aws.InternalChartsPath, "cloud-provider-config"),
	Objects: []*chart.Object{
		{
			Type: &corev1.ConfigMap{},
			Name: aws.CloudProviderConfigName,
		},
	},
}

var ccmChart = &chart.Chart{
	Name:   "cloud-controller-manager",
	Path:   filepath.Join(aws.InternalChartsPath, "cloud-controller-manager"),
	Images: []string{aws.CloudControllerManagerImageName},
	Objects: []*chart.Object{
		{Type: &corev1.Service{}, Name: "cloud-controller-manager"},
		{Type: &appsv1.Deployment{}, Name: "cloud-controller-manager"},
		{Type: &corev1.ConfigMap{}, Name: "cloud-controller-manager-monitoring-config"},
	},
}

var ccmShootChart = &chart.Chart{
	Name: "cloud-controller-manager-shoot",
	Path: filepath.Join(aws.InternalChartsPath, "cloud-controller-manager-shoot"),
	Objects: []*chart.Object{
		{Type: &rbacv1.ClusterRole{}, Name: "system:controller:cloud-node-controller"},
		{Type: &rbacv1.ClusterRoleBinding{}, Name: "system:controller:cloud-node-controller"},
	},
}

var storageClassChart = &chart.Chart{
	Name: "shoot-storageclasses",
	Path: filepath.Join(aws.InternalChartsPath, "shoot-storageclasses"),
}

var cpExposureChart = &chart.Chart{
	Name:   "aws-lb-readvertiser",
	Path:   filepath.Join(aws.InternalChartsPath, "aws-lb-readvertiser"),
	Images: []string{aws.AWSLBReadvertiserImageName},
	Objects: []*chart.Object{
		{Type: &appsv1.Deployment{}, Name: "aws-lb-readvertiser"},
		{Type: extensionscontroller.GetVerticalPodAutoscalerObject(), Name: "aws-lb-readvertiser-vpa"},
	},
}

// NewValuesProvider creates a new ValuesProvider for the generic actuator.
func NewValuesProvider(logger logr.Logger) genericactuator.ValuesProvider {
	return &valuesProvider{
		logger: logger.WithName("aws-values-provider"),
	}
}

// valuesProvider is a ValuesProvider that provides AWS-specific values for the 2 charts applied by the generic actuator.
type valuesProvider struct {
	genericactuator.NoopValuesProvider
	common.ClientContext
	logger logr.Logger
}

// GetConfigChartValues returns the values for the config chart applied by the generic actuator.
func (vp *valuesProvider) GetConfigChartValues(
	ctx context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
) (map[string]interface{}, error) {
	// Decode infrastructureProviderStatus
	infraStatus := &apisaws.InfrastructureStatus{}
	if cp.Spec.InfrastructureProviderStatus != nil {
		if _, _, err := vp.Decoder().Decode(cp.Spec.InfrastructureProviderStatus.Raw, nil, infraStatus); err != nil {
			return nil, errors.Wrapf(err, "could not decode infrastructureProviderStatus of controlplane '%s'", util.ObjectName(cp))
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
	checksums map[string]string,
	scaledDown bool,
) (map[string]interface{}, error) {
	// Decode providerConfig
	cpConfig := &apisaws.ControlPlaneConfig{}
	if cp.Spec.ProviderConfig != nil {
		if _, _, err := vp.Decoder().Decode(cp.Spec.ProviderConfig.Raw, nil, cpConfig); err != nil {
			return nil, errors.Wrapf(err, "could not decode providerConfig of controlplane '%s'", util.ObjectName(cp))
		}
	}

	// Get CCM chart values
	return getCCMChartValues(cpConfig, cp, cluster, checksums, scaledDown)
}

// GetControlPlaneExposureChartValues deploys the aws-lb-readvertiser.
func (vp *valuesProvider) GetControlPlaneExposureChartValues(
	ctx context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	checksums map[string]string,
) (map[string]interface{}, error) {
	var address string

	if !controller.IsHibernated(cluster) {
		// Get load balancer address of the kube-apiserver service
		var err error
		address, err = kutil.GetLoadBalancerIngress(ctx, vp.Client(), cp.Namespace, v1beta1constants.DeploymentNameKubeAPIServer)
		if err != nil {
			return nil, errors.Wrap(err, "could not get kube-apiserver service load balancer address")
		}
	}

	return map[string]interface{}{
		"domain":   address,
		"replicas": extensionscontroller.GetReplicas(cluster, 1),
		"podAnnotations": map[string]interface{}{
			"checksum/secret-aws-lb-readvertiser": checksums[aws.LBReadvertiserDeploymentName],
		},
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
		return nil, errors.Wrapf(err, "could not determine subnet from infrastructureProviderStatus of controlplane '%s'", util.ObjectName(cp))
	}

	// Collect config chart values
	return map[string]interface{}{
		"vpcID":       infraStatus.VPC.ID,
		"subnetID":    subnet.ID,
		"clusterName": cp.Namespace,
		"zone":        subnet.Zone,
	}, nil
}

// getCCMChartValues collects and returns the CCM chart values.
func getCCMChartValues(
	cpConfig *apisaws.ControlPlaneConfig,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
	checksums map[string]string,
	scaledDown bool,
) (map[string]interface{}, error) {
	values := map[string]interface{}{
		"replicas":          extensionscontroller.GetControlPlaneReplicas(cluster, scaledDown, 1),
		"clusterName":       cp.Namespace,
		"kubernetesVersion": cluster.Shoot.Spec.Kubernetes.Version,
		"podNetwork":        extensionscontroller.GetPodNetwork(cluster),
		"podAnnotations": map[string]interface{}{
			"checksum/secret-cloud-controller-manager":        checksums[aws.CloudControllerManagerName],
			"checksum/secret-cloud-controller-manager-server": checksums[cloudControllerManagerServerName],
			"checksum/secret-cloudprovider":                   checksums[v1beta1constants.SecretNameCloudProvider],
			"checksum/configmap-cloud-provider-config":        checksums[aws.CloudProviderConfigName],
		},
		"podLabels": map[string]interface{}{
			v1beta1constants.LabelPodMaintenanceRestart: "true",
		},
	}

	if cpConfig.CloudControllerManager != nil {
		values["featureGates"] = cpConfig.CloudControllerManager.FeatureGates
	}

	return values, nil
}
