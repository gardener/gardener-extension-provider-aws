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
	"encoding/json"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	extensionscontroller "github.com/gardener/gardener-extensions/pkg/controller"
	mockclient "github.com/gardener/gardener-extensions/pkg/mock/controller-runtime/client"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
)

const (
	namespace = "test"
)

var _ = Describe("ValuesProvider", func() {
	var (
		ctrl *gomock.Controller

		// Build scheme
		scheme = runtime.NewScheme()
		_      = apisaws.AddToScheme(scheme)

		cp = &extensionsv1alpha1.ControlPlane{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "control-plane",
				Namespace: namespace,
			},
			Spec: extensionsv1alpha1.ControlPlaneSpec{
				DefaultSpec: extensionsv1alpha1.DefaultSpec{
					ProviderConfig: &runtime.RawExtension{
						Raw: encode(&apisaws.ControlPlaneConfig{
							CloudControllerManager: &apisaws.CloudControllerManagerConfig{
								FeatureGates: map[string]bool{
									"CustomResourceValidation": true,
								},
							},
						}),
					},
				},
				InfrastructureProviderStatus: &runtime.RawExtension{
					Raw: encode(&apisaws.InfrastructureStatus{
						VPC: apisaws.VPCStatus{
							ID: "vpc-1234",
							Subnets: []apisaws.Subnet{
								{
									ID:      "subnet-acbd1234",
									Purpose: "public",
									Zone:    "eu-west-1a",
								},
							},
						},
					}),
				},
			},
		}

		cidr    = "10.250.0.0/19"
		cluster = &extensionscontroller.Cluster{
			Shoot: &gardencorev1beta1.Shoot{
				Spec: gardencorev1beta1.ShootSpec{
					Networking: gardencorev1beta1.Networking{
						Pods: &cidr,
					},
					Kubernetes: gardencorev1beta1.Kubernetes{
						Version: "1.13.4",
					},
				},
			},
		}
		cpService = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      v1beta1constants.DeploymentNameKubeAPIServer,
				Namespace: namespace,
			},
			Status: corev1.ServiceStatus{
				LoadBalancer: corev1.LoadBalancerStatus{
					Ingress: []corev1.LoadBalancerIngress{
						{IP: "10.10.10.1"},
					},
				},
			},
		}

		checksums = map[string]string{
			v1beta1constants.SecretNameCloudProvider: "8bafb35ff1ac60275d62e1cbd495aceb511fb354f74a20f7d06ecb48b3a68432",
			aws.CloudProviderConfigName:              "08a7bc7fe8f59b055f173145e211760a83f02cf89635cef26ebb351378635606",
			"cloud-controller-manager":               "3d791b164a808638da9a8df03924be2a41e34cd664e42231c00fe369e3588272",
			"cloud-controller-manager-server":        "6dff2a2e6f14444b66d8e4a351c049f7e89ee24ba3eaab95dbec40ba6bdebb52",
			aws.LBReadvertiserDeploymentName:         "599aeee0cbbfdab4ea29c642cb04a6c9a3eb90ec21b41570efb987958f99d4b1",
		}

		configChartValues = map[string]interface{}{
			"vpcID":       "vpc-1234",
			"subnetID":    "subnet-acbd1234",
			"clusterName": namespace,
			"zone":        "eu-west-1a",
		}

		ccmChartValues = map[string]interface{}{
			"replicas":          1,
			"clusterName":       namespace,
			"kubernetesVersion": "1.13.4",
			"podNetwork":        cidr,
			"podAnnotations": map[string]interface{}{
				"checksum/secret-cloud-controller-manager":        "3d791b164a808638da9a8df03924be2a41e34cd664e42231c00fe369e3588272",
				"checksum/secret-cloud-controller-manager-server": "6dff2a2e6f14444b66d8e4a351c049f7e89ee24ba3eaab95dbec40ba6bdebb52",
				"checksum/secret-cloudprovider":                   "8bafb35ff1ac60275d62e1cbd495aceb511fb354f74a20f7d06ecb48b3a68432",
				"checksum/configmap-cloud-provider-config":        "08a7bc7fe8f59b055f173145e211760a83f02cf89635cef26ebb351378635606",
			},
			"podLabels": map[string]interface{}{
				"maintenance.gardener.cloud/restart": "true",
			},
			"featureGates": map[string]bool{
				"CustomResourceValidation": true,
			},
		}

		cpExposureChartValues = map[string]interface{}{
			"domain":   "10.10.10.1",
			"replicas": 1,
			"podAnnotations": map[string]interface{}{
				"checksum/secret-aws-lb-readvertiser": "599aeee0cbbfdab4ea29c642cb04a6c9a3eb90ec21b41570efb987958f99d4b1",
			},
		}

		logger = log.Log.WithName("test")
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#GetConfigChartValues", func() {
		It("should return correct config chart values", func() {
			// Create valuesProvider
			vp := NewValuesProvider(logger)
			err := vp.(inject.Scheme).InjectScheme(scheme)
			Expect(err).NotTo(HaveOccurred())

			// Call GetConfigChartValues method and check the result
			values, err := vp.GetConfigChartValues(context.TODO(), cp, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(configChartValues))
		})
	})

	Describe("#GetControlPlaneChartValues", func() {
		It("should return correct control plane chart values", func() {
			// Create valuesProvider
			vp := NewValuesProvider(logger)
			err := vp.(inject.Scheme).InjectScheme(scheme)
			Expect(err).NotTo(HaveOccurred())

			// Call GetControlPlaneChartValues method and check the result
			values, err := vp.GetControlPlaneChartValues(context.TODO(), cp, cluster, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(ccmChartValues))
		})
	})

	Describe("#GetControlPlaneExposureChartValues", func() {
		It("should return correct control plane exposure chart values", func() {
			serviceKey := client.ObjectKey{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeAPIServer}
			// Create mock client
			client := mockclient.NewMockClient(ctrl)
			client.EXPECT().Get(context.TODO(), serviceKey, &corev1.Service{}).DoAndReturn(clientGet(cpService))

			// Create valuesProvider
			vp := NewValuesProvider(logger)
			err := vp.(inject.Scheme).InjectScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			err = vp.(inject.Client).InjectClient(client)
			Expect(err).NotTo(HaveOccurred())

			// Call GetControlPlaneChartValues method and check the result
			values, err := vp.GetControlPlaneExposureChartValues(context.TODO(), cp, cluster, checksums)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(cpExposureChartValues))
		})
	})
})

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}

func clientGet(result runtime.Object) interface{} {
	return func(ctx context.Context, key client.ObjectKey, obj runtime.Object) error {
		switch obj.(type) {
		case *corev1.Service:
			*obj.(*corev1.Service) = *result.(*corev1.Service)
		}
		return nil
	}
}
