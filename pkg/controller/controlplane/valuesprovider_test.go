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
	"io/ioutil"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane/genericactuator"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	"github.com/gardener/gardener/pkg/utils"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
)

const namespace = "test"

var _ = Describe("ValuesProvider", func() {
	var (
		ctrl                  *gomock.Controller
		c                     *mockclient.MockClient
		encoder               runtime.Encoder
		ctx                   context.Context
		logger                logr.Logger
		scheme                *runtime.Scheme
		vp                    genericactuator.ValuesProvider
		region                string
		cp                    *extensionsv1alpha1.ControlPlane
		cidr                  string
		clusterK8sLessThan118 *extensionscontroller.Cluster
		clusterK8sAtLeast118  *extensionscontroller.Cluster
		checksums             map[string]string
		enabledTrue           map[string]interface{}
		enabledFalse          map[string]interface{}
		encode                = func(obj runtime.Object) []byte {
			b := &bytes.Buffer{}
			Expect(encoder.Encode(obj, b)).To(Succeed())

			data, err := ioutil.ReadAll(b)
			Expect(err).ToNot(HaveOccurred())

			return data
		}
	)

	BeforeEach(func() {
		ctx = context.TODO()
		logger = log.Log.WithName("test")
		scheme = runtime.NewScheme()

		Expect(apisaws.AddToScheme(scheme)).To(Succeed())
		Expect(apisawsv1alpha1.AddToScheme(scheme)).To(Succeed())

		codec := serializer.NewCodecFactory(scheme, serializer.EnableStrict)

		info, found := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeJSON)
		Expect(found).To(BeTrue(), "should be able to decode")

		encoder = codec.EncoderForVersion(info.Serializer, apisawsv1alpha1.SchemeGroupVersion)

		region = "europe"
		cidr = "10.250.0.0/19"

		cp = &extensionsv1alpha1.ControlPlane{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "control-plane",
				Namespace: namespace,
			},
			Spec: extensionsv1alpha1.ControlPlaneSpec{
				DefaultSpec: extensionsv1alpha1.DefaultSpec{
					ProviderConfig: &runtime.RawExtension{
						Raw: encode(&apisawsv1alpha1.ControlPlaneConfig{
							CloudControllerManager: &apisawsv1alpha1.CloudControllerManagerConfig{
								FeatureGates: map[string]bool{
									"CustomResourceValidation": true,
								},
							},
						}),
					},
				},
				InfrastructureProviderStatus: &runtime.RawExtension{
					Raw: encode(&apisawsv1alpha1.InfrastructureStatus{
						VPC: apisawsv1alpha1.VPCStatus{
							ID: "vpc-1234",
							Subnets: []apisawsv1alpha1.Subnet{
								{
									ID:      "subnet-acbd1234",
									Purpose: "public",
									Zone:    "eu-west-1a",
								},
							},
						},
					}),
				},
				Region: region,
			},
		}

		clusterK8sLessThan118 = &extensionscontroller.Cluster{
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

		clusterK8sAtLeast118 = &extensionscontroller.Cluster{
			Shoot: &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						aws.VolumeAttachLimit: "42",
					},
				},
				Spec: gardencorev1beta1.ShootSpec{
					Networking: gardencorev1beta1.Networking{
						Pods: &cidr,
					},
					Kubernetes: gardencorev1beta1.Kubernetes{
						Version: "1.18.1",
						VerticalPodAutoscaler: &gardencorev1beta1.VerticalPodAutoscaler{
							Enabled: true,
						},
					},
				},
			},
		}

		checksums = map[string]string{
			v1beta1constants.SecretNameCloudProvider:   "8bafb35ff1ac60275d62e1cbd495aceb511fb354f74a20f7d06ecb48b3a68432",
			aws.CloudProviderConfigName:                "08a7bc7fe8f59b055f173145e211760a83f02cf89635cef26ebb351378635606",
			aws.CloudControllerManagerName:             "3d791b164a808638da9a8df03924be2a41e34cd664e42231c00fe369e3588272",
			aws.CloudControllerManagerName + "-server": "6dff2a2e6f14444b66d8e4a351c049f7e89ee24ba3eaab95dbec40ba6bdebb52",
			aws.LBReadvertiserDeploymentName:           "599aeee0cbbfdab4ea29c642cb04a6c9a3eb90ec21b41570efb987958f99d4b1",
			aws.CSIProvisionerName:                     "65b1dac6b50673535cff480564c2e5c71077ed19b1b6e0e2291207225bdf77d4",
			aws.CSIAttacherName:                        "3f22909841cdbb80e5382d689d920309c0a7d995128e52c79773f9608ed7c289",
			aws.CSISnapshotterName:                     "6a5bfc847638c499062f7fb44e31a30a9760bf4179e1dbf85e0ff4b4f162cd68",
			aws.CSIResizerName:                         "a77e663ba1af340fb3dd7f6f8a1be47c7aa9e658198695480641e6b934c0b9ed",
			aws.CSISnapshotControllerName:              "84cba346d2e2cf96c3811b55b01f57bdd9b9bcaed7065760470942d267984eaf",
		}

		enabledTrue = map[string]interface{}{"enabled": true}
		enabledFalse = map[string]interface{}{"enabled": false}

		ctrl = gomock.NewController(GinkgoT())
		vp = NewValuesProvider(logger)

		Expect(vp.(inject.Scheme).InjectScheme(scheme)).To(Succeed())
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#GetConfigChartValues", func() {
		It("should return correct config chart values", func() {
			values, err := vp.GetConfigChartValues(ctx, cp, clusterK8sLessThan118)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"vpcID":       "vpc-1234",
				"subnetID":    "subnet-acbd1234",
				"clusterName": namespace,
				"zone":        "eu-west-1a",
			}))
		})
	})

	Describe("#GetControlPlaneChartValues", func() {
		var ccmChartValues map[string]interface{}

		BeforeEach(func() {
			ccmChartValues = utils.MergeMaps(enabledTrue, map[string]interface{}{
				"replicas":    1,
				"clusterName": namespace,
				"podNetwork":  cidr,
				"podLabels": map[string]interface{}{
					"maintenance.gardener.cloud/restart": "true",
				},
				"podAnnotations": map[string]interface{}{
					"checksum/secret-" + aws.CloudControllerManagerName:             checksums[aws.CloudControllerManagerName],
					"checksum/secret-" + aws.CloudControllerManagerName + "-server": checksums[aws.CloudControllerManagerName+"-server"],
					"checksum/secret-" + v1beta1constants.SecretNameCloudProvider:   checksums[v1beta1constants.SecretNameCloudProvider],
					"checksum/configmap-" + aws.CloudProviderConfigName:             checksums[aws.CloudProviderConfigName],
				},
				"featureGates": map[string]bool{
					"CustomResourceValidation": true,
				},
			})
			c = mockclient.NewMockClient(ctrl)

			err := vp.(inject.Client).InjectClient(c)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return correct control plane chart values (k8s < 1.18)", func() {
			values, err := vp.GetControlPlaneChartValues(ctx, cp, clusterK8sLessThan118, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": clusterK8sLessThan118.Shoot.Spec.Kubernetes.Version,
				}),
				aws.CSIControllerName: enabledFalse,
			}))
		})

		It("should return correct control plane chart values (k8s >= 1.18)", func() {
			values, err := vp.GetControlPlaneChartValues(ctx, cp, clusterK8sAtLeast118, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": clusterK8sAtLeast118.Shoot.Spec.Kubernetes.Version,
				}),
				aws.CSIControllerName: utils.MergeMaps(enabledTrue, map[string]interface{}{
					"replicas": 1,
					"region":   region,
					"podAnnotations": map[string]interface{}{
						"checksum/secret-" + aws.CSIProvisionerName:                   checksums[aws.CSIProvisionerName],
						"checksum/secret-" + aws.CSIAttacherName:                      checksums[aws.CSIAttacherName],
						"checksum/secret-" + aws.CSISnapshotterName:                   checksums[aws.CSISnapshotterName],
						"checksum/secret-" + aws.CSIResizerName:                       checksums[aws.CSIResizerName],
						"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
					},
					"csiSnapshotController": map[string]interface{}{
						"replicas": 1,
						"podAnnotations": map[string]interface{}{
							"checksum/secret-" + aws.CSISnapshotControllerName: checksums[aws.CSISnapshotControllerName],
						},
					},
				}),
			}))
		})
	})

	Describe("#GetControlPlaneShootChartValues", func() {
		It("should return correct shoot control plane chart values (k8s < 1.18)", func() {
			values, err := vp.GetControlPlaneShootChartValues(ctx, cp, clusterK8sLessThan118, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				aws.CloudControllerManagerName: enabledTrue,
				aws.CSINodeName: utils.MergeMaps(enabledFalse, map[string]interface{}{
					"vpaEnabled": false,
				}),
			}))
		})

		It("should return correct shoot control plane chart values (k8s >= 1.18)", func() {
			values, err := vp.GetControlPlaneShootChartValues(ctx, cp, clusterK8sAtLeast118, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				aws.CloudControllerManagerName: enabledTrue,
				aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
					"vpaEnabled": true,
					"driver": map[string]interface{}{
						"volumeAttachLimit": "42",
					},
				}),
			}))
		})
	})

	Describe("#GetStorageClassesChartValues()", func() {
		It("should return correct storage class chart values (k8s < 1.18)", func() {
			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sLessThan118)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"useLegacyProvisioner": true,
				"managedDefaultClass":  true,
			}))
		})

		It("should return correct storage class chart values (k8s < 1.18) and default is set to true", func() {
			cp.Spec.DefaultSpec.ProviderConfig.Raw = encode(&apisawsv1alpha1.ControlPlaneConfig{
				Storage: &apisawsv1alpha1.Storage{
					ManagedDefaultClass: pointer.BoolPtr(true),
				},
			})

			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sLessThan118)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"useLegacyProvisioner": true,
				"managedDefaultClass":  true,
			}))
		})

		It("should return correct storage class chart values (k8s < 1.18) and default is set to false", func() {
			cp.Spec.DefaultSpec.ProviderConfig.Raw = encode(&apisawsv1alpha1.ControlPlaneConfig{
				Storage: &apisawsv1alpha1.Storage{
					ManagedDefaultClass: pointer.BoolPtr(false),
				},
			})

			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sLessThan118)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"useLegacyProvisioner": true,
				"managedDefaultClass":  false,
			}))
		})

		It("should return correct storage class chart values (k8s >= 1.18)", func() {
			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sAtLeast118)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"useLegacyProvisioner": false,
				"managedDefaultClass":  true,
			}))
		})

		It("should return correct storage class chart values (k8s >= 1.18) and default is set to true", func() {
			cp.Spec.DefaultSpec.ProviderConfig.Raw = encode(&apisawsv1alpha1.ControlPlaneConfig{
				Storage: &apisawsv1alpha1.Storage{
					ManagedDefaultClass: pointer.BoolPtr(true),
				},
			})

			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sAtLeast118)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"useLegacyProvisioner": false,
				"managedDefaultClass":  true,
			}))
		})

		It("should return correct storage class chart values (k8s >= 1.18) and default is set to false", func() {
			cp.Spec.DefaultSpec.ProviderConfig.Raw = encode(&apisawsv1alpha1.ControlPlaneConfig{
				Storage: &apisawsv1alpha1.Storage{
					ManagedDefaultClass: pointer.BoolPtr(false),
				},
			})

			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sAtLeast118)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"useLegacyProvisioner": false,
				"managedDefaultClass":  false,
			}))
		})

		It("should have managedDefaultClass to true when using internal resource", func() {
			internal := `{"kind":"ControlPlaneConfig","apiVersion":"aws.provider.extensions.gardener.cloud/__internal"}`

			cp.Spec.DefaultSpec.ProviderConfig.Raw = []byte(internal)

			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sLessThan118)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"useLegacyProvisioner": true,
				"managedDefaultClass":  true,
			}))
		})
	})

	Describe("#GetControlPlaneExposureChartValues", func() {
		var (
			c *mockclient.MockClient

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
		)

		BeforeEach(func() {
			c = mockclient.NewMockClient(ctrl)

			err := vp.(inject.Client).InjectClient(c)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return correct control plane exposure chart values", func() {
			serviceKey := client.ObjectKey{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeAPIServer}
			c.EXPECT().Get(ctx, serviceKey, gomock.AssignableToTypeOf(&corev1.Service{})).DoAndReturn(clientGet(cpService))

			values, err := vp.GetControlPlaneExposureChartValues(ctx, cp, clusterK8sLessThan118, checksums)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"domain":   "10.10.10.1",
				"replicas": 1,
				"podAnnotations": map[string]interface{}{
					"checksum/secret-aws-lb-readvertiser": "599aeee0cbbfdab4ea29c642cb04a6c9a3eb90ec21b41570efb987958f99d4b1",
				},
			}))
		})
	})
})

func clientGet(result runtime.Object) interface{} {
	return func(ctx context.Context, key client.ObjectKey, obj runtime.Object) error {
		switch obj.(type) {
		case *corev1.Service:
			*obj.(*corev1.Service) = *result.(*corev1.Service)
		}
		return nil
	}
}
