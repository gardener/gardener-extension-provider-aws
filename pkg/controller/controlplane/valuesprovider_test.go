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
	"fmt"
	"io"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane/genericactuator"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	"github.com/gardener/gardener/pkg/utils"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	fakesecretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager/fake"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	namespace                        = "test"
	genericTokenKubeconfigSecretName = "generic-token-kubeconfig-92e9ae14"
)

var _ = Describe("ValuesProvider", func() {
	var (
		ctrl                 *gomock.Controller
		c                    *mockclient.MockClient
		encoder              runtime.Encoder
		ctx                  context.Context
		scheme               *runtime.Scheme
		vp                   genericactuator.ValuesProvider
		region               string
		cp                   *extensionsv1alpha1.ControlPlane
		cidr                 string
		clusterK8sAtLeast120 *extensionscontroller.Cluster
		checksums            map[string]string
		enabledTrue          map[string]interface{}
		enabledFalse         map[string]interface{}
		encode               = func(obj runtime.Object) []byte {
			b := &bytes.Buffer{}
			Expect(encoder.Encode(obj, b)).To(Succeed())

			data, err := io.ReadAll(b)
			Expect(err).ToNot(HaveOccurred())

			return data
		}
		setCustomRouteControllerEnabled = func(cp *extensionsv1alpha1.ControlPlane) {
			cp.Spec.ProviderConfig = &runtime.RawExtension{
				Raw: encode(&apisawsv1alpha1.ControlPlaneConfig{
					CloudControllerManager: &apisawsv1alpha1.CloudControllerManagerConfig{
						FeatureGates: map[string]bool{
							"CustomResourceValidation": true,
						},
						UseCustomRouteController: pointer.Bool(true),
					},
				}),
			}
		}
		setLoadBalancerControllerEnabled = func(cp *extensionsv1alpha1.ControlPlane, ingressClassName *string) {
			cp.Spec.ProviderConfig = &runtime.RawExtension{
				Raw: encode(&apisawsv1alpha1.ControlPlaneConfig{
					CloudControllerManager: &apisawsv1alpha1.CloudControllerManagerConfig{
						FeatureGates: map[string]bool{
							"CustomResourceValidation": true,
						},
					},
					LoadBalancerController: &apisawsv1alpha1.LoadBalancerControllerConfig{
						Enabled:          true,
						IngressClassName: ingressClassName,
					},
				}),
			}
		}

		fakeClient         client.Client
		fakeSecretsManager secretsmanager.Interface
	)

	BeforeEach(func() {
		ctx = context.TODO()
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

		clusterK8sAtLeast120 = &extensionscontroller.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"generic-token-kubeconfig.secret.gardener.cloud/name": genericTokenKubeconfigSecretName,
				},
			},
			Seed: &gardencorev1beta1.Seed{},
			Shoot: &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						aws.VolumeAttachLimit: "42",
					},
				},
				Spec: gardencorev1beta1.ShootSpec{
					Provider: gardencorev1beta1.Provider{
						Workers: []gardencorev1beta1.Worker{
							{
								Name: "worker",
							},
						},
					},
					Networking: &gardencorev1beta1.Networking{
						Pods: &cidr,
					},
					Kubernetes: gardencorev1beta1.Kubernetes{
						Version: "1.20.1",
						VerticalPodAutoscaler: &gardencorev1beta1.VerticalPodAutoscaler{
							Enabled: true,
						},
					},
				},
			},
		}

		checksums = map[string]string{
			v1beta1constants.SecretNameCloudProvider: "8bafb35ff1ac60275d62e1cbd495aceb511fb354f74a20f7d06ecb48b3a68432",
			aws.CloudProviderConfigName:              "08a7bc7fe8f59b055f173145e211760a83f02cf89635cef26ebb351378635606",
		}

		enabledTrue = map[string]interface{}{"enabled": true}
		enabledFalse = map[string]interface{}{"enabled": false}

		ctrl = gomock.NewController(GinkgoT())
		vp = NewValuesProvider()

		Expect(vp.(inject.Scheme).InjectScheme(scheme)).To(Succeed())

		fakeClient = fakeclient.NewClientBuilder().Build()
		fakeSecretsManager = fakesecretsmanager.New(fakeClient, namespace)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#GetConfigChartValues", func() {
		It("should return correct config chart values", func() {
			values, err := vp.GetConfigChartValues(ctx, cp, clusterK8sAtLeast120)
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
		var crcChartValues map[string]interface{}
		var albChartValues map[string]interface{}

		BeforeEach(func() {
			ccmChartValues = utils.MergeMaps(enabledTrue, map[string]interface{}{
				"replicas":    1,
				"clusterName": namespace,
				"podNetwork":  cidr,
				"podLabels": map[string]interface{}{
					"maintenance.gardener.cloud/restart": "true",
				},
				"podAnnotations": map[string]interface{}{
					"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
					"checksum/configmap-" + aws.CloudProviderConfigName:           checksums[aws.CloudProviderConfigName],
				},
				"featureGates": map[string]bool{
					"CustomResourceValidation": true,
				},
				"tlsCipherSuites": []string{
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
					"TLS_RSA_WITH_AES_128_CBC_SHA",
					"TLS_RSA_WITH_AES_256_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
				},
				"secrets": map[string]interface{}{
					"server": "cloud-controller-manager-server",
				},
			})
			crcChartValues = map[string]interface{}{
				"podLabels": map[string]interface{}{
					"maintenance.gardener.cloud/restart": "true",
				},
				"region":      "europe",
				"enabled":     true,
				"replicas":    0,
				"clusterName": "test",
				"podNetwork":  "10.250.0.0/19",
				"podAnnotations": map[string]interface{}{
					"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
				},
			}
			albChartValues = map[string]interface{}{
				"region":                "europe",
				"vpcId":                 "vpc-1234",
				"enabled":               true,
				"replicaCount":          0,
				"clusterName":           "test",
				"webhookCertSecretName": awsLoadBalancerControllerWebhook,
				"webhookTLS": map[string]interface{}{
					"caCert": "",
				},
				"webhookURL": fmt.Sprintf("https://%s.%s:443", awsLoadBalancerControllerWebhook, namespace),
				"defaultTags": map[string]interface{}{
					"KubernetesCluster":          "test",
					"kubernetes.io/cluster/test": "owned",
				},
				"podAnnotations": map[string]interface{}{
					"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
				},
			}
			c = mockclient.NewMockClient(ctrl)

			err := vp.(inject.Client).InjectClient(c)
			Expect(err).NotTo(HaveOccurred())

			By("creating secrets managed outside of this package for whose secretsmanager.Get() will be called")
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca-provider-aws-controlplane", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "csi-snapshot-validation-server", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cloud-controller-manager-server", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: awsLoadBalancerControllerWebhook, Namespace: namespace}})).To(Succeed())
			c.EXPECT().Delete(context.TODO(), &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-kube-apiserver-to-csi-snapshot-validation", Namespace: cp.Namespace}})
		})

		It("should return correct control plane chart values (k8s >= 1.20)", func() {
			values, err := vp.GetControlPlaneChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"global": map[string]interface{}{
					"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				},
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": clusterK8sAtLeast120.Shoot.Spec.Kubernetes.Version,
				}),
				aws.AWSCustomRouteControllerName:  crcChartValues,
				aws.AWSLoadBalancerControllerName: albChartValues,
				aws.CSIControllerName: utils.MergeMaps(enabledTrue, map[string]interface{}{
					"replicas": 1,
					"region":   region,
					"podAnnotations": map[string]interface{}{
						"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
					},
					"csiSnapshotController": map[string]interface{}{
						"replicas": 1,
					},
					"csiSnapshotValidationWebhook": map[string]interface{}{
						"replicas": 1,
						"secrets": map[string]interface{}{
							"server": "csi-snapshot-validation-server",
						},
						"topologyAwareRoutingEnabled": false,
					},
				}),
			}))
		})

		It("should return correct control plane chart values (k8s >= 1.20) and custom route controller enabled", func() {
			setCustomRouteControllerEnabled(cp)
			crcChartValues["replicas"] = 1 // chart is always deployed, but with 0 replicas when disabled

			values, err := vp.GetControlPlaneChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"global": map[string]interface{}{
					"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				},
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": clusterK8sAtLeast120.Shoot.Spec.Kubernetes.Version,
				}),
				aws.AWSCustomRouteControllerName:  crcChartValues,
				aws.AWSLoadBalancerControllerName: albChartValues,
				aws.CSIControllerName: utils.MergeMaps(enabledTrue, map[string]interface{}{
					"replicas": 1,
					"region":   region,
					"podAnnotations": map[string]interface{}{
						"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
					},
					"csiSnapshotController": map[string]interface{}{
						"replicas": 1,
					},
					"csiSnapshotValidationWebhook": map[string]interface{}{
						"replicas": 1,
						"secrets": map[string]interface{}{
							"server": "csi-snapshot-validation-server",
						},
						"topologyAwareRoutingEnabled": false,
					},
				}),
			}))
		})

		It("should return correct control plane chart values (k8s >= 1.20) and ALB enabled", func() {
			setLoadBalancerControllerEnabled(cp, nil)
			albChartValues["replicaCount"] = 1 // chart is always deployed, but with 0 replicas when disabled
			values, err := vp.GetControlPlaneChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"global": map[string]interface{}{
					"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				},
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": clusterK8sAtLeast120.Shoot.Spec.Kubernetes.Version,
				}),
				aws.AWSCustomRouteControllerName:  crcChartValues,
				aws.AWSLoadBalancerControllerName: albChartValues,
				aws.CSIControllerName: utils.MergeMaps(enabledTrue, map[string]interface{}{
					"replicas": 1,
					"region":   region,
					"podAnnotations": map[string]interface{}{
						"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
					},
					"csiSnapshotController": map[string]interface{}{
						"replicas": 1,
					},
					"csiSnapshotValidationWebhook": map[string]interface{}{
						"replicas": 1,
						"secrets": map[string]interface{}{
							"server": "csi-snapshot-validation-server",
						},
						"topologyAwareRoutingEnabled": false,
					},
				}),
			}))
		})

		It("should return correct control plane chart values (k8s >= 1.20) and ALB enabled with ingress class name", func() {
			setLoadBalancerControllerEnabled(cp, pointer.String("my-alb"))
			albChartValues["replicaCount"] = 1 // chart is always deployed, but with 0 replicas when disabled
			albChartValues["ingressClass"] = "my-alb"
			values, err := vp.GetControlPlaneChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"global": map[string]interface{}{
					"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				},
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": clusterK8sAtLeast120.Shoot.Spec.Kubernetes.Version,
				}),
				aws.AWSCustomRouteControllerName:  crcChartValues,
				aws.AWSLoadBalancerControllerName: albChartValues,
				aws.CSIControllerName: utils.MergeMaps(enabledTrue, map[string]interface{}{
					"replicas": 1,
					"region":   region,
					"podAnnotations": map[string]interface{}{
						"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
					},
					"csiSnapshotController": map[string]interface{}{
						"replicas": 1,
					},
					"csiSnapshotValidationWebhook": map[string]interface{}{
						"replicas": 1,
						"secrets": map[string]interface{}{
							"server": "csi-snapshot-validation-server",
						},
						"topologyAwareRoutingEnabled": false,
					},
				}),
			}))
		})

		DescribeTable("topologyAwareRoutingEnabled value",
			func(seedSettings *gardencorev1beta1.SeedSettings, shootControlPlane *gardencorev1beta1.ControlPlane, expected bool) {
				clusterK8sAtLeast120.Seed = &gardencorev1beta1.Seed{
					Spec: gardencorev1beta1.SeedSpec{
						Settings: seedSettings,
					},
				}
				clusterK8sAtLeast120.Shoot.Spec.ControlPlane = shootControlPlane

				values, err := vp.GetControlPlaneChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, checksums, false)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(HaveKey(aws.CSIControllerName))
				Expect(values[aws.CSIControllerName]).To(HaveKeyWithValue("csiSnapshotValidationWebhook", HaveKeyWithValue("topologyAwareRoutingEnabled", expected)))
			},

			Entry("seed setting is nil, shoot control plane is not HA",
				nil,
				&gardencorev1beta1.ControlPlane{HighAvailability: nil},
				false,
			),
			Entry("seed setting is disabled, shoot control plane is not HA",
				&gardencorev1beta1.SeedSettings{TopologyAwareRouting: &gardencorev1beta1.SeedSettingTopologyAwareRouting{Enabled: false}},
				&gardencorev1beta1.ControlPlane{HighAvailability: nil},
				false,
			),
			Entry("seed setting is enabled, shoot control plane is not HA",
				&gardencorev1beta1.SeedSettings{TopologyAwareRouting: &gardencorev1beta1.SeedSettingTopologyAwareRouting{Enabled: true}},
				&gardencorev1beta1.ControlPlane{HighAvailability: nil},
				false,
			),
			Entry("seed setting is nil, shoot control plane is HA with failure tolerance type 'zone'",
				nil,
				&gardencorev1beta1.ControlPlane{HighAvailability: &gardencorev1beta1.HighAvailability{FailureTolerance: gardencorev1beta1.FailureTolerance{Type: gardencorev1beta1.FailureToleranceTypeZone}}},
				false,
			),
			Entry("seed setting is disabled, shoot control plane is HA with failure tolerance type 'zone'",
				&gardencorev1beta1.SeedSettings{TopologyAwareRouting: &gardencorev1beta1.SeedSettingTopologyAwareRouting{Enabled: false}},
				&gardencorev1beta1.ControlPlane{HighAvailability: &gardencorev1beta1.HighAvailability{FailureTolerance: gardencorev1beta1.FailureTolerance{Type: gardencorev1beta1.FailureToleranceTypeZone}}},
				false,
			),
			Entry("seed setting is enabled, shoot control plane is HA with failure tolerance type 'zone'",
				&gardencorev1beta1.SeedSettings{TopologyAwareRouting: &gardencorev1beta1.SeedSettingTopologyAwareRouting{Enabled: true}},
				&gardencorev1beta1.ControlPlane{HighAvailability: &gardencorev1beta1.HighAvailability{FailureTolerance: gardencorev1beta1.FailureTolerance{Type: gardencorev1beta1.FailureToleranceTypeZone}}},
				true,
			),
		)
	})

	Describe("#GetControlPlaneShootChartValues", func() {
		BeforeEach(func() {
			c = mockclient.NewMockClient(ctrl)

			err := vp.(inject.Client).InjectClient(c)
			Expect(err).NotTo(HaveOccurred())

			By("creating secrets managed outside of this package for whose secretsmanager.Get() will be called")
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca-provider-aws-controlplane", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "csi-snapshot-validation-server", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cloud-controller-manager-server", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: awsLoadBalancerControllerWebhook, Namespace: namespace}})).To(Succeed())
		})

		Context("shoot control plane chart values (k8s >= 1.20)", func() {
			It("should return correct shoot control plane chart when ca is secret found", func() {
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSCustomRouteControllerName:  enabledFalse,
					aws.AWSLoadBalancerControllerName: enabledFalse,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.20.1",
						"vpaEnabled":        true,
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
						"webhookConfig": map[string]interface{}{
							"url":      "https://" + aws.CSISnapshotValidationName + "." + cp.Namespace + "/volumesnapshot",
							"caBundle": "",
						},
						"pspDisabled": false,
					}),
				}))
			})
		})

		Context("shoot control plane chart values (k8s >= 1.20) and custom route controller enabled", func() {
			It("should return correct shoot control plane chart when ca is secret found", func() {
				setCustomRouteControllerEnabled(cp)
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSCustomRouteControllerName:  enabledTrue,
					aws.AWSLoadBalancerControllerName: enabledFalse,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.20.1",
						"vpaEnabled":        true,
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
						"webhookConfig": map[string]interface{}{
							"url":      "https://" + aws.CSISnapshotValidationName + "." + cp.Namespace + "/volumesnapshot",
							"caBundle": "",
						},
						"pspDisabled": false,
					}),
				}))
			})
		})

		Context("shoot control plane chart values (k8s >= 1.20) and ALB enabled", func() {
			It("should return correct shoot control plane chart when ca is secret found", func() {
				setLoadBalancerControllerEnabled(cp, nil)
				albChartValues := map[string]interface{}{
					"region":                "europe",
					"enabled":               true,
					"clusterName":           "test",
					"webhookCertSecretName": awsLoadBalancerControllerWebhook,
					"webhookTLS": map[string]interface{}{
						"caCert": "",
					},
					"webhookURL":   fmt.Sprintf("https://%s.%s:443", awsLoadBalancerControllerWebhook, namespace),
					"replicaCount": 1,
					"defaultTags": map[string]interface{}{
						"KubernetesCluster":          "test",
						"kubernetes.io/cluster/test": "owned",
					},
				}
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSCustomRouteControllerName:  enabledFalse,
					aws.AWSLoadBalancerControllerName: albChartValues,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.20.1",
						"vpaEnabled":        true,
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
						"webhookConfig": map[string]interface{}{
							"url":      "https://" + aws.CSISnapshotValidationName + "." + cp.Namespace + "/volumesnapshot",
							"caBundle": "",
						},
						"pspDisabled": false,
					}),
				}))
			})
		})

		Context("podSecurityPolicy", func() {
			It("should return correct shoot control plane chart when PodSecurityPolicy admission plugin is not disabled in the shoot", func() {
				clusterK8sAtLeast120.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name: "PodSecurityPolicy",
						},
					},
				}
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSCustomRouteControllerName:  enabledFalse,
					aws.AWSLoadBalancerControllerName: enabledFalse,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.20.1",
						"vpaEnabled":        true,
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
						"webhookConfig": map[string]interface{}{
							"url":      "https://" + aws.CSISnapshotValidationName + "." + cp.Namespace + "/volumesnapshot",
							"caBundle": "",
						},
						"pspDisabled": false,
					}),
				}))
			})
			It("should return correct shoot control plane chart when PodSecurityPolicy admission plugin is disabled in the shoot", func() {
				clusterK8sAtLeast120.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     "PodSecurityPolicy",
							Disabled: pointer.Bool(true),
						},
					},
				}
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSCustomRouteControllerName:  enabledFalse,
					aws.AWSLoadBalancerControllerName: enabledFalse,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.20.1",
						"vpaEnabled":        true,
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
						"webhookConfig": map[string]interface{}{
							"url":      "https://" + aws.CSISnapshotValidationName + "." + cp.Namespace + "/volumesnapshot",
							"caBundle": "",
						},
						"pspDisabled": true,
					}),
				}))
			})
		})
	})

	Describe("#GetStorageClassesChartValues()", func() {
		It("should return correct storage class chart values (k8s >= 1.20)", func() {
			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sAtLeast120)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"managedDefaultClass": true,
			}))
		})

		It("should return correct storage class chart values (k8s >= 1.20) and default is set to true", func() {
			cp.Spec.DefaultSpec.ProviderConfig.Raw = encode(&apisawsv1alpha1.ControlPlaneConfig{
				Storage: &apisawsv1alpha1.Storage{
					ManagedDefaultClass: pointer.Bool(true),
				},
			})

			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sAtLeast120)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"managedDefaultClass": true,
			}))
		})

		It("should return correct storage class chart values (k8s >= 1.20) and default is set to false", func() {
			cp.Spec.DefaultSpec.ProviderConfig.Raw = encode(&apisawsv1alpha1.ControlPlaneConfig{
				Storage: &apisawsv1alpha1.Storage{
					ManagedDefaultClass: pointer.Bool(false),
				},
			})

			values, err := vp.GetStorageClassesChartValues(ctx, cp, clusterK8sAtLeast120)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"managedDefaultClass": false,
			}))
		})
	})

	Describe("#GetControlPlaneShootCRDsChartValues", func() {
		It("should return correct control plane shoot CRDs chart values (k8s >= 1.20)", func() {
			values, err := vp.GetControlPlaneShootCRDsChartValues(ctx, cp, clusterK8sAtLeast120)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"volumesnapshots":                 map[string]interface{}{"enabled": true},
				aws.AWSLoadBalancerControllerName: map[string]interface{}{"enabled": false},
			}))
		})

		It("should return correct control plane shoot CRDs if ALB is enabled", func() {
			setLoadBalancerControllerEnabled(cp, nil)
			values, err := vp.GetControlPlaneShootCRDsChartValues(ctx, cp, clusterK8sAtLeast120)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"volumesnapshots":                 map[string]interface{}{"enabled": true},
				aws.AWSLoadBalancerControllerName: map[string]interface{}{"enabled": true},
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

			values, err := vp.GetControlPlaneExposureChartValues(ctx, cp, clusterK8sAtLeast120, fakeSecretsManager, checksums)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				"domain":                           "10.10.10.1",
				"replicas":                         1,
			}))
		})
	})
})

func clientGet(result runtime.Object) interface{} {
	return func(ctx context.Context, key client.ObjectKey, obj runtime.Object, _ ...client.GetOption) error {
		switch obj.(type) {
		case *corev1.Service:
			*obj.(*corev1.Service) = *result.(*corev1.Service)
		}
		return nil
	}
}
