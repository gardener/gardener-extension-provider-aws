// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/gardener/gardener/pkg/utils"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	fakesecretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager/fake"
	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

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
		ctrl         *gomock.Controller
		c            *mockclient.MockClient
		mgr          *mockmanager.MockManager
		encoder      runtime.Encoder
		ctx          context.Context
		scheme       *runtime.Scheme
		vp           genericactuator.ValuesProvider
		region       string
		cp           *extensionsv1alpha1.ControlPlane
		cidr         string
		cluster      *extensionscontroller.Cluster
		checksums    map[string]string
		enabledTrue  map[string]interface{}
		enabledFalse map[string]interface{}
		encode       = func(obj runtime.Object) []byte {
			b := &bytes.Buffer{}
			Expect(encoder.Encode(obj, b)).To(Succeed())

			data, err := io.ReadAll(b)
			Expect(err).ToNot(HaveOccurred())

			return data
		}
		setCustomIPAMEnabled = func(cp *extensionsv1alpha1.ControlPlane) {
			cp.Spec.ProviderConfig = &runtime.RawExtension{
				Raw: encode(&apisawsv1alpha1.ControlPlaneConfig{
					CloudControllerManager: &apisawsv1alpha1.CloudControllerManagerConfig{
						FeatureGates: map[string]bool{
							"SomeKubernetesFeature": true,
						},
					},
				}),
			}
		}
		setCustomRouteControllerEnabled = func(cp *extensionsv1alpha1.ControlPlane) {
			cp.Spec.ProviderConfig = &runtime.RawExtension{
				Raw: encode(&apisawsv1alpha1.ControlPlaneConfig{
					CloudControllerManager: &apisawsv1alpha1.CloudControllerManagerConfig{
						FeatureGates: map[string]bool{
							"SomeKubernetesFeature": true,
						},
						UseCustomRouteController: ptr.To(true),
					},
				}),
			}
		}
		setLoadBalancerControllerEnabled = func(cp *extensionsv1alpha1.ControlPlane, ingressClassName *string) {
			cp.Spec.ProviderConfig = &runtime.RawExtension{
				Raw: encode(&apisawsv1alpha1.ControlPlaneConfig{
					CloudControllerManager: &apisawsv1alpha1.CloudControllerManagerConfig{
						FeatureGates: map[string]bool{
							"SomeKubernetesFeature": true,
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
		format.MaxLength = 0
		ctx = context.TODO()
		scheme = runtime.NewScheme()

		Expect(apisaws.AddToScheme(scheme)).To(Succeed())
		Expect(apisawsv1alpha1.AddToScheme(scheme)).To(Succeed())

		codec := serializer.NewCodecFactory(scheme, serializer.EnableStrict)

		info, found := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeJSON)
		Expect(found).To(BeTrue(), "should be able to decode")

		encoder = codec.EncoderForVersion(info.Serializer, apisawsv1alpha1.SchemeGroupVersion)

		region = "eu-west-1"
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
									"SomeKubernetesFeature": true,
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
				SecretRef: corev1.SecretReference{
					Name:      "cloudprovider",
					Namespace: namespace,
				},
			},
		}

		cluster = &extensionscontroller.Cluster{
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
						Version: "1.34.0",
					},
				},
				Status: gardencorev1beta1.ShootStatus{
					Networking: &gardencorev1beta1.NetworkingStatus{
						Nodes: []string{"1.2.3.4/24"},
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
		c = mockclient.NewMockClient(ctrl)
		mgr = mockmanager.NewMockManager(ctrl)
		mgr.EXPECT().GetClient().Return(c)
		mgr.EXPECT().GetScheme().Return(scheme)
		vp = NewValuesProvider(mgr)

		fakeClient = fakeclient.NewClientBuilder().Build()
		fakeSecretsManager = fakesecretsmanager.New(fakeClient, namespace)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#GetConfigChartValues", func() {
		It("should return correct config chart values", func() {
			values, err := vp.GetConfigChartValues(ctx, cp, cluster)
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
		var ipamChartValues map[string]interface{}
		var albChartValues map[string]interface{}

		BeforeEach(func() {
			ipamChartValues = utils.MergeMaps(enabledTrue, map[string]interface{}{
				"podAnnotations": map[string]interface{}{
					"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
				},
				"nodeCIDRMaskSizeIPv6": int32(64),
				"enabled":              true,
				"podNetwork":           "192.168.0.0/16",
				"podLabels": map[string]interface{}{
					"maintenance.gardener.cloud/restart": "true",
				},
				"region":               "eu-west-1",
				"mode":                 "ipv4",
				"primaryIPFamily":      "ipv4",
				"nodeCIDRMaskSizeIPv4": int32(24),
				"replicas":             0,
				"clusterName":          "test",
				"useWorkloadIdentity":  false,
			})
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
					"SomeKubernetesFeature": true,
				},
				"tlsCipherSuites": []string{
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
					"TLS_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
					"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
				},
				"secrets": map[string]interface{}{
					"server": "cloud-controller-manager-server",
				},
				"useWorkloadIdentity": false,
				"region":              "eu-west-1",
			})
			crcChartValues = map[string]interface{}{
				"podLabels": map[string]interface{}{
					"maintenance.gardener.cloud/restart": "true",
				},
				"region":      "eu-west-1",
				"enabled":     true,
				"replicas":    0,
				"clusterName": "test",
				"podNetwork":  "10.250.0.0/19",
				"podAnnotations": map[string]interface{}{
					"checksum/secret-" + v1beta1constants.SecretNameCloudProvider: checksums[v1beta1constants.SecretNameCloudProvider],
				},
				"useWorkloadIdentity": false,
			}
			albChartValues = map[string]interface{}{
				"region":                "eu-west-1",
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
				"useWorkloadIdentity": false,
			}

			By("creating secrets managed outside of this package for whose secretsmanager.Get() will be called")
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca-provider-aws-controlplane", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cloud-controller-manager-server", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: awsLoadBalancerControllerWebhook, Namespace: namespace}})).To(Succeed())
			cloudProviderSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cloudprovider",
					Namespace: namespace,
				},
			}
			c.EXPECT().Get(context.TODO(), client.ObjectKeyFromObject(cloudProviderSecret), cloudProviderSecret).Return(nil)
		})

		It("should return correct control plane chart values", func() {
			values, err := vp.GetControlPlaneChartValues(ctx, cp, cluster, fakeSecretsManager, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"global": map[string]interface{}{
					"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				},
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": cluster.Shoot.Spec.Kubernetes.Version,
				}),
				aws.AWSCustomRouteControllerName:  crcChartValues,
				aws.AWSIPAMControllerName:         ipamChartValues,
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
					"useWorkloadIdentity": false,
				}),
			}))
		})

		It("should return correct control plane chart values and custom route controller enabled", func() {
			setCustomRouteControllerEnabled(cp)
			crcChartValues["replicas"] = 1 // chart is always deployed, but with 0 replicas when disabled

			values, err := vp.GetControlPlaneChartValues(ctx, cp, cluster, fakeSecretsManager, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"global": map[string]interface{}{
					"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				},
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": cluster.Shoot.Spec.Kubernetes.Version,
				}),
				aws.AWSCustomRouteControllerName:  crcChartValues,
				aws.AWSIPAMControllerName:         ipamChartValues,
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
					"useWorkloadIdentity": false,
				}),
			}))
		})

		It("should return correct control plane chart values and ALB enabled", func() {
			setLoadBalancerControllerEnabled(cp, nil)
			albChartValues["replicaCount"] = 1 // chart is always deployed, but with 0 replicas when disabled
			values, err := vp.GetControlPlaneChartValues(ctx, cp, cluster, fakeSecretsManager, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"global": map[string]interface{}{
					"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				},
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": cluster.Shoot.Spec.Kubernetes.Version,
				}),
				aws.AWSCustomRouteControllerName:  crcChartValues,
				aws.AWSIPAMControllerName:         ipamChartValues,
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
					"useWorkloadIdentity": false,
				}),
			}))
		})

		It("should return correct control plane chart values and ALB enabled with ingress class name", func() {
			setLoadBalancerControllerEnabled(cp, ptr.To("my-alb"))
			albChartValues["replicaCount"] = 1 // chart is always deployed, but with 0 replicas when disabled
			albChartValues["ingressClass"] = "my-alb"
			values, err := vp.GetControlPlaneChartValues(ctx, cp, cluster, fakeSecretsManager, checksums, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"global": map[string]interface{}{
					"genericTokenKubeconfigSecretName": genericTokenKubeconfigSecretName,
				},
				aws.CloudControllerManagerName: utils.MergeMaps(ccmChartValues, map[string]interface{}{
					"kubernetesVersion": cluster.Shoot.Spec.Kubernetes.Version,
				}),
				aws.AWSCustomRouteControllerName:  crcChartValues,
				aws.AWSIPAMControllerName:         ipamChartValues,
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
					"useWorkloadIdentity": false,
				}),
			}))
		})

		DescribeTable("topologyAwareRoutingEnabled value",
			func(seedSettings *gardencorev1beta1.SeedSettings, shootControlPlane *gardencorev1beta1.ControlPlane) {
				cluster.Seed = &gardencorev1beta1.Seed{
					Spec: gardencorev1beta1.SeedSpec{
						Settings: seedSettings,
					},
				}
				cluster.Shoot.Spec.ControlPlane = shootControlPlane

				values, err := vp.GetControlPlaneChartValues(ctx, cp, cluster, fakeSecretsManager, checksums, false)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(HaveKey(aws.CSIControllerName))
			},

			Entry("seed setting is nil, shoot control plane is not HA",
				nil,
				&gardencorev1beta1.ControlPlane{HighAvailability: nil},
			),
			Entry("seed setting is disabled, shoot control plane is not HA",
				&gardencorev1beta1.SeedSettings{TopologyAwareRouting: &gardencorev1beta1.SeedSettingTopologyAwareRouting{Enabled: false}},
				&gardencorev1beta1.ControlPlane{HighAvailability: nil},
			),
			Entry("seed setting is enabled, shoot control plane is not HA",
				&gardencorev1beta1.SeedSettings{TopologyAwareRouting: &gardencorev1beta1.SeedSettingTopologyAwareRouting{Enabled: true}},
				&gardencorev1beta1.ControlPlane{HighAvailability: nil},
			),
			Entry("seed setting is nil, shoot control plane is HA with failure tolerance type 'zone'",
				nil,
				&gardencorev1beta1.ControlPlane{HighAvailability: &gardencorev1beta1.HighAvailability{FailureTolerance: gardencorev1beta1.FailureTolerance{Type: gardencorev1beta1.FailureToleranceTypeZone}}},
			),
			Entry("seed setting is disabled, shoot control plane is HA with failure tolerance type 'zone'",
				&gardencorev1beta1.SeedSettings{TopologyAwareRouting: &gardencorev1beta1.SeedSettingTopologyAwareRouting{Enabled: false}},
				&gardencorev1beta1.ControlPlane{HighAvailability: &gardencorev1beta1.HighAvailability{FailureTolerance: gardencorev1beta1.FailureTolerance{Type: gardencorev1beta1.FailureToleranceTypeZone}}},
			),
			Entry("seed setting is enabled, shoot control plane is HA with failure tolerance type 'zone'",
				&gardencorev1beta1.SeedSettings{TopologyAwareRouting: &gardencorev1beta1.SeedSettingTopologyAwareRouting{Enabled: true}},
				&gardencorev1beta1.ControlPlane{HighAvailability: &gardencorev1beta1.HighAvailability{FailureTolerance: gardencorev1beta1.FailureTolerance{Type: gardencorev1beta1.FailureToleranceTypeZone}}},
			),
		)
	})

	Describe("#GetControlPlaneShootChartValues", func() {
		BeforeEach(func() {
			By("creating secrets managed outside of this package for whose secretsmanager.Get() will be called")
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca-provider-aws-controlplane", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cloud-controller-manager-server", Namespace: namespace}})).To(Succeed())
			Expect(fakeClient.Create(context.TODO(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: awsLoadBalancerControllerWebhook, Namespace: namespace}})).To(Succeed())
			cloudProviderSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cloudprovider",
					Namespace: namespace,
				},
			}
			c.EXPECT().Get(context.TODO(), client.ObjectKeyFromObject(cloudProviderSecret), cloudProviderSecret).Return(nil)
		})

		Context("shoot control plane chart values", func() {
			It("should return correct shoot control plane chart when ca is secret found", func() {
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, cluster, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSIPAMControllerName:         enabledFalse,
					aws.AWSCustomRouteControllerName:  enabledFalse,
					aws.AWSLoadBalancerControllerName: enabledFalse,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.34.0",
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
					}),
					aws.CSIEfsNodeName:                 enabledFalse,
					"calico-mutating-admission-policy": enabledFalse,
				}))
			})
		})

		Context("shoot control plane chart values and ipam controller enabled", func() {
			It("should return correct shoot control plane chart when ca is secret found", func() {
				setCustomIPAMEnabled(cp)
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, cluster, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSIPAMControllerName:         enabledFalse,
					aws.AWSCustomRouteControllerName:  enabledFalse,
					aws.AWSLoadBalancerControllerName: enabledFalse,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.34.0",
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
					}),
					aws.CSIEfsNodeName:                 enabledFalse,
					"calico-mutating-admission-policy": enabledFalse,
				}))
			})
		})

		Context("shoot control plane chart values and custom route controller enabled", func() {
			It("should return correct shoot control plane chart when ca is secret found", func() {
				setCustomRouteControllerEnabled(cp)
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, cluster, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSIPAMControllerName:         enabledFalse,
					aws.AWSCustomRouteControllerName:  enabledTrue,
					aws.AWSLoadBalancerControllerName: enabledFalse,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.34.0",
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
					}),
					aws.CSIEfsNodeName:                 enabledFalse,
					"calico-mutating-admission-policy": enabledFalse,
				}))
			})
		})

		Context("shoot control plane chart values and ALB enabled", func() {
			It("should return correct shoot control plane chart when ca is secret found", func() {
				setLoadBalancerControllerEnabled(cp, nil)
				albChartValues := map[string]interface{}{
					"region":                "eu-west-1",
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
					"useWorkloadIdentity": false,
				}
				values, err := vp.GetControlPlaneShootChartValues(ctx, cp, cluster, fakeSecretsManager, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(values).To(Equal(map[string]interface{}{
					aws.CloudControllerManagerName:    enabledTrue,
					aws.AWSIPAMControllerName:         enabledFalse,
					aws.AWSCustomRouteControllerName:  enabledFalse,
					aws.AWSLoadBalancerControllerName: albChartValues,
					aws.CSINodeName: utils.MergeMaps(enabledTrue, map[string]interface{}{
						"kubernetesVersion": "1.34.0",
						"driver": map[string]interface{}{
							"volumeAttachLimit": "42",
						},
					}),
					aws.CSIEfsNodeName:                 enabledFalse,
					"calico-mutating-admission-policy": enabledFalse,
				}))
			})
		})
	})

	Describe("#GetStorageClassesChartValues()", func() {
		It("should return correct storage class chart values", func() {
			values, err := vp.GetStorageClassesChartValues(ctx, cp, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"managedDefaultClass": true,
			}))
		})

		It("should return correct storage class chart values and default is set to true", func() {
			cp.Spec.ProviderConfig.Raw = encode(&apisawsv1alpha1.ControlPlaneConfig{
				Storage: &apisawsv1alpha1.Storage{
					ManagedDefaultClass: ptr.To(true),
				},
			})

			values, err := vp.GetStorageClassesChartValues(ctx, cp, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"managedDefaultClass": true,
			}))
		})

		It("should return correct storage class chart values and default is set to false", func() {
			cp.Spec.ProviderConfig.Raw = encode(&apisawsv1alpha1.ControlPlaneConfig{
				Storage: &apisawsv1alpha1.Storage{
					ManagedDefaultClass: ptr.To(false),
				},
			})

			values, err := vp.GetStorageClassesChartValues(ctx, cp, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"managedDefaultClass": false,
			}))
		})
	})

	Describe("#GetControlPlaneShootCRDsChartValues", func() {
		It("should return correct control plane shoot CRDs chart values", func() {
			values, err := vp.GetControlPlaneShootCRDsChartValues(ctx, cp, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"volumesnapshots":                 map[string]interface{}{"enabled": true},
				aws.AWSLoadBalancerControllerName: map[string]interface{}{"enabled": false},
			}))
		})

		It("should return correct control plane shoot CRDs if ALB is enabled", func() {
			setLoadBalancerControllerEnabled(cp, nil)
			values, err := vp.GetControlPlaneShootCRDsChartValues(ctx, cp, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(Equal(map[string]interface{}{
				"volumesnapshots":                 map[string]interface{}{"enabled": true},
				aws.AWSLoadBalancerControllerName: map[string]interface{}{"enabled": true},
			}))
		})
	})

	Describe("#getControlPlaneShootChartCSIEfsValues", func() {
		It("sets imdsEndpointMode to ipv4 when not IPv6 single-stack", func() {
			infraConfig := &apisaws.InfrastructureConfig{
				ElasticFileSystem: &apisaws.ElasticFileSystemConfig{Enabled: true},
			}
			infraStatus := &apisaws.InfrastructureStatus{
				ElasticFileSystem: apisaws.ElasticFileSystemStatus{ID: "fs-1234"},
			}

			values := getControlPlaneShootChartCSIEfsValues(infraConfig, infraStatus, false)

			Expect(values).To(HaveKeyWithValue("enabled", true))
			Expect(values).To(HaveKey("controller"))
			controller := values["controller"].(map[string]interface{})
			Expect(controller).To(HaveKeyWithValue("imdsEndpointMode", "ipv4"))
		})

		It("sets imdsEndpointMode to ipv6 when IPv6 single-stack", func() {
			infraConfig := &apisaws.InfrastructureConfig{
				ElasticFileSystem: &apisaws.ElasticFileSystemConfig{Enabled: true},
			}
			infraStatus := &apisaws.InfrastructureStatus{
				ElasticFileSystem: apisaws.ElasticFileSystemStatus{ID: "fs-5678"},
			}

			values := getControlPlaneShootChartCSIEfsValues(infraConfig, infraStatus, true)

			Expect(values).To(HaveKeyWithValue("enabled", true))
			Expect(values).To(HaveKey("controller"))
			controller := values["controller"].(map[string]interface{})
			Expect(controller).To(HaveKeyWithValue("imdsEndpointMode", "ipv6"))
		})

		It("is disabled when EFS is not enabled", func() {
			infraConfig := &apisaws.InfrastructureConfig{
				ElasticFileSystem: &apisaws.ElasticFileSystemConfig{Enabled: false},
			}
			infraStatus := &apisaws.InfrastructureStatus{}

			values := getControlPlaneShootChartCSIEfsValues(infraConfig, infraStatus, false)
			Expect(values).To(HaveKeyWithValue("enabled", false))
			Expect(values).NotTo(HaveKey("controller"))
		})
	})

	Describe("#isMutatingAdmissionPolicyEnabled", func() {
		var testCluster *extensionscontroller.Cluster

		BeforeEach(func() {
			calico := "calico"
			testCluster = &extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						Networking: &gardencorev1beta1.Networking{
							Type: &calico,
						},
						Kubernetes: gardencorev1beta1.Kubernetes{
							Version: "1.33.0",
						},
					},
				},
			}
		})

		It("should return false if KubeAPIServer is nil", func() {
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeFalse())
		})

		It("should return false if feature gates are nil", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeFalse())
		})

		It("should return false if MutatingAdmissionPolicy feature gate is not set", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"SomeOtherGate": true},
				},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeFalse())
		})

		It("should return false if MutatingAdmissionPolicy feature gate is disabled", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": false},
				},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeFalse())
		})

		It("should return false if RuntimeConfig is nil", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": true},
				},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeFalse())
		})

		It("should return false if neither v1alpha1 nor v1beta1 is enabled in RuntimeConfig", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": true},
				},
				RuntimeConfig: map[string]bool{"some.other/v1": true},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeFalse())
		})

		It("should return true if feature gate is enabled and v1alpha1 is in RuntimeConfig", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": true},
				},
				RuntimeConfig: map[string]bool{"admissionregistration.k8s.io/v1alpha1": true},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeTrue())
		})

		It("should return true if feature gate is enabled and v1beta1 is in RuntimeConfig", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": true},
				},
				RuntimeConfig: map[string]bool{"admissionregistration.k8s.io/v1beta1": true},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeTrue())
		})

		It("should return true if feature gate is enabled and both v1alpha1 and v1beta1 are in RuntimeConfig", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": true},
				},
				RuntimeConfig: map[string]bool{
					"admissionregistration.k8s.io/v1alpha1": true,
					"admissionregistration.k8s.io/v1beta1":  true,
				},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeTrue())
		})

		It("should return true for K8s >= 1.34 without any feature gate or RuntimeConfig (beta)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.34.0"
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeTrue())
		})

		It("should return true for K8s >= 1.34 even without KubeAPIServer config (beta)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.35.0"
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeTrue())
		})

		It("should return false for K8s >= 1.34 and < 1.36 if feature gate is explicitly disabled (beta)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.34.0"
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": false},
				},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeFalse())
		})

		It("should return false for K8s 1.35 if feature gate is explicitly disabled (beta)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.35.0"
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": false},
				},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeFalse())
		})

		It("should return true for K8s >= 1.36 even if feature gate is explicitly disabled (GA, locked on)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.36.0"
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				KubernetesConfig: gardencorev1beta1.KubernetesConfig{
					FeatureGates: map[string]bool{"MutatingAdmissionPolicy": false},
				},
			}
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeTrue())
		})

		It("should return true for K8s >= 1.36 without any feature gate or RuntimeConfig (GA)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.36.0"
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeTrue())
		})

		It("should return true for K8s >= 1.36 even without KubeAPIServer config (GA)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.37.1"
			Expect(isMutatingAdmissionPolicyEnabled(testCluster)).To(BeTrue())
		})
	})

	Describe("#mutatingAdmissionPolicyAPIVersion", func() {
		var testCluster *extensionscontroller.Cluster

		BeforeEach(func() {
			testCluster = &extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						Kubernetes: gardencorev1beta1.Kubernetes{
							Version: "1.33.0",
						},
					},
				},
			}
		})

		It("should return v1alpha1 if no RuntimeConfig is set (< 1.34)", func() {
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1alpha1"))
		})

		It("should return v1alpha1 if only v1alpha1 is in RuntimeConfig (< 1.34)", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				RuntimeConfig: map[string]bool{"admissionregistration.k8s.io/v1alpha1": true},
			}
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1alpha1"))
		})

		It("should return v1beta1 if v1beta1 is in RuntimeConfig (< 1.34)", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				RuntimeConfig: map[string]bool{"admissionregistration.k8s.io/v1beta1": true},
			}
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1beta1"))
		})

		It("should return v1beta1 if both v1alpha1 and v1beta1 are in RuntimeConfig (< 1.34)", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				RuntimeConfig: map[string]bool{
					"admissionregistration.k8s.io/v1alpha1": true,
					"admissionregistration.k8s.io/v1beta1":  true,
				},
			}
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1beta1"))
		})

		It("should return v1alpha1 if v1beta1 is explicitly disabled in RuntimeConfig (< 1.34)", func() {
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				RuntimeConfig: map[string]bool{
					"admissionregistration.k8s.io/v1alpha1": true,
					"admissionregistration.k8s.io/v1beta1":  false,
				},
			}
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1alpha1"))
		})

		It("should return v1beta1 for K8s >= 1.34 (beta)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.34.0"
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1beta1"))
		})

		It("should return v1beta1 for K8s 1.35 (beta)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.35.0"
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1beta1"))
		})

		It("should return v1 for K8s >= 1.36 (GA)", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.36.0"
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1"))
		})

		It("should return v1 for K8s 1.36 even if v1beta1 is in RuntimeConfig", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.36.2"
			testCluster.Shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
				RuntimeConfig: map[string]bool{"admissionregistration.k8s.io/v1beta1": true},
			}
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1"))
		})

		It("should return v1 for K8s versions higher than 1.36", func() {
			testCluster.Shoot.Spec.Kubernetes.Version = "1.38.0"
			Expect(mutatingAdmissionPolicyAPIVersion(testCluster)).To(Equal("v1"))
		})
	})
})
