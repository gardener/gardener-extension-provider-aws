// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator_test

import (
	"context"
	"fmt"
	"time"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	testutils "github.com/gardener/gardener/pkg/utils/test"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/mutator"
	awsinstall "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

var _ = Describe("Shoot mutator", func() {
	Describe("#Mutate", func() {
		const namespace = "garden-dev"

		var (
			shootMutator extensionswebhook.Mutator
			shoot        *gardencorev1beta1.Shoot
			oldShoot     *gardencorev1beta1.Shoot
			ctx          = context.TODO()
			now          = metav1.Now()
			mgr          *testutils.FakeManager
		)

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(gardencorev1beta1.AddToScheme(scheme)).To(Succeed())
			Expect(awsinstall.AddToScheme(scheme)).To(Succeed())

			mgr = &testutils.FakeManager{Scheme: scheme}
			shootMutator = mutator.NewShootMutator(mgr)

			shoot = &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Spec: gardencorev1beta1.ShootSpec{
					Kubernetes: gardencorev1beta1.Kubernetes{
						Version: "1.34.0",
					},
					SeedName: ptr.To("aws"),
					Provider: gardencorev1beta1.Provider{
						Type: aws.Type,
						Workers: []gardencorev1beta1.Worker{
							{
								Name: "worker",
							},
						},
					},
					Region: "us-west-1",
					Networking: &gardencorev1beta1.Networking{
						Nodes: ptr.To("10.250.0.0/16"),
						Type:  ptr.To("calico"),
					},
				},
			}

			oldShoot = &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Spec: gardencorev1beta1.ShootSpec{
					Kubernetes: gardencorev1beta1.Kubernetes{
						Version: "1.34.0",
					},
					SeedName: ptr.To("aws"),
					Provider: gardencorev1beta1.Provider{
						Type: aws.Type,
						Workers: []gardencorev1beta1.Worker{
							{
								Name: "worker",
							},
						},
					},
					Region: "us-west-1",
					Networking: &gardencorev1beta1.Networking{
						Nodes: ptr.To("10.250.0.0/16"),
						Type:  ptr.To("calico"),
					},
				},
			}
		})

		Context("Workerless Shoot", func() {
			BeforeEach(func() {
				shoot.Spec.Provider.Workers = nil
			})

			It("should return without mutation", func() {
				shootExpected := shoot.DeepCopy()
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot).To(DeepEqual(shootExpected))
			})
		})

		Context("Mutate shoot networking providerconfig for type calico", func() {
			It("should return without mutation when shoot is in scheduled to new seed phase", func() {
				shoot.Status.LastOperation = &gardencorev1beta1.LastOperation{
					Description:    "test",
					LastUpdateTime: metav1.Time{Time: metav1.Now().Add(time.Second * -1000)},
					Progress:       0,
					Type:           gardencorev1beta1.LastOperationTypeReconcile,
					State:          gardencorev1beta1.LastOperationStateProcessing,
				}
				shoot.Status.SeedName = ptr.To("gcp")
				shootExpected := shoot.DeepCopy()
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot).To(DeepEqual(shootExpected))
			})

			It("should return without mutation when shoot is in migration or restore phase", func() {
				shoot.Status.LastOperation = &gardencorev1beta1.LastOperation{
					Description:    "test",
					LastUpdateTime: metav1.Time{Time: metav1.Now().Add(time.Second * -1000)},
					Progress:       0,
					Type:           gardencorev1beta1.LastOperationTypeMigrate,
					State:          gardencorev1beta1.LastOperationStateProcessing,
				}
				shoot.Status.SeedName = ptr.To("aws")
				shootExpected := shoot.DeepCopy()
				err := shootMutator.Mutate(ctx, shoot, shoot)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot).To(DeepEqual(shootExpected))
			})

			It("should return without mutation when shoot is in deletion phase", func() {
				shoot.DeletionTimestamp = &now
				shootExpected := shoot.DeepCopy()
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot).To(DeepEqual(shootExpected))
			})

			It("should return without mutation when shoot specs have not changed", func() {
				shootWithAnnotations := shoot.DeepCopy()
				shootWithAnnotations.Annotations = map[string]string{"foo": "bar"}
				shootExpected := shootWithAnnotations.DeepCopy()

				err := shootMutator.Mutate(ctx, shootWithAnnotations, shoot)
				Expect(err).ToNot(HaveOccurred())
				Expect(shootWithAnnotations).To(DeepEqual(shootExpected))
			})

			It("should disable overlay for a new shoot", func() {
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Networking.ProviderConfig).To(Equal(&runtime.RawExtension{
					Raw: []byte(`{"overlay":{"enabled":false}}`),
				}))
			})

			It("should take overlay field value from old shoot when unspecified in new shoot", func() {
				oldShoot.Spec.Networking.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"overlay":{"enabled":true}}`),
				}
				err := shootMutator.Mutate(ctx, shoot, oldShoot)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Networking.ProviderConfig).To(Equal(&runtime.RawExtension{
					Raw: []byte(`{"overlay":{"enabled":true}}`),
				}))
			})
		})

		Context("Mutate shoot networking providerconfig for type cilium", func() {
			BeforeEach(func() {

				shoot.Spec.Networking.Type = ptr.To("cilium")
				oldShoot.Spec.Networking.Type = ptr.To("cilium")
			})

			It("should return without mutation when shoot is in scheduled to new seed phase", func() {
				shoot.Status.LastOperation = &gardencorev1beta1.LastOperation{
					Description:    "test",
					LastUpdateTime: metav1.Time{Time: metav1.Now().Add(time.Second * -1000)},
					Progress:       0,
					Type:           gardencorev1beta1.LastOperationTypeReconcile,
					State:          gardencorev1beta1.LastOperationStateProcessing,
				}
				shoot.Status.SeedName = ptr.To("gcp")
				shootExpected := shoot.DeepCopy()
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot).To(DeepEqual(shootExpected))
			})

			It("should return without mutation when shoot is in migration or restore phase", func() {
				shoot.Status.LastOperation = &gardencorev1beta1.LastOperation{
					Description:    "test",
					LastUpdateTime: metav1.Time{Time: metav1.Now().Add(time.Second * -1000)},
					Progress:       0,
					Type:           gardencorev1beta1.LastOperationTypeMigrate,
					State:          gardencorev1beta1.LastOperationStateProcessing,
				}
				shoot.Status.SeedName = ptr.To("aws")
				shootExpected := shoot.DeepCopy()
				err := shootMutator.Mutate(ctx, shoot, shoot)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot).To(DeepEqual(shootExpected))
			})

			It("should return without mutation when shoot is in deletion phase", func() {
				shoot.DeletionTimestamp = &now
				shootExpected := shoot.DeepCopy()
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot).To(DeepEqual(shootExpected))
			})

			It("should return without mutation when shoot specs have not changed", func() {
				shootWithAnnotations := shoot.DeepCopy()
				shootWithAnnotations.Annotations = map[string]string{"foo": "bar"}
				shootExpected := shootWithAnnotations.DeepCopy()

				err := shootMutator.Mutate(ctx, shootWithAnnotations, shoot)
				Expect(err).ToNot(HaveOccurred())
				Expect(shootWithAnnotations).To(DeepEqual(shootExpected))
			})

			It("should disable overlay for a new shoot", func() {
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Networking.ProviderConfig).To(Equal(&runtime.RawExtension{
					Raw: []byte(`{"overlay":{"enabled":false}}`),
				}))
			})

			It("should disable overlay for a new shoot non empty network config", func() {
				shoot.Spec.Networking.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"foo":{"enabled":true}}`),
				}
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Networking.ProviderConfig).To(Equal(&runtime.RawExtension{
					Raw: []byte(`{"foo":{"enabled":true},"overlay":{"enabled":false}}`),
				}))
			})

			It("should take overlay field value from old shoot when unspecified in new shoot", func() {
				oldShoot.Spec.Networking.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"overlay":{"enabled":true}}`),
				}
				err := shootMutator.Mutate(ctx, shoot, oldShoot)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Networking.ProviderConfig).To(Equal(&runtime.RawExtension{
					Raw: []byte(`{"overlay":{"enabled":true}}`),
				}))
			})

			It("should not add the overlay field when unspecified in new and old shoot", func() {
				err := shootMutator.Mutate(ctx, shoot, oldShoot)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Networking.ProviderConfig).To(BeNil())
			})
		})

		Context("Mutate AWS load balancer controller based on IP families", func() {
			It("should not enable AWS load balancer controller for IPv4", func() {
				shoot.Spec.Networking.IPFamilies = []gardencorev1beta1.IPFamily{gardencorev1beta1.IPFamilyIPv4}
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Provider.ControlPlaneConfig).To(Equal(&runtime.RawExtension{
					Object: &awsv1alpha1.ControlPlaneConfig{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ControlPlaneConfig",
							APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
						},
						CloudControllerManager: &awsv1alpha1.CloudControllerManagerConfig{
							UseCustomRouteController: ptr.To(true),
						},
					},
				}))
			})

			It("should enable AWS load balancer controller for IPv6", func() {
				shoot.Spec.Networking.IPFamilies = []gardencorev1beta1.IPFamily{gardencorev1beta1.IPFamilyIPv6}
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Provider.ControlPlaneConfig).To(Equal(&runtime.RawExtension{
					Object: &awsv1alpha1.ControlPlaneConfig{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ControlPlaneConfig",
							APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
						},
						CloudControllerManager: &awsv1alpha1.CloudControllerManagerConfig{
							UseCustomRouteController: ptr.To(true),
						},
						LoadBalancerController: &awsv1alpha1.LoadBalancerControllerConfig{
							Enabled: true,
						},
					},
				}))
			})

			It("should enable AWS load balancer controller for dual-stack", func() {
				shoot.Spec.Networking.IPFamilies = []gardencorev1beta1.IPFamily{gardencorev1beta1.IPFamilyIPv4, gardencorev1beta1.IPFamilyIPv6}
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Provider.ControlPlaneConfig).To(Equal(&runtime.RawExtension{
					Object: &awsv1alpha1.ControlPlaneConfig{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ControlPlaneConfig",
							APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
						},
						CloudControllerManager: &awsv1alpha1.CloudControllerManagerConfig{
							UseCustomRouteController: ptr.To(true),
						},
						LoadBalancerController: &awsv1alpha1.LoadBalancerControllerConfig{
							Enabled: true,
						},
					},
				}))
			})
		})

		Context("Mutate shoot NodeLocalDNS default for ForceTCPToUpstreamDNS property", func() {
			BeforeEach(func() {
				shoot.Spec.SystemComponents = &gardencorev1beta1.SystemComponents{
					NodeLocalDNS: &gardencorev1beta1.NodeLocalDNS{
						Enabled: true,
					},
				}
			})

			It("should not touch the ForceTCPToUpstreamDNS property if NodeLocalDNS is disabled", func() {
				shoot.Spec.SystemComponents.NodeLocalDNS.Enabled = false
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.SystemComponents.NodeLocalDNS.ForceTCPToUpstreamDNS).To(BeNil())
			})

			It("should not touch the ForceTCPToUpstreamDNS property if it is already set", func() {
				shoot.Spec.SystemComponents.NodeLocalDNS.ForceTCPToUpstreamDNS = ptr.To(true)
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.SystemComponents.NodeLocalDNS.ForceTCPToUpstreamDNS).ToNot(BeNil())
				Expect(*shoot.Spec.SystemComponents.NodeLocalDNS.ForceTCPToUpstreamDNS).To(BeTrue())
			})

			It("should set the ForceTCPToUpstreamDNS property to false by default", func() {
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.SystemComponents.NodeLocalDNS.ForceTCPToUpstreamDNS).ToNot(BeNil())
				Expect(*shoot.Spec.SystemComponents.NodeLocalDNS.ForceTCPToUpstreamDNS).To(BeFalse())
			})
		})

		Context("Mutate InfrastructureConfig EnableMTUCustomizer default", func() {
			infraConfigWithMTU := func(enabled bool) *runtime.RawExtension {
				return &runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"InfrastructureConfig","networks":{"vpc":{"cidr":"10.250.0.0/16"}},"enableMTUCustomizer":%v}`, enabled)),
				}
			}

			It("should default enableMTUCustomizer to false for a new shoot", func() {
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Provider.InfrastructureConfig).NotTo(BeNil())
				infra, ok := shoot.Spec.Provider.InfrastructureConfig.Object.(*awsv1alpha1.InfrastructureConfig)
				Expect(ok).To(BeTrue())
				Expect(infra.EnableMTUCustomizer).NotTo(BeNil())
				Expect(*infra.EnableMTUCustomizer).To(BeFalse())
			})

			It("should not set enableMTUCustomizer for an existing shoot that never set the field", func() {
				shoot.Spec.Kubernetes.Version = "1.35.0"
				err := shootMutator.Mutate(ctx, shoot, oldShoot)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Provider.InfrastructureConfig).To(BeNil())
			})

			It("should not overwrite an explicitly set enableMTUCustomizer on a new shoot", func() {
				shoot.Spec.Provider.InfrastructureConfig = infraConfigWithMTU(true)
				err := shootMutator.Mutate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(shoot.Spec.Provider.InfrastructureConfig.Raw).NotTo(BeNil())
			})
		})
	})
})
