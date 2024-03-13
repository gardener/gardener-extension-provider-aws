// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator_test

import (
	"context"
	"encoding/json"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/pkg/mock/controller-runtime/manager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/validator"
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var _ = Describe("Shoot validator", func() {
	Describe("#Validate", func() {
		const namespace = "garden-dev"

		var (
			shootValidator extensionswebhook.Validator

			ctrl         *gomock.Controller
			mgr          *mockmanager.MockManager
			c            *mockclient.MockClient
			cloudProfile *gardencorev1beta1.CloudProfile
			shoot        *core.Shoot

			ctx             = context.TODO()
			cloudProfileKey = client.ObjectKey{Name: "aws"}
			gp2type         = string(apisaws.VolumeTypeGP2)
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())

			scheme := runtime.NewScheme()
			Expect(apisaws.AddToScheme(scheme)).To(Succeed())
			Expect(apisawsv1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(gardencorev1beta1.AddToScheme(scheme)).To(Succeed())

			c = mockclient.NewMockClient(ctrl)
			mgr = mockmanager.NewMockManager(ctrl)

			mgr.EXPECT().GetScheme().Return(scheme).Times(3)
			mgr.EXPECT().GetClient().Return(c)

			shootValidator = validator.NewShootValidator(mgr)

			cloudProfile = &gardencorev1beta1.CloudProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "aws",
				},
				Spec: gardencorev1beta1.CloudProfileSpec{
					Regions: []gardencorev1beta1.Region{
						{
							Name: "us-west",
							Zones: []gardencorev1beta1.AvailabilityZone{
								{
									Name: "zone1",
								},
								{
									Name: "zone2",
								},
							},
						},
					},
				},
			}
			shoot = &core.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Spec: core.ShootSpec{
					CloudProfileName: cloudProfile.Name,
					Provider: core.Provider{
						InfrastructureConfig: &runtime.RawExtension{
							Raw: encode(&apisawsv1alpha1.InfrastructureConfig{
								TypeMeta: metav1.TypeMeta{
									APIVersion: apisawsv1alpha1.SchemeGroupVersion.String(),
									Kind:       "InfrastructureConfig",
								},
								Networks: apisawsv1alpha1.Networks{
									VPC: apisawsv1alpha1.VPC{
										CIDR: pointer.String("10.250.0.0/16"),
									},
									Zones: []apisawsv1alpha1.Zone{
										{
											Name:     "zone1",
											Internal: "10.250.112.0/26",
											Public:   "10.250.96.0/26",
											Workers:  "10.250.0.0/26",
										},
									},
								},
							}),
						},
						Workers: []core.Worker{
							{
								Name: "worker-1",
								Volume: &core.Volume{
									VolumeSize: "50Gi",
									Type:       pointer.String(gp2type),
								},
								Zones: []string{"zone1"},
							},
						},
					},
					Region: "us-west",
					Networking: &core.Networking{
						Nodes: pointer.String("10.250.0.0/16"),
					},
				},
			}
		})

		Context("Shoot creation (old is nil)", func() {
			It("should return err when new is not a Shoot", func() {
				err := shootValidator.Validate(ctx, &corev1.Pod{}, nil)
				Expect(err).To(MatchError("wrong object type *v1.Pod"))
			})

			It("should return err when infrastructureConfig is nil", func() {
				shoot.Spec.Provider.InfrastructureConfig = nil

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).To(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.provider.infrastructureConfig"),
				})))
			})

			It("should return err when infrastructureConfig fails to be decoded", func() {
				shoot.Spec.Provider.InfrastructureConfig = &runtime.RawExtension{Raw: []byte("foo")}

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).To(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("spec.provider.infrastructureConfig"),
				})))
			})

			It("should return err when infrastructureConfig is invalid against CloudProfile", func() {
				c.EXPECT().Get(ctx, cloudProfileKey, &gardencorev1beta1.CloudProfile{}).SetArg(2, *cloudProfile)

				shoot.Spec.Provider.InfrastructureConfig = &runtime.RawExtension{
					Raw: encode(&apisawsv1alpha1.InfrastructureConfig{
						TypeMeta: metav1.TypeMeta{
							APIVersion: apisawsv1alpha1.SchemeGroupVersion.String(),
							Kind:       "InfrastructureConfig",
						},
						Networks: apisawsv1alpha1.Networks{
							Zones: []apisawsv1alpha1.Zone{
								{
									Name: "not-available",
								},
							},
						},
					}),
				}

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeNotSupported),
					"Field": Equal("spec.provider.infrastructureConfig.network.zones[0].name"),
				}))))
			})

			It("should return err when networking is invalid", func() {
				c.EXPECT().Get(ctx, cloudProfileKey, &gardencorev1beta1.CloudProfile{}).SetArg(2, *cloudProfile)

				shoot.Spec.Networking.Nodes = nil

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.networking.nodes"),
				}))))
			})

			It("should return err when infrastructureConfig is invalid", func() {
				c.EXPECT().Get(ctx, cloudProfileKey, &gardencorev1beta1.CloudProfile{}).SetArg(2, *cloudProfile)

				shoot.Spec.Provider.InfrastructureConfig = &runtime.RawExtension{
					Raw: encode(&apisawsv1alpha1.InfrastructureConfig{
						TypeMeta: metav1.TypeMeta{
							APIVersion: apisawsv1alpha1.SchemeGroupVersion.String(),
							Kind:       "InfrastructureConfig",
						},
						Networks: apisawsv1alpha1.Networks{},
					}),
				}

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("networks.zones"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.vpc"),
				}))))
			})

			It("should return err when controlPlaneConfig fails to be decoded", func() {
				c.EXPECT().Get(ctx, cloudProfileKey, &gardencorev1beta1.CloudProfile{}).SetArg(2, *cloudProfile)

				shoot.Spec.Provider.ControlPlaneConfig = &runtime.RawExtension{Raw: []byte("foo")}

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).To(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("spec.provider.controlPlaneConfig"),
				})))
			})

			It("should return err when worker's providerConfig fails to be decoded", func() {
				c.EXPECT().Get(ctx, cloudProfileKey, &gardencorev1beta1.CloudProfile{}).SetArg(2, *cloudProfile)

				shoot.Spec.Provider.Workers = []core.Worker{
					{
						Name:           "worker-1",
						ProviderConfig: &runtime.RawExtension{Raw: []byte("foo")},
					},
				}

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).To(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("spec.provider.workers[0].providerConfig"),
				})))
			})

			It("should return err when worker is invalid", func() {
				c.EXPECT().Get(ctx, cloudProfileKey, &gardencorev1beta1.CloudProfile{}).SetArg(2, *cloudProfile)

				shoot.Spec.Provider.Workers = []core.Worker{
					{
						Name:   "worker-1",
						Volume: nil,
						Zones:  nil,
					},
				}

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.provider.workers[0].volume"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.provider.workers[0].zones"),
				}))))
			})

			It("should succeed for valid Shoot", func() {
				c.EXPECT().Get(ctx, cloudProfileKey, &gardencorev1beta1.CloudProfile{}).SetArg(2, *cloudProfile)

				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("Workerless Shoot", func() {
			BeforeEach(func() {
				shoot.Spec.Provider.Workers = nil
			})

			It("should not validate", func() {
				err := shootValidator.Validate(ctx, shoot, nil)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}
