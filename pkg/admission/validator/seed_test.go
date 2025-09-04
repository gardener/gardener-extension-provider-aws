// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator_test

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencore "github.com/gardener/gardener/pkg/apis/core"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/validator"
	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsapiv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var _ = Describe("Seed Validator", func() {
	Describe("#Validate", func() {
		const name = "my-seed"

		var (
			seedValidator extensionswebhook.Validator

			ctrl *gomock.Controller
			mgr  *mockmanager.MockManager

			ctx            context.Context
			credentialsRef *corev1.ObjectReference
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())

			mgr = mockmanager.NewMockManager(ctrl)

			scheme := runtime.NewScheme()
			Expect(gardencore.AddToScheme(scheme)).To(Succeed())
			Expect(awsapi.AddToScheme(scheme)).To(Succeed())
			Expect(awsapiv1alpha1.AddToScheme(scheme)).To(Succeed())

			mgr.EXPECT().GetScheme().Return(scheme).AnyTimes()

			seedValidator = validator.NewSeedValidator(mgr)

			ctx = context.TODO()
			credentialsRef = &corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       "backup-credentials",
				Namespace:  "garden",
			}
		})

		AfterEach(func() {
			ctrl.Finish()
		})

		It("should return err when obj is not a gardencore.Seed", func() {
			Expect(seedValidator.Validate(ctx, &corev1.Secret{}, nil)).To(MatchError("wrong object type *v1.Secret for new object"))
		})

		It("should return err when oldObj is not a gardencore.Seed", func() {
			Expect(seedValidator.Validate(ctx, &gardencore.Seed{}, &corev1.Secret{})).To(MatchError("wrong object type *v1.Secret for old object"))
		})

		Context("Create", func() {
			It("should succeed to create seed when backup is unset", func() {
				seed := &gardencore.Seed{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.SeedSpec{
						Backup: nil,
					},
				}

				Expect(seedValidator.Validate(ctx, seed, nil)).To(Succeed())
			})

			It("should fail to create seed when backup has nil credentialsRef", func() {
				seed := &gardencore.Seed{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.SeedSpec{
						Backup: &gardencore.Backup{
							CredentialsRef: nil,
						},
					},
				}

				err := seedValidator.Validate(ctx, seed, nil)
				Expect(err).To(HaveOccurred())
			})

			It("should succeed to create seed when backup has providerConfig unset", func() {
				seed := &gardencore.Seed{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.SeedSpec{
						Backup: &gardencore.Backup{
							CredentialsRef: credentialsRef,
						},
					},
				}

				Expect(seedValidator.Validate(ctx, seed, nil)).To(Succeed())
			})

			It("should fail to create seed when backup has invalid providerConfig", func() {
				seed := &gardencore.Seed{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.SeedSpec{
						Backup: &gardencore.Backup{
							CredentialsRef: nil,
							ProviderConfig: &runtime.RawExtension{
								Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "invalid"}`),
							},
						},
					},
				}

				err := seedValidator.Validate(ctx, seed, nil)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("Update", func() {
			It("should succeed when seed had empty backup config but is now updated with valid providerConfig", func() {
				seed := &gardencore.Seed{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.SeedSpec{
						Backup: nil,
					},
				}

				newSeed := seed.DeepCopy()
				newSeed.Spec.Backup = &gardencore.Backup{
					CredentialsRef: credentialsRef,
					ProviderConfig: &runtime.RawExtension{
						Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "compliance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
					},
				}

				Expect(seedValidator.Validate(ctx, newSeed, seed)).To(Succeed())
			})

			It("should fail when seed had empty backup config but is now updated with invalid providerConfig", func() {
				seed := &gardencore.Seed{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.SeedSpec{
						Backup: nil,
					},
				}

				newSeed := seed.DeepCopy()
				newSeed.Spec.Backup = &gardencore.Backup{
					CredentialsRef: credentialsRef,
					ProviderConfig: &runtime.RawExtension{
						Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "invalid"`),
					},
				}

				Expect(seedValidator.Validate(ctx, newSeed, seed)).To(HaveOccurred())
			})

			It("should succeed when seed had set backup config and is now updated with valid providerConfig", func() {
				seed := &gardencore.Seed{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.SeedSpec{
						Backup: &gardencore.Backup{
							CredentialsRef: credentialsRef,
							ProviderConfig: &runtime.RawExtension{
								Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig"}`),
							},
						},
					},
				}

				newseed := seed.DeepCopy()
				newseed.Spec.Backup.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
				}

				Expect(seedValidator.Validate(ctx, newseed, seed)).To(Succeed())
			})

			It("should return error when seed had set backup config and is now updated with invalid providerConfig fields", func() {
				seed := &gardencore.Seed{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.SeedSpec{
						Backup: &gardencore.Backup{
							CredentialsRef: credentialsRef,
							ProviderConfig: &runtime.RawExtension{
								Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig"}`),
							},
						},
					},
				}

				newseed := seed.DeepCopy()
				newseed.Spec.Backup.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "invalid"}`),
				}

				Expect(seedValidator.Validate(ctx, newseed, seed)).To(HaveOccurred())
			})
		})
	})
})
