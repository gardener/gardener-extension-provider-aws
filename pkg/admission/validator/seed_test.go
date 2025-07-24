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
		const (
			namespace = "garden-dev"
			name      = "my-provider-account"
		)

		var (
			seedValidator extensionswebhook.Validator

			ctrl *gomock.Controller
			mgr  *mockmanager.MockManager

			ctx = context.TODO()
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

		It("should succeed when seed is created with empty providerConfig", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: &gardencore.Backup{},
				},
			}

			Expect(seedValidator.Validate(ctx, seed, nil)).To(Succeed())
		})

		It("should succeed when seed is created with empty backup", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: nil,
				},
			}

			Expect(seedValidator.Validate(ctx, seed, nil)).To(Succeed())
		})

		It("should return error when seed is created with invalid providerConfig and it fails to decode", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: &gardencore.Backup{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "invalid"}`),
						},
					},
				},
			}

			err := seedValidator.Validate(ctx, seed, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`failed to decode new provider config: no kind "invalid" is registered for version "aws.provider.extensions.gardener.cloud/v1alpha1"`))
		})

		It("should return error when seed is created with invalid providerConfig and non-supported fields", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: &gardencore.Backup{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "invalid", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				},
			}

			err := seedValidator.Validate(ctx, seed, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`spec.backup.providerConfig.immutability.mode: Invalid value: "invalid": should be either compliance mode or governance mode`))
		})

		It("should succeed when seed had empty providerConfig but is now updated with valid provider config", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: &gardencore.Backup{},
				},
			}

			newSeed := seed.DeepCopy()
			newSeed.Spec.Backup.ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "compliance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
			}

			Expect(seedValidator.Validate(ctx, newSeed, seed)).To(Succeed())

			seed.Spec.Backup = nil

			Expect(seedValidator.Validate(ctx, newSeed, seed)).To(Succeed())
		})

		It("should return error when seed is updated with invalid providerConfig and it fails to decode", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: &gardencore.Backup{
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

			err := seedValidator.Validate(ctx, newseed, seed)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`failed to decode new provider config: no kind "invalid" is registered for version "aws.provider.extensions.gardener.cloud/v1alpha1"`))
		})

		It("should return error when seed is updated with immutable providerConfig fields", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: &gardencore.Backup{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "compliance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				},
			}

			newseed := seed.DeepCopy()
			newseed.Spec.Backup.ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
			}

			err := seedValidator.Validate(ctx, newseed, seed)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`spec.backup.providerConfig.immutability.mode: Forbidden: immutable retention mode can't be change to governance once it is compliance`))
		})

		It("should succeed when Seed is updated with valid providerConfig", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: &gardencore.Backup{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				},
			}

			newSeed := seed.DeepCopy()
			newSeed.Spec.Backup.ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "compliance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
			}

			Expect(seedValidator.Validate(ctx, newSeed, seed)).To(Succeed())
		})

		It("should succeed when old Seed does not have provider config and new Seed is updated with valid providerConfig", func() {
			seed := &gardencore.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: gardencore.SeedSpec{
					Backup: nil,
				},
			}

			newSeed := seed.DeepCopy()
			newSeed.Spec.Backup = &gardencore.Backup{
				ProviderConfig: &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "compliance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
				},
			}

			Expect(seedValidator.Validate(ctx, newSeed, seed)).To(Succeed())
		})
	})
})
