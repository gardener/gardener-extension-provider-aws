// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
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

var _ = Describe("BackupBucket Validator", func() {
	Describe("#Validate", func() {
		const name = "my-provider-account"

		var (
			backupBucketValidator extensionswebhook.Validator

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

			backupBucketValidator = validator.NewBackupBucketValidator(mgr)

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

		It("should return err when obj is not a gardencore.BackupBucket", func() {
			Expect(backupBucketValidator.Validate(ctx, &corev1.Secret{}, nil)).To(MatchError("wrong object type *v1.Secret for new object"))
		})

		It("should return err when oldObj is not a gardencore.BackupBucket", func() {
			Expect(backupBucketValidator.Validate(ctx, &gardencore.BackupBucket{}, &corev1.Secret{})).To(MatchError("wrong object type *v1.Secret for old object"))
		})

		Context("Create", func() {
			It("should return error when BackupBucket is created with invalid spec", func() {
				backupBucket := &gardencore.BackupBucket{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.BackupBucketSpec{
						CredentialsRef: credentialsRef,
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "invalid"}`),
						},
					},
				}

				err := backupBucketValidator.Validate(ctx, backupBucket, nil)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(`failed to decode new provider config: no kind "invalid" is registered for version "aws.provider.extensions.gardener.cloud/v1alpha1"`))
			})

			It("should succeed when BackupBucket is created with valid spec", func() {
				backupBucket := &gardencore.BackupBucket{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.BackupBucketSpec{
						CredentialsRef: credentialsRef,
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				}

				Expect(backupBucketValidator.Validate(ctx, backupBucket, nil)).To(Succeed())
			})
		})

		Context("Update", func() {
			It("should return error when BackupBucket is updated with invalid spec and old had unset providerConfig", func() {
				backupBucket := &gardencore.BackupBucket{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.BackupBucketSpec{
						CredentialsRef: credentialsRef,
						ProviderConfig: nil,
					},
				}

				newBackupBucket := backupBucket.DeepCopy()
				newBackupBucket.Spec.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "invalid"}`),
				}

				err := backupBucketValidator.Validate(ctx, newBackupBucket, backupBucket)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(`failed to decode new provider config: no kind "invalid" is registered for version "aws.provider.extensions.gardener.cloud/v1alpha1"`))
			})

			It("should succeed when BackupBucket is updated with valid spec and old had unset providerConfig", func() {
				backupBucket := &gardencore.BackupBucket{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.BackupBucketSpec{
						CredentialsRef: credentialsRef,
						ProviderConfig: nil,
					},
				}

				newBackupBucket := backupBucket.DeepCopy()
				newBackupBucket.Spec.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
				}

				Expect(backupBucketValidator.Validate(ctx, newBackupBucket, backupBucket)).To(Succeed())
			})

			It("should return error when BackupBucket is updated with invalid spec and old had providerConfig set", func() {
				backupBucket := &gardencore.BackupBucket{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.BackupBucketSpec{
						CredentialsRef: credentialsRef,
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				}

				newBackupBucket := backupBucket.DeepCopy()
				newBackupBucket.Spec.CredentialsRef = nil

				err := backupBucketValidator.Validate(ctx, newBackupBucket, backupBucket)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(`spec.credentialsRef: Required value: must be set`))
			})

			It("should succeed when BackupBucket is updated with valid spec and old had providerConfig set", func() {
				backupBucket := &gardencore.BackupBucket{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: gardencore.BackupBucketSpec{
						CredentialsRef: nil,
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				}

				newBackupBucket := backupBucket.DeepCopy()
				newBackupBucket.Spec.CredentialsRef = credentialsRef

				Expect(backupBucketValidator.Validate(ctx, newBackupBucket, backupBucket)).To(Succeed())

			})
		})
	})
})
