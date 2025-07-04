// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket_test

import (
	"context"
	"testing"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsapiv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/webhook/backupbucket"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BackupBucket Webhook Suite")
}

var _ = Describe("BackupBucket Validator", func() {
	Describe("#Validate", func() {
		const (
			namespace = "garden-dev"
			name      = "my-provider-account"
		)

		var (
			backupBucketValidator extensionswebhook.Validator

			ctrl *gomock.Controller
			mgr  *mockmanager.MockManager

			ctx = context.TODO()
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())

			mgr = mockmanager.NewMockManager(ctrl)

			scheme := runtime.NewScheme()
			Expect(extensionsv1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(awsapi.AddToScheme(scheme)).To(Succeed())
			Expect(awsapiv1alpha1.AddToScheme(scheme)).To(Succeed())

			mgr.EXPECT().GetScheme().Return(scheme).AnyTimes()

			backupBucketValidator = backupbucket.New(mgr)
		})

		AfterEach(func() {
			ctrl.Finish()
		})

		It("should return err when obj is not a extensionsv1alpha1.BackupBucket", func() {
			Expect(backupBucketValidator.Validate(ctx, &corev1.Secret{}, nil)).To(MatchError("wrong object type *v1.Secret for new object"))
		})

		It("should return err when oldObj is not a extensionsv1alpha1.BackupBucket", func() {
			Expect(backupBucketValidator.Validate(ctx, &extensionsv1alpha1.BackupBucket{}, &corev1.Secret{})).To(MatchError("wrong object type *v1.Secret for old object"))
		})

		It("should return error when BackupBucket is created with invalid providerConfig and it fails to decode", func() {
			backupBucket := &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "invalid"}`),
						},
					},
				},
			}

			err := backupBucketValidator.Validate(ctx, backupBucket, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`failed to decode new provider config: no kind "invalid" is registered for version "aws.provider.extensions.gardener.cloud/v1alpha1"`))
		})

		It("should return error when BackupBucket is created with invalid providerConfig and non-supported fields", func() {
			backupBucket := &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "invalid", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				},
			}

			err := backupBucketValidator.Validate(ctx, backupBucket, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`spec.providerConfig.immutability.mode: Invalid value: "invalid": should be either compliance mode or governance mode`))
		})

		It("should succeed when BackupBucket is created with valid providerConfig", func() {
			backupBucket := &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				},
			}

			Expect(backupBucketValidator.Validate(ctx, backupBucket, nil)).To(Succeed())
		})

		It("should return error when BackupBucket is updated with invalid providerConfig and it fails to decode", func() {
			backupBucket := &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig"}`),
						},
					},
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

		It("should return error when BackupBucket is updated with immutable providerConfig fields", func() {
			backupBucket := &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "compliance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				},
			}

			newBackupBucket := backupBucket.DeepCopy()
			newBackupBucket.Spec.ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
			}

			err := backupBucketValidator.Validate(ctx, newBackupBucket, backupBucket)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`spec.providerConfig.immutability.mode: Forbidden: immutable retention mode can't be change to governance once it is compliance`))
		})

		It("should succeed when BackupBucket is updated with valid providerConfig", func() {
			backupBucket := &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "governance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
						},
					},
				},
			}

			newBackupBucket := backupBucket.DeepCopy()
			newBackupBucket.Spec.ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "compliance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
			}

			Expect(backupBucketValidator.Validate(ctx, newBackupBucket, backupBucket)).To(Succeed())
		})

		It("should succeed when old BackupBucket does not have provider config and new BackupBucket is updated with valid providerConfig", func() {
			backupBucket := &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						ProviderConfig: nil,
					},
				},
			}

			newBackupBucket := backupBucket.DeepCopy()
			newBackupBucket.Spec.ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "BackupBucketConfig", "immutability": {"mode": "compliance", "retentionPeriod": "96h", "retentionType": "bucket"}}`),
			}

			Expect(backupBucketValidator.Validate(ctx, newBackupBucket, backupBucket)).To(Succeed())
		})
	})
})
