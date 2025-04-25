// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket_test

import (
	"context"
	"fmt"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gardener/gardener/extensions/pkg/controller/backupbucket"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupbucket"
)

const (
	bucketName      = "test-bucket"
	region          = "eu-west-1"
	accessKeyID     = "accessKeyID"
	secretAccessKey = "secretAccessKey"
	name            = "aws-operator"
	namespace       = "shoot--test--aws"
)

var _ = Describe("Actuator", func() {
	var (
		ctrl             *gomock.Controller
		c                *mockclient.MockClient
		mgr              *mockmanager.MockManager
		sw               *mockclient.MockStatusWriter
		a                backupbucket.Actuator
		awsClientFactory *mockawsclient.MockFactory
		awsClient        *mockawsclient.MockInterface
		ctx              context.Context
		logger           logr.Logger
		secret           *corev1.Secret
		authConfig       awsclient.AuthConfig
		secretRef        = corev1.SecretReference{Name: name, Namespace: namespace}
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		scheme := runtime.NewScheme()

		Expect(extensionsv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(apisawsv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(apisaws.AddToScheme(scheme)).To(Succeed())

		c = mockclient.NewMockClient(ctrl)
		mgr = mockmanager.NewMockManager(ctrl)
		mgr.EXPECT().GetClient().Return(c).AnyTimes()
		c.EXPECT().Scheme().Return(scheme).MaxTimes(1)

		sw = mockclient.NewMockStatusWriter(ctrl)
		awsClientFactory = mockawsclient.NewMockFactory(ctrl)
		awsClient = mockawsclient.NewMockInterface(ctrl)

		c.EXPECT().Status().Return(sw).AnyTimes()
		sw.EXPECT().Patch(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		ctx = context.Background()
		logger = log.Log.WithName("test")

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				aws.AccessKeyID:     []byte(accessKeyID),
				aws.SecretAccessKey: []byte(secretAccessKey),
			},
		}

		authConfig = awsclient.AuthConfig{
			AccessKey: &awsclient.AccessKey{
				ID:     accessKeyID,
				Secret: secretAccessKey,
			},
			Region: region,
		}

		a = NewActuator(mgr, awsClientFactory)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#Reconcile", func() {
		var backupBucket *extensionsv1alpha1.BackupBucket

		BeforeEach(func() {
			backupBucket = &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      bucketName,
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					SecretRef: secretRef,
					Region:    region,
				},
			}

			c.EXPECT().Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
				func(_ context.Context, _ client.ObjectKey, obj *corev1.Secret, _ ...client.GetOption) error {
					*obj = *secret
					return nil
				},
			)
		})

		Context("when creating aws client fails", func() {
			BeforeEach(func() {
				backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"24h","mode":"compliance"}}`),
				}
			})

			It("should return an error if storage client creation fails", func() {
				awsClientFactory.EXPECT().NewClient(authConfig).Return(nil, fmt.Errorf("failed to created aws client"))

				err := a.Reconcile(ctx, logger, backupBucket)
				Expect(err).Should(HaveOccurred())
			})
		})

		Context("when decoder failed to decode backupBucket provider config", func() {
			BeforeEach(func() {
				// wrong "providerConfig" is passed
				backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"24h","mo":"compliance"}}`),
				}
			})

			It("should return error", func() {
				awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)

				err := a.Reconcile(ctx, logger, backupBucket)
				Expect(err).Should(HaveOccurred())
			})
		})

		Context("when bucket does not exist", func() {
			BeforeEach(func() {
				backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"24h","mode":"compliance"}}`),
				}

				awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)

				awsClient.EXPECT().GetBucketVersioningStatus(ctx, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ string) (*s3.GetBucketVersioningOutput, error) {
						return nil, &s3types.NoSuchBucket{}
					},
				)
			})

			It("should create the bucket successfully", func() {
				awsClient.EXPECT().CreateBucket(ctx, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				err := a.Reconcile(ctx, logger, backupBucket)
				Expect(err).ShouldNot(HaveOccurred())
			})

			It("should return error if creation of bucket fails", func() {
				awsClient.EXPECT().CreateBucket(ctx, gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("unable to create bucket"))

				err := a.Reconcile(ctx, logger, backupBucket)
				Expect(err).Should(HaveOccurred())
			})
		})

		Context("when bucket exist and bucket versioning isn't enabled", func() {
			BeforeEach(func() {
				backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"24h","mode":"compliance"}}`),
				}

				awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)
				awsClient.EXPECT().GetBucketVersioningStatus(ctx, gomock.Any()).Return(nil, nil)
			})

			It("should update the bucket", func() {
				awsClient.EXPECT().UpdateBucketConfig(ctx, gomock.Any(), gomock.Any(), false).Return(nil)

				err := a.Reconcile(ctx, logger, backupBucket)
				Expect(err).ShouldNot(HaveOccurred())
			})

			It("should return error if bucket updation failed", func() {
				awsClient.EXPECT().UpdateBucketConfig(ctx, gomock.Any(), gomock.Any(), false).Return(fmt.Errorf("bucket update failed"))

				err := a.Reconcile(ctx, logger, backupBucket)
				Expect(err).Should(HaveOccurred())
			})
		})

		Context("when bucket exist and bucket versioning is enabled", func() {
			BeforeEach(func() {
				backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"24h","mode":"compliance"}}`),
				}

				awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)

				awsClient.EXPECT().GetBucketVersioningStatus(ctx, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ string) (*s3.GetBucketVersioningOutput, error) {
						return &s3.GetBucketVersioningOutput{
							Status: s3types.BucketVersioningStatusEnabled,
						}, nil
					},
				)
			})

			Context("GetObjectLockConfiguration API call fails", func() {
				BeforeEach(func() {
					awsClient.EXPECT().GetObjectLockConfiguration(ctx, gomock.Any()).Return(nil, fmt.Errorf("ObjectLockConfigurationNotFoundError")).AnyTimes()
				})
				It("should update the bucket", func() {
					awsClient.EXPECT().UpdateBucketConfig(ctx, gomock.Any(), gomock.Any(), true).Return(nil)

					err := a.Reconcile(ctx, logger, backupBucket)
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("should return error if bucket updation failed", func() {
					awsClient.EXPECT().UpdateBucketConfig(ctx, gomock.Any(), gomock.Any(), true).Return(fmt.Errorf("bucket update failed"))

					err := a.Reconcile(ctx, logger, backupBucket)
					Expect(err).Should(HaveOccurred())
				})
			})

			Context("GetObjectLockConfiguration API call succeeds", func() {

				Context("Disable the object lock settings if backupbucketConfig isn't provided in ProviderConfig", func() {
					It("should be removed the object lock settings", func() {
						// set the providerConfig to nil
						backupBucket.Spec.ProviderConfig = nil

						awsClient.EXPECT().GetObjectLockConfiguration(ctx, gomock.Any()).DoAndReturn(
							func(_ context.Context, _ string) (*s3.GetObjectLockConfigurationOutput, error) {
								return &s3.GetObjectLockConfigurationOutput{
									ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
										ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
										Rule: &s3types.ObjectLockRule{
											DefaultRetention: &s3types.DefaultRetention{
												Days: awsv2.Int32(1),
												Mode: s3types.ObjectLockRetentionModeGovernance,
											},
										},
									},
								}, nil
							},
						)
						awsClient.EXPECT().RemoveObjectLockConfig(ctx, gomock.Any()).Return(nil)

						err := a.Reconcile(ctx, logger, backupBucket)
						Expect(err).ShouldNot(HaveOccurred())
					})

					It("should do nothing if the object lock settings are already removed", func() {
						// set the providerConfig to nil
						backupBucket.Spec.ProviderConfig = nil

						awsClient.EXPECT().GetObjectLockConfiguration(ctx, gomock.Any()).DoAndReturn(
							func(_ context.Context, _ string) (*s3.GetObjectLockConfigurationOutput, error) {
								return &s3.GetObjectLockConfigurationOutput{
									ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
										ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
									},
								}, nil
							},
						)

						err := a.Reconcile(ctx, logger, backupBucket)
						Expect(err).ShouldNot(HaveOccurred())
					})

					It("should return error if the object lock settings are failed to remove", func() {
						// set the providerConfig to nil
						backupBucket.Spec.ProviderConfig = nil

						awsClient.EXPECT().GetObjectLockConfiguration(ctx, gomock.Any()).DoAndReturn(
							func(_ context.Context, _ string) (*s3.GetObjectLockConfigurationOutput, error) {
								return &s3.GetObjectLockConfigurationOutput{
									ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
										ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
										Rule: &s3types.ObjectLockRule{
											DefaultRetention: &s3types.DefaultRetention{
												Days: awsv2.Int32(1),
												Mode: s3types.ObjectLockRetentionModeGovernance,
											},
										},
									},
								}, nil
							},
						)

						awsClient.EXPECT().RemoveObjectLockConfig(ctx, gomock.Any()).Return(fmt.Errorf("Unable to remove object lock settings"))

						err := a.Reconcile(ctx, logger, backupBucket)
						Expect(err).Should(HaveOccurred())
					})

				})

				It("should update the bucket if object lock configuration needs to be updated", func() {
					backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
						Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"48h","mode":"compliance"}}`),
					}

					awsClient.EXPECT().GetObjectLockConfiguration(ctx, gomock.Any()).DoAndReturn(
						func(_ context.Context, _ string) (*s3.GetObjectLockConfigurationOutput, error) {
							return &s3.GetObjectLockConfigurationOutput{
								ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
									ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
									Rule: &s3types.ObjectLockRule{
										DefaultRetention: &s3types.DefaultRetention{
											Days: awsv2.Int32(1),
											Mode: s3types.ObjectLockRetentionModeCompliance,
										},
									},
								},
							}, nil
						},
					).AnyTimes()

					awsClient.EXPECT().UpdateBucketConfig(ctx, gomock.Any(), gomock.Any(), true).Return(nil)

					err := a.Reconcile(ctx, logger, backupBucket)
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("should return error if object lock config needs to be updated but bucket updation failed", func() {
					backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
						Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"24h","mode":"compliance"}}`),
					}

					awsClient.EXPECT().GetObjectLockConfiguration(ctx, gomock.Any()).DoAndReturn(
						func(_ context.Context, _ string) (*s3.GetObjectLockConfigurationOutput, error) {
							return &s3.GetObjectLockConfigurationOutput{
								ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
									ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
									Rule: &s3types.ObjectLockRule{
										DefaultRetention: &s3types.DefaultRetention{
											Days: awsv2.Int32(1),
											Mode: s3types.ObjectLockRetentionModeGovernance,
										},
									},
								},
							}, nil
						},
					).AnyTimes()

					awsClient.EXPECT().UpdateBucketConfig(ctx, gomock.Any(), gomock.Any(), true).Return(fmt.Errorf("bucket updation failed"))

					err := a.Reconcile(ctx, logger, backupBucket)
					Expect(err).Should(HaveOccurred())
				})

				It("should update the bucket if the object lock is enabled but rules are not defined", func() {
					backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
						Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"24h","mode":"compliance"}}`),
					}

					awsClient.EXPECT().GetObjectLockConfiguration(ctx, gomock.Any()).DoAndReturn(
						func(_ context.Context, _ string) (*s3.GetObjectLockConfigurationOutput, error) {
							return &s3.GetObjectLockConfigurationOutput{
								ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
									ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
								},
							}, nil
						},
					).AnyTimes()
					awsClient.EXPECT().UpdateBucketConfig(ctx, gomock.Any(), gomock.Any(), true).Return(nil)

					err := a.Reconcile(ctx, logger, backupBucket)
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("should do nothing if the object lock config doesn't need to be updated", func() {
					backupBucket.Spec.ProviderConfig = &runtime.RawExtension{
						Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig","immutability":{"retentionType":"bucket","retentionPeriod":"24h","mode":"compliance"}}`),
					}

					awsClient.EXPECT().GetObjectLockConfiguration(ctx, gomock.Any()).DoAndReturn(
						func(_ context.Context, _ string) (*s3.GetObjectLockConfigurationOutput, error) {
							return &s3.GetObjectLockConfigurationOutput{
								ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
									ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
									Rule: &s3types.ObjectLockRule{
										DefaultRetention: &s3types.DefaultRetention{
											Days: awsv2.Int32(1),
											Mode: s3types.ObjectLockRetentionModeCompliance,
										},
									},
								},
							}, nil
						},
					).AnyTimes()

					err := a.Reconcile(ctx, logger, backupBucket)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})
		})
	})

	Describe("#Delete", func() {
		var backupBucket *extensionsv1alpha1.BackupBucket

		BeforeEach(func() {
			backupBucket = &extensionsv1alpha1.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      bucketName,
					Namespace: namespace,
				},
				Spec: extensionsv1alpha1.BackupBucketSpec{
					SecretRef: secretRef,
					Region:    region,
				},
			}

			c.EXPECT().Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
				func(_ context.Context, _ client.ObjectKey, obj *corev1.Secret, _ ...client.GetOption) error {
					*obj = *secret
					return nil
				},
			)
		})

		It("should return error if aws client creation fails", func() {
			awsClientFactory.EXPECT().NewClient(authConfig).Return(nil, fmt.Errorf("failed to created aws client"))

			err := a.Delete(ctx, logger, backupBucket)
			Expect(err).Should(HaveOccurred())
		})

		It("should delete the backup bucket successfully", func() {
			awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)
			awsClient.EXPECT().DeleteBucketIfExists(ctx, gomock.Any()).Return(nil)

			err := a.Delete(ctx, logger, backupBucket)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should return error if deletion of backup bucket fails", func() {
			awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)
			awsClient.EXPECT().DeleteBucketIfExists(ctx, gomock.Any()).Return(fmt.Errorf("failed to delete the backup bucket"))

			err := a.Delete(ctx, logger, backupBucket)
			Expect(err).Should(HaveOccurred())
		})
	})
})
