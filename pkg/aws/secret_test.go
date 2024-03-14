// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"

	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	. "github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

var (
	accessKeyID     = []byte("foo")
	secretAccessKey = []byte("bar")
	region          = []byte("region")
)

var _ = Describe("Secret", func() {
	var secret *corev1.Secret

	BeforeEach(func() {
		secret = &corev1.Secret{}
	})

	Describe("#GetCredentialsFromSecretRef", func() {
		var (
			ctrl *gomock.Controller
			c    *mockclient.MockClient

			ctx       = context.TODO()
			namespace = "namespace"
			name      = "name"

			secretRef = corev1.SecretReference{
				Name:      name,
				Namespace: namespace,
			}
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())

			c = mockclient.NewMockClient(ctrl)
		})

		AfterEach(func() {
			ctrl.Finish()
		})

		It("should fail if the secret could not be read", func() {
			fakeErr := errors.New("error")
			c.EXPECT().Get(ctx, kutil.Key(namespace, name), gomock.AssignableToTypeOf(&corev1.Secret{})).Return(fakeErr)

			credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, false)

			Expect(credentials).To(BeNil())
			Expect(err).To(Equal(fakeErr))
		})

		Context("DNS keys are not allowed", func() {
			It("should return the correct credentials object if non-DNS keys are used", func() {
				c.EXPECT().Get(ctx, kutil.Key(namespace, name), gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret, _ ...client.GetOption) error {
						secret.Data = map[string][]byte{
							AccessKeyID:     accessKeyID,
							SecretAccessKey: secretAccessKey,
						}
						return nil
					},
				)

				credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, false)

				Expect(credentials).To(Equal(&Credentials{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should fail if DNS keys are used", func() {
				c.EXPECT().Get(ctx, kutil.Key(namespace, name), gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret, _ ...client.GetOption) error {
						secret.Data = map[string][]byte{
							DNSAccessKeyID:     accessKeyID,
							DNSSecretAccessKey: secretAccessKey,
						}
						return nil
					},
				)

				credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, false)

				Expect(credentials).To(BeNil())
				Expect(err).To(HaveOccurred())
			})
		})

		Context("DNS keys are allowed", func() {
			It("should return the correct credentials object if DNS keys are used", func() {
				c.EXPECT().Get(ctx, kutil.Key(namespace, name), gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret, _ ...client.GetOption) error {
						secret.Data = map[string][]byte{
							DNSAccessKeyID:     accessKeyID,
							DNSSecretAccessKey: secretAccessKey,
							DNSRegion:          region,
						}
						return nil
					},
				)

				credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, true)

				Expect(credentials).To(Equal(&Credentials{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
					Region:          region,
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return the correct credentials object if non-DNS keys are used", func() {
				c.EXPECT().Get(ctx, kutil.Key(namespace, name), gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret, _ ...client.GetOption) error {
						secret.Data = map[string][]byte{
							AccessKeyID:     accessKeyID,
							SecretAccessKey: secretAccessKey,
							Region:          region,
						}
						return nil
					},
				)

				credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, true)

				Expect(credentials).To(Equal(&Credentials{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
					Region:          region,
				}))
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("#ReadCredentialsSecret", func() {
		It("should fail if access key id is missing", func() {
			credentials, err := ReadCredentialsSecret(secret, false)

			Expect(credentials).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		It("should fail if secret access key is missing", func() {
			secret.Data = map[string][]byte{
				AccessKeyID: accessKeyID,
			}

			credentials, err := ReadCredentialsSecret(secret, false)

			Expect(credentials).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		Context("DNS keys are not allowed", func() {
			It("should return the correct credentials object if non-DNS keys are used", func() {
				secret.Data = map[string][]byte{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
				}

				credentials, err := ReadCredentialsSecret(secret, false)

				Expect(credentials).To(Equal(&Credentials{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should fail if DNS keys are used", func() {
				secret.Data = map[string][]byte{
					DNSAccessKeyID:     accessKeyID,
					DNSSecretAccessKey: secretAccessKey,
				}

				credentials, err := ReadCredentialsSecret(secret, false)

				Expect(credentials).To(BeNil())
				Expect(err).To(HaveOccurred())
			})
		})

		Context("DNS keys are allowed", func() {
			It("should return the correct credentials object if DNS keys are used", func() {
				secret.Data = map[string][]byte{
					DNSAccessKeyID:     accessKeyID,
					DNSSecretAccessKey: secretAccessKey,
					DNSRegion:          region,
				}

				credentials, err := ReadCredentialsSecret(secret, true)

				Expect(credentials).To(Equal(&Credentials{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
					Region:          region,
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return the correct credentials object if non-DNS keys are used", func() {
				secret.Data = map[string][]byte{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
					Region:          region,
				}

				credentials, err := ReadCredentialsSecret(secret, true)

				Expect(credentials).To(Equal(&Credentials{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
					Region:          region,
				}))
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
