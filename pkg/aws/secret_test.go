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

package aws_test

import (
	"context"
	"errors"

	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/golang/mock/gomock"
	"sigs.k8s.io/controller-runtime/pkg/client"

	. "github.com/gardener/gardener-extension-provider-aws/pkg/aws"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
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
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret) error {
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
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret) error {
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
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret) error {
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
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret) error {
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
