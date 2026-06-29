// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
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
			ctx       = context.TODO()
			namespace = "namespace"
			name      = "name"

			secretRef = corev1.SecretReference{
				Name:      name,
				Namespace: namespace,
			}

			scheme = runtime.NewScheme()
		)

		BeforeEach(func() {
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
		})

		It("should fail if the secret could not be read", func() {
			c := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
			// secret does not exist → Get returns NotFound
			credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, false, "")
			Expect(credentials).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		Context("DNS keys are not allowed", func() {
			It("should return the correct credentials object if non-DNS keys are used", func() {
				s := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Data: map[string][]byte{
						AccessKeyID:     accessKeyID,
						SecretAccessKey: secretAccessKey,
					},
				}
				c := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()

				credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, false, "sample")

				Expect(credentials).To(Equal(&awsclient.AuthConfig{
					AccessKey: &awsclient.AccessKey{
						ID:     string(accessKeyID),
						Secret: string(secretAccessKey),
					},
					Region: "sample",
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should fail if DNS keys are used", func() {
				s := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Data: map[string][]byte{
						DNSAccessKeyID:     accessKeyID,
						DNSSecretAccessKey: secretAccessKey,
					},
				}
				c := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()

				credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, false, "")

				Expect(credentials).To(BeNil())
				Expect(err).To(HaveOccurred())
			})
		})

		Context("DNS keys are allowed", func() {
			It("should return the correct credentials object if DNS keys are used", func() {
				s := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Data: map[string][]byte{
						DNSAccessKeyID:     accessKeyID,
						DNSSecretAccessKey: secretAccessKey,
						DNSRegion:          region,
					},
				}
				c := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()

				credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, true, "")

				Expect(credentials).To(Equal(&awsclient.AuthConfig{
					AccessKey: &awsclient.AccessKey{
						ID:     string(accessKeyID),
						Secret: string(secretAccessKey),
					},
					Region: string(region),
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return the correct credentials object if non-DNS keys are used", func() {
				s := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Data: map[string][]byte{
						AccessKeyID:     accessKeyID,
						SecretAccessKey: secretAccessKey,
						Region:          region,
					},
				}
				c := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()

				credentials, err := GetCredentialsFromSecretRef(ctx, c, secretRef, true, "")

				Expect(credentials).To(Equal(&awsclient.AuthConfig{
					AccessKey: &awsclient.AccessKey{
						ID:     string(accessKeyID),
						Secret: string(secretAccessKey),
					},
					Region: string(region),
				}))
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("#ReadCredentialsSecret", func() {
		It("should fail if access key id is missing", func() {
			credentials, err := ReadCredentialsSecret(secret, false, "")

			Expect(credentials).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		It("should fail if secret access key is missing", func() {
			secret.Data = map[string][]byte{
				AccessKeyID: accessKeyID,
			}

			credentials, err := ReadCredentialsSecret(secret, false, "")

			Expect(credentials).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		Context("DNS keys are not allowed", func() {
			It("should return the correct credentials object if non-DNS keys are used", func() {
				secret.Data = map[string][]byte{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
				}

				credentials, err := ReadCredentialsSecret(secret, false, "sample")

				Expect(credentials).To(Equal(&awsclient.AuthConfig{
					AccessKey: &awsclient.AccessKey{
						ID:     string(accessKeyID),
						Secret: string(secretAccessKey),
					},
					Region: "sample",
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return the correct credentials object if non-DNS keys are used with workload identity and roleARN data key", func() {
				secret.Data = map[string][]byte{
					"token":   []byte("foo"),
					"roleARN": []byte("arn"),
					Region:    region,
				}

				credentials, err := ReadCredentialsSecret(secret, false, "")

				Expect(credentials.Region).To(Equal(string(region)))
				Expect(credentials.AccessKey).To(BeNil())
				Expect(credentials.WorkloadIdentity.RoleARN).To(Equal("arn"))
				Expect(err).NotTo(HaveOccurred())
				token, err := credentials.WorkloadIdentity.TokenRetriever.GetIdentityToken()
				Expect(err).NotTo(HaveOccurred())
				Expect(token).To(Equal([]byte("foo")))
			})

			It("should return the correct credentials object if non-DNS keys are used with workload identity and without roleARN data key", func() {
				secret.Data = map[string][]byte{
					"token": []byte("foo"),
					"config": []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: role-arn`),
					Region: region,
				}

				credentials, err := ReadCredentialsSecret(secret, false, "")
				Expect(err).ToNot(HaveOccurred())

				Expect(credentials.Region).To(Equal(string(region)))
				Expect(credentials.AccessKey).To(BeNil())
				Expect(credentials.WorkloadIdentity.RoleARN).To(Equal("role-arn"))

				token, err := credentials.WorkloadIdentity.TokenRetriever.GetIdentityToken()
				Expect(err).ToNot(HaveOccurred())
				Expect(token).To(Equal([]byte("foo")))
			})

			It("should fail to return the correct credentials object if non-DNS keys are used with workload identity without roleARN and config data key", func() {
				secret.Data = map[string][]byte{
					"token": []byte("foo"),
					Region:  region,
				}

				credentials, err := ReadCredentialsSecret(secret, false, "")
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("failed to retrieve role ARN from secret: missing \"config\" field in secret"))
				Expect(credentials).To(BeNil())
			})

			It("should fail to the correct credentials object if non-DNS keys are used with workload identity without roleARN data key and empty roleARN in workloadIdentityConfig", func() {
				secret.Data = map[string][]byte{
					"token": []byte("foo"),
					"config": []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN:`),
					Region: region,
				}

				credentials, err := ReadCredentialsSecret(secret, false, "")
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("failed to retrieve role ARN from secret: workloadIdentityConfig.roleARN is empty"))
				Expect(credentials).To(BeNil())
			})

			It("should fail if DNS keys are used", func() {
				secret.Data = map[string][]byte{
					DNSAccessKeyID:     accessKeyID,
					DNSSecretAccessKey: secretAccessKey,
				}

				credentials, err := ReadCredentialsSecret(secret, false, "")

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

				credentials, err := ReadCredentialsSecret(secret, true, "")

				Expect(credentials).To(Equal(&awsclient.AuthConfig{
					AccessKey: &awsclient.AccessKey{
						ID:     string(accessKeyID),
						Secret: string(secretAccessKey),
					},
					Region: string(region),
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return the correct credentials object if non-DNS keys are used", func() {
				secret.Data = map[string][]byte{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
					Region:          region,
				}

				credentials, err := ReadCredentialsSecret(secret, true, "")

				Expect(credentials).To(Equal(&awsclient.AuthConfig{
					AccessKey: &awsclient.AccessKey{
						ID:     string(accessKeyID),
						Secret: string(secretAccessKey),
					},
					Region: string(region),
				}))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return the correct credentials object if non-DNS keys are used with workload identity config", func() {
				secret.Data = map[string][]byte{
					"token":   []byte("foo"),
					"roleARN": []byte("arn"),
					Region:    region,
				}

				credentials, err := ReadCredentialsSecret(secret, true, "")

				Expect(credentials.Region).To(Equal(string(region)))
				Expect(credentials.AccessKey).To(BeNil())
				Expect(credentials.WorkloadIdentity.RoleARN).To(Equal("arn"))
				Expect(err).NotTo(HaveOccurred())
				token, err := credentials.WorkloadIdentity.TokenRetriever.GetIdentityToken()
				Expect(err).NotTo(HaveOccurred())
				Expect(token).To(Equal([]byte("foo")))
			})
		})
	})
})
