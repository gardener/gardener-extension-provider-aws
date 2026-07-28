// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator_test

import (
	"context"
	"errors"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/apis/security"
	securityv1alpha1 "github.com/gardener/gardener/pkg/apis/security/v1alpha1"
	testutils "github.com/gardener/gardener/pkg/utils/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/validator"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

var _ = Describe("CredentialsBinding validator", func() {
	Describe("#Validate", func() {
		const (
			namespace = "garden-dev"
			name      = "my-provider-account"
		)

		var (
			mgr *testutils.FakeManager

			ctx                                = context.TODO()
			credentialsBindingSecret           *security.CredentialsBinding
			credentialsBindingInternalSecret   *security.CredentialsBinding
			credentialsBindingWorkloadIdentity *security.CredentialsBinding

			scheme = func() *runtime.Scheme {
				s := runtime.NewScheme()
				Expect(corev1.AddToScheme(s)).To(Succeed())
				Expect(gardencorev1beta1.AddToScheme(s)).To(Succeed())
				Expect(securityv1alpha1.AddToScheme(s)).To(Succeed())
				return s
			}()
		)

		BeforeEach(func() {
			credentialsBindingSecret = &security.CredentialsBinding{
				CredentialsRef: corev1.ObjectReference{
					Name:       name,
					Namespace:  namespace,
					Kind:       "Secret",
					APIVersion: "v1",
				},
			}
			credentialsBindingWorkloadIdentity = &security.CredentialsBinding{
				CredentialsRef: corev1.ObjectReference{
					Name:       name,
					Namespace:  namespace,
					Kind:       "WorkloadIdentity",
					APIVersion: "security.gardener.cloud/v1alpha1",
				},
			}
			credentialsBindingInternalSecret = &security.CredentialsBinding{
				CredentialsRef: corev1.ObjectReference{
					Name:       name,
					Namespace:  namespace,
					Kind:       "InternalSecret",
					APIVersion: "core.gardener.cloud/v1beta1",
				},
			}
		})

		newValidator := func(objects ...client.Object) extensionswebhook.Validator {
			b := fakeclient.NewClientBuilder().WithScheme(scheme)
			if len(objects) > 0 {
				b = b.WithObjects(objects...)
			}
			apiReader := b.Build()
			mgr = &testutils.FakeManager{APIReader: apiReader}
			return validator.NewCredentialsBindingValidator(mgr)
		}

		It("should return err when obj is not a CredentialsBinding", func() {
			v := newValidator()
			err := v.Validate(ctx, &corev1.Secret{}, nil)
			Expect(err).To(MatchError("wrong object type *v1.Secret"))
		})

		It("should return err when oldObj is not a CredentialsBinding", func() {
			v := newValidator()
			err := v.Validate(ctx, &security.CredentialsBinding{}, &corev1.Secret{})
			Expect(err).To(MatchError("wrong object type *v1.Secret for old object"))
		})

		It("should return err if the CredentialsBinding references unknown credentials type", func() {
			v := newValidator()
			credentialsBindingSecret.CredentialsRef.APIVersion = "unknown"
			err := v.Validate(ctx, credentialsBindingSecret, nil)
			Expect(err).To(MatchError(errors.New(`unsupported credentials reference: version "unknown", kind "Secret"`)))
		})

		It("should return err if it fails to get the corresponding Secret", func() {
			v := newValidator() // no secret pre-loaded
			err := v.Validate(ctx, credentialsBindingSecret, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return err when the corresponding Secret is not valid", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Data: map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"),                     // 20 chars but has underscore
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
				},
			}
			v := newValidator(secret)
			err := v.Validate(ctx, credentialsBindingSecret, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return nil when the corresponding Secret is valid", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Data: map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPLE"),                     // exactly 20 chars, uppercase alphanumeric
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
				},
			}
			v := newValidator(secret)
			err := v.Validate(ctx, credentialsBindingSecret, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return nil when the CredentialsBinding did not change", func() {
			v := newValidator()
			old := credentialsBindingSecret.DeepCopy()
			Expect(v.Validate(ctx, credentialsBindingSecret, old)).To(Succeed())
		})

		It("should return err if it fails to get the corresponding InternalSecret", func() {
			v := newValidator() // no InternalSecret pre-loaded
			err := v.Validate(ctx, credentialsBindingInternalSecret, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return err when the corresponding InternalSecret is not valid", func() {
			internalSecret := &gardencorev1beta1.InternalSecret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Data: map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"),                     // 20 chars but has underscore
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
				},
			}
			v := newValidator(internalSecret)
			err := v.Validate(ctx, credentialsBindingInternalSecret, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return nil when the corresponding InternalSecret is valid", func() {
			internalSecret := &gardencorev1beta1.InternalSecret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Data: map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPLE"),                     // exactly 20 chars, uppercase alphanumeric
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
				},
			}
			v := newValidator(internalSecret)
			err := v.Validate(ctx, credentialsBindingInternalSecret, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should succeed when the corresponding WorkloadIdentity is valid", func() {
			workloadIdentity := &securityv1alpha1.WorkloadIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: securityv1alpha1.WorkloadIdentitySpec{
					Audiences: []string{"foo"},
					TargetSystem: securityv1alpha1.TargetSystem{
						Type: "aws",
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"WorkloadIdentityConfig","roleARN":"arn:aws:iam::123456789012:role/my-role"}`),
						},
					},
				},
			}
			v := newValidator(workloadIdentity)
			Expect(v.Validate(ctx, credentialsBindingWorkloadIdentity, nil)).To(Succeed())
		})

		It("should return err if it fails to get the corresponding WorkloadIdentity", func() {
			v := newValidator() // no WorkloadIdentity pre-loaded
			err := v.Validate(ctx, credentialsBindingWorkloadIdentity, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return err when the corresponding WorkloadIdentity is missing config for target system", func() {
			workloadIdentity := &securityv1alpha1.WorkloadIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: securityv1alpha1.WorkloadIdentitySpec{
					Audiences: []string{"foo"},
					TargetSystem: securityv1alpha1.TargetSystem{
						Type: "aws",
					},
				},
			}
			v := newValidator(workloadIdentity)
			err := v.Validate(ctx, credentialsBindingWorkloadIdentity, nil)
			Expect(err).To(MatchError("the target system is missing configuration"))
		})

		It("should return err when the corresponding WorkloadIdentity has empty config for target system", func() {
			workloadIdentity := &securityv1alpha1.WorkloadIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: securityv1alpha1.WorkloadIdentitySpec{
					Audiences: []string{"foo"},
					TargetSystem: securityv1alpha1.TargetSystem{
						Type:           "aws",
						ProviderConfig: &runtime.RawExtension{Raw: []byte("{}")},
					},
				},
			}
			v := newValidator(workloadIdentity)
			err := v.Validate(ctx, credentialsBindingWorkloadIdentity, nil)
			Expect(err.Error()).To(ContainSubstring("target system's configuration is not valid"))
		})

		It("should return err when the corresponding WorkloadIdentity has invalid target system configuration", func() {
			workloadIdentity := &securityv1alpha1.WorkloadIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: securityv1alpha1.WorkloadIdentitySpec{
					Audiences: []string{"foo"},
					TargetSystem: securityv1alpha1.TargetSystem{
						Type: "aws",
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"WorkloadIdentityConfig"}`),
						},
					},
				},
			}
			v := newValidator(workloadIdentity)
			err := v.Validate(ctx, credentialsBindingWorkloadIdentity, nil)
			Expect(err.Error()).To(ContainSubstring("referenced workload identity garden-dev/my-provider-account is not valid"))
		})
	})
})
