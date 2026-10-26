// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package validator_test

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
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

var _ = Describe("SecretBinding validator", func() {

	Describe("#Validate", func() {
		const (
			namespace                 = "garden-dev"
			name                      = "my-provider-account"
			extensionProviderLabelKey = "provider.extensions.gardener.cloud/aws"
		)

		var (
			secretBindingValidator extensionswebhook.Validator

			mgr *testutils.FakeManager

			ctx           = context.TODO()
			secretBinding *core.SecretBinding

			scheme = func() *runtime.Scheme {
				s := runtime.NewScheme()
				Expect(corev1.AddToScheme(s)).To(Succeed())
				return s
			}()
		)

		newValidator := func(objs ...client.Object) {
			b := fakeclient.NewClientBuilder().WithScheme(scheme)
			if len(objs) > 0 {
				b = b.WithObjects(objs...)
			}
			mgr = &testutils.FakeManager{APIReader: b.Build()}
			secretBindingValidator = validator.NewSecretBindingValidator(mgr)
		}

		BeforeEach(func() {
			secretBinding = &core.SecretBinding{
				SecretRef: corev1.SecretReference{
					Name:      name,
					Namespace: namespace,
				},
			}
			newValidator()
		})

		It("should return err when obj is not a SecretBinding", func() {
			err := secretBindingValidator.Validate(ctx, &corev1.Secret{}, nil)
			Expect(err).To(MatchError("wrong object type *v1.Secret"))
		})

		It("should return err when oldObj is not a SecretBinding", func() {
			err := secretBindingValidator.Validate(ctx, &core.SecretBinding{}, &corev1.Secret{})
			Expect(err).To(MatchError("wrong object type *v1.Secret for old object"))
		})

		It("should return err if it fails to get the corresponding Secret", func() {
			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return err when the corresponding Secret is not valid", func() {
			newValidator(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Data: map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"),                     // 20 chars but has underscore
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
				},
			})

			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return nil when the corresponding Secret is valid", func() {
			newValidator(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Data: map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPLE"),                     // exactly 20 chars, uppercase alphanumeric
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
				},
			})

			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should revalidate the referenced Secret when the provider label is introduced", func() {
			secretBinding.Provider = &core.SecretBindingProvider{Type: "aws"}
			oldSecretBinding := secretBinding.DeepCopy()
			secretBinding.Labels = map[string]string{extensionProviderLabelKey: "true"}
			newValidator(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Data: map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"),                     // invalid
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
				},
			})

			Expect(secretBindingValidator.Validate(ctx, secretBinding, oldSecretBinding)).To(HaveOccurred())
		})

		It("should skip validation when the SecretBinding was previously validated", func() {
			secretBinding.Provider = &core.SecretBindingProvider{Type: "aws"}
			secretBinding.Labels = map[string]string{extensionProviderLabelKey: "true"}

			Expect(secretBindingValidator.Validate(ctx, secretBinding, secretBinding.DeepCopy())).To(Succeed())
		})
	})
})
