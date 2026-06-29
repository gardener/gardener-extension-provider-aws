// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
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
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/validator"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

var _ = Describe("SecretBinding validator", func() {

	Describe("#Validate", func() {
		const (
			namespace = "garden-dev"
			name      = "my-provider-account"
		)

		var (
			secretBindingValidator extensionswebhook.Validator

			mgr *testutils.FakeManager

			ctx           = context.TODO()
			secretBinding = &core.SecretBinding{
				SecretRef: corev1.SecretReference{
					Name:      name,
					Namespace: namespace,
				},
			}

			scheme = func() *runtime.Scheme {
				s := runtime.NewScheme()
				Expect(corev1.AddToScheme(s)).To(Succeed())
				return s
			}()
		)

		It("should return err when obj is not a SecretBinding", func() {
			apiReader := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
			mgr = &testutils.FakeManager{APIReader: apiReader}
			secretBindingValidator = validator.NewSecretBindingValidator(mgr)

			err := secretBindingValidator.Validate(ctx, &corev1.Secret{}, nil)
			Expect(err).To(MatchError("wrong object type *v1.Secret"))
		})

		It("should return err when oldObj is not a SecretBinding", func() {
			apiReader := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
			mgr = &testutils.FakeManager{APIReader: apiReader}
			secretBindingValidator = validator.NewSecretBindingValidator(mgr)

			err := secretBindingValidator.Validate(ctx, &core.SecretBinding{}, &corev1.Secret{})
			Expect(err).To(MatchError("wrong object type *v1.Secret for old object"))
		})

		It("should return err if it fails to get the corresponding Secret", func() {
			// secret does not exist → Get returns NotFound
			apiReader := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
			mgr = &testutils.FakeManager{APIReader: apiReader}
			secretBindingValidator = validator.NewSecretBindingValidator(mgr)

			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
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
			apiReader := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
			mgr = &testutils.FakeManager{APIReader: apiReader}
			secretBindingValidator = validator.NewSecretBindingValidator(mgr)

			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
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
			apiReader := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
			mgr = &testutils.FakeManager{APIReader: apiReader}
			secretBindingValidator = validator.NewSecretBindingValidator(mgr)

			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
