// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator_test

import (
	"context"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

			ctrl      *gomock.Controller
			mgr       *mockmanager.MockManager
			apiReader *mockclient.MockReader

			ctx           = context.TODO()
			secretBinding = &core.SecretBinding{
				SecretRef: corev1.SecretReference{
					Name:      name,
					Namespace: namespace,
				},
			}
			fakeErr = fmt.Errorf("fake err")
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())

			mgr = mockmanager.NewMockManager(ctrl)

			apiReader = mockclient.NewMockReader(ctrl)
			mgr.EXPECT().GetAPIReader().Return(apiReader)

			secretBindingValidator = validator.NewSecretBindingValidator(mgr)
		})

		AfterEach(func() {
			ctrl.Finish()
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
			apiReader.EXPECT().Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(fakeErr)

			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
			Expect(err).To(MatchError(fakeErr))
		})

		It("should return err when the corresponding Secret is not valid", func() {
			secret := &corev1.Secret{Data: map[string][]byte{
				aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"),                     // 20 chars but has underscore
				aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
			}}
			apiReader.EXPECT().Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, gomock.AssignableToTypeOf(&corev1.Secret{})).
				SetArg(2, *secret)

			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return nil when the corresponding Secret is valid", func() {
			secret := &corev1.Secret{Data: map[string][]byte{
				aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPLE"),                     // exactly 20 chars, uppercase alphanumeric
				aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY"), // exactly 40 chars, base64
			}}
			apiReader.EXPECT().Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, gomock.AssignableToTypeOf(&corev1.Secret{})).
				SetArg(2, *secret)

			err := secretBindingValidator.Validate(ctx, secretBinding, nil)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
