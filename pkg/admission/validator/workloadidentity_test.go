// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator_test

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	securityv1alpha1 "github.com/gardener/gardener/pkg/apis/security/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/validator"
	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsapiv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var _ = Describe("WorkloadIdentity validator", func() {
	Describe("#Validate", func() {
		var (
			workloadIdentityValidator extensionswebhook.Validator
			workloadIdentity          *securityv1alpha1.WorkloadIdentity
			ctx                       = context.Background()
		)

		BeforeEach(func() {
			workloadIdentity = &securityv1alpha1.WorkloadIdentity{
				Spec: securityv1alpha1.WorkloadIdentitySpec{
					Audiences: []string{"foo"},
					TargetSystem: securityv1alpha1.TargetSystem{
						Type: "aws",
						ProviderConfig: &runtime.RawExtension{
							Raw: []byte(`
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: "foo"
`),
						},
					},
				},
			}
			scheme := runtime.NewScheme()
			Expect(securityv1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(awsapi.AddToScheme(scheme)).To(Succeed())
			Expect(awsapiv1alpha1.AddToScheme(scheme)).To(Succeed())

			workloadIdentityValidator = validator.NewWorkloadIdentityValidator(serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder())
		})

		It("should skip validation if workload identity is not of type 'aws'", func() {
			workloadIdentity.Spec.TargetSystem.Type = "foo"
			Expect(workloadIdentityValidator.Validate(ctx, workloadIdentity, nil)).To(Succeed())
		})

		It("should successfully validate the creation of a workload identity", func() {
			Expect(workloadIdentityValidator.Validate(ctx, workloadIdentity, nil)).To(Succeed())
		})

		It("should successfully validate the update of a workload identity", func() {
			newWorkloadIdentity := workloadIdentity.DeepCopy()
			newWorkloadIdentity.Spec.TargetSystem.ProviderConfig.Raw = []byte(`
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: "foo"
`)
			Expect(workloadIdentityValidator.Validate(ctx, newWorkloadIdentity, workloadIdentity)).To(Succeed())
		})
	})
})
