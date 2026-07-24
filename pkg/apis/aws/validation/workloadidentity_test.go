// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

var _ = Describe("#ValidateWorkloadIdentityConfig", func() {
	var (
		workloadIdentityConfig *apisaws.WorkloadIdentityConfig
	)

	BeforeEach(func() {
		workloadIdentityConfig = &apisaws.WorkloadIdentityConfig{
			RoleARN: "arn:aws:iam::123456789012:role/my-role",
		}
	})

	It("should validate the config successfully", func() {
		Expect(validation.ValidateWorkloadIdentityConfig(workloadIdentityConfig, field.NewPath(""))).To(BeEmpty())
	})

	DescribeTable("should accept valid IAM role ARNs",
		func(roleARN string) {
			workloadIdentityConfig.RoleARN = roleARN
			Expect(validation.ValidateWorkloadIdentityConfig(workloadIdentityConfig, field.NewPath(""))).To(BeEmpty())
		},
		Entry("simple role", "arn:aws:iam::123456789012:role/my-role"),
		Entry("role with path", "arn:aws:iam::123456789012:role/path/to/my-role"),
		Entry("role name with allowed special characters", "arn:aws:iam::123456789012:role/my.role_name+=,.@-"),
		Entry("china partition", "arn:aws-cn:iam::123456789012:role/my-role"),
		Entry("gov cloud partition", "arn:aws-us-gov:iam::123456789012:role/my-role"),
		Entry("eusc partition", "arn:aws-eusc:iam::123456789012:role/my-role"),
		Entry("iso partition", "arn:aws-iso:iam::123456789012:role/my-role"),
	)

	DescribeTable("should reject invalid IAM role ARNs",
		func(roleARN string) {
			workloadIdentityConfig.RoleARN = roleARN
			errorList := validation.ValidateWorkloadIdentityConfig(workloadIdentityConfig, field.NewPath("providerConfig"))
			Expect(errorList).To(ConsistOfFields(
				Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("providerConfig.roleARN"),
					"Detail": Equal("does not match expected regex ^arn:aws[a-z0-9-]*:iam::\\d{12}:role(/[\\w+=,.@-]+)*/[\\w+=,.@-]+$"),
				},
			))
		},
		Entry("arbitrary string", "foo"),
		Entry("missing arn prefix", "aws:iam::123456789012:role/my-role"),
		Entry("wrong service", "arn:aws:s3::123456789012:role/my-role"),
		Entry("wrong resource type", "arn:aws:iam::123456789012:user/my-user"),
		Entry("account id too short", "arn:aws:iam::12345:role/my-role"),
		Entry("account id with non-digits", "arn:aws:iam::12345678901a:role/my-role"),
		Entry("non-empty region segment", "arn:aws:iam:us-east-1:123456789012:role/my-role"),
		Entry("missing role name", "arn:aws:iam::123456789012:role/"),
		Entry("missing role name and slash", "arn:aws:iam::123456789012:role"),
		Entry("trailing whitespace", "arn:aws:iam::123456789012:role/my-role "),
		Entry("invalid character in role name", "arn:aws:iam::123456789012:role/my-role*"),
	)

	It("should contain all expected validation errors when roleARN is empty", func() {
		workloadIdentityConfig.RoleARN = ""
		errorList := validation.ValidateWorkloadIdentityConfig(workloadIdentityConfig, field.NewPath("providerConfig"))
		Expect(errorList).To(ConsistOfFields(
			Fields{
				"Type":   Equal(field.ErrorTypeRequired),
				"Field":  Equal("providerConfig.roleARN"),
				"Detail": Equal("cannot be empty"),
			},
		))
	})

	It("should validate the config successfully during update", func() {
		newConfig := workloadIdentityConfig.DeepCopy()
		Expect(validation.ValidateWorkloadIdentityConfigUpdate(workloadIdentityConfig, newConfig, field.NewPath(""))).To(BeEmpty())
	})

	It("should allow changing the roleARN during update", func() {
		newConfig := workloadIdentityConfig.DeepCopy()
		newConfig.RoleARN = "arn:aws:iam::123456789012:role/another-role"
		errorList := validation.ValidateWorkloadIdentityConfigUpdate(workloadIdentityConfig, newConfig, field.NewPath("providerConfig"))
		Expect(errorList).To(BeEmpty())
	})

	It("should reject changing the roleARN to an invalid value during update", func() {
		newConfig := workloadIdentityConfig.DeepCopy()
		newConfig.RoleARN = "not-a-valid-role-arn"
		errorList := validation.ValidateWorkloadIdentityConfigUpdate(workloadIdentityConfig, newConfig, field.NewPath("providerConfig"))
		Expect(errorList).To(ConsistOfFields(
			Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("providerConfig.roleARN"),
				"Detail": Equal("does not match expected regex ^arn:aws[a-z0-9-]*:iam::\\d{12}:role(/[\\w+=,.@-]+)*/[\\w+=,.@-]+$"),
			},
		))
	})
})
