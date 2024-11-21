// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
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
			RoleARN: "foo",
		}
	})

	It("should validate the config successfully", func() {
		Expect(validation.ValidateWorkloadIdentityConfig(workloadIdentityConfig, field.NewPath(""))).To(BeEmpty())
	})

	It("should contain all expected validation errors", func() {
		workloadIdentityConfig.RoleARN = ""
		errorList := validation.ValidateWorkloadIdentityConfig(workloadIdentityConfig, field.NewPath("providerConfig"))
		Expect(errorList).To(ConsistOfFields(
			Fields{
				"Type":   Equal(field.ErrorTypeRequired),
				"Field":  Equal("providerConfig.roleARN"),
				"Detail": Equal("roleARN is required"),
			},
		))
	})

	It("should validate the config successfully during update", func() {
		newConfig := workloadIdentityConfig.DeepCopy()
		Expect(validation.ValidateWorkloadIdentityConfigUpdate(workloadIdentityConfig, newConfig, field.NewPath(""))).To(BeEmpty())
	})

	It("should allow changing the roleARN during update", func() {
		newConfig := workloadIdentityConfig.DeepCopy()
		newConfig.RoleARN = "bar"
		errorList := validation.ValidateWorkloadIdentityConfigUpdate(workloadIdentityConfig, newConfig, field.NewPath("providerConfig"))
		Expect(errorList).To(BeEmpty())
	})
})
