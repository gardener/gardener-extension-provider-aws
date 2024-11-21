// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateWorkloadIdentityConfig checks whether the given workload identity configuration contains expected fields and values.
func ValidateWorkloadIdentityConfig(config *apisaws.WorkloadIdentityConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(config.RoleARN) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("roleARN"), "roleARN is required"))
	}

	return allErrs
}

// ValidateWorkloadIdentityConfigUpdate validates updates on WorkloadIdentityConfig object.
func ValidateWorkloadIdentityConfigUpdate(oldConfig, newConfig *apisaws.WorkloadIdentityConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	allErrs = append(allErrs, ValidateWorkloadIdentityConfig(newConfig, fldPath)...)

	return allErrs
}
