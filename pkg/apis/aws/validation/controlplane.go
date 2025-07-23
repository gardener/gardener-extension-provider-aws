// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	featurevalidation "github.com/gardener/gardener/pkg/utils/validation/features"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateControlPlaneConfig validates a ControlPlaneConfig object.
func ValidateControlPlaneConfig(cpConfig *apisaws.ControlPlaneConfig, version string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if cpConfig.CloudControllerManager != nil {
		allErrs = append(allErrs, featurevalidation.ValidateFeatureGates(cpConfig.CloudControllerManager.FeatureGates, version, fldPath.Child("cloudControllerManager", "featureGates"))...)
	}

	if cpConfig.LoadBalancerController != nil && cpConfig.LoadBalancerController.IngressClassName != nil {
		ingressClassName := *cpConfig.LoadBalancerController.IngressClassName
		ingressPath := fldPath.Child("loadBalancerController", "ingressClassName")
		allErrs = append(allErrs, validateK8sResourceName(ingressClassName, ingressPath)...)
	}

	return allErrs
}
