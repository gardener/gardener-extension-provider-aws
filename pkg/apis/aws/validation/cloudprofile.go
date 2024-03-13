// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/strings/slices"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateCloudProfileConfig validates a CloudProfileConfig object.
func ValidateCloudProfileConfig(cloudProfile *apisaws.CloudProfileConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	machineImagesPath := fldPath.Child("machineImages")
	if len(cloudProfile.MachineImages) == 0 {
		allErrs = append(allErrs, field.Required(machineImagesPath, "must provide at least one machine image"))
	}
	for i, machineImage := range cloudProfile.MachineImages {
		idxPath := machineImagesPath.Index(i)

		if len(machineImage.Name) == 0 {
			allErrs = append(allErrs, field.Required(idxPath.Child("name"), "must provide a name"))
		}

		if len(machineImage.Versions) == 0 {
			allErrs = append(allErrs, field.Required(idxPath.Child("versions"), fmt.Sprintf("must provide at least one version for machine image %q", machineImage.Name)))
		}
		for j, version := range machineImage.Versions {
			jdxPath := idxPath.Child("versions").Index(j)

			if len(version.Version) == 0 {
				allErrs = append(allErrs, field.Required(jdxPath.Child("version"), "must provide a version"))
			}

			if len(version.Regions) == 0 {
				allErrs = append(allErrs, field.Required(jdxPath.Child("regions"), fmt.Sprintf("must provide at least one region for machine image %q and version %q", machineImage.Name, version.Version)))
			}
			for k, region := range version.Regions {
				kdxPath := jdxPath.Child("regions").Index(k)

				if len(region.Name) == 0 {
					allErrs = append(allErrs, field.Required(kdxPath.Child("name"), "must provide a name"))
				}
				if len(region.AMI) == 0 {
					allErrs = append(allErrs, field.Required(kdxPath.Child("ami"), "must provide an ami"))
				}
				if !slices.Contains(v1beta1constants.ValidArchitectures, *region.Architecture) {
					allErrs = append(allErrs, field.NotSupported(kdxPath.Child("architecture"), *region.Architecture, v1beta1constants.ValidArchitectures))
				}
			}
		}
	}

	return allErrs
}
