// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"maps"
	"slices"

	"github.com/gardener/gardener/pkg/apis/core"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/pkg/utils/gardener"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateCloudProfileConfig validates a CloudProfileConfig object.
func ValidateCloudProfileConfig(cloudProfile *apisaws.CloudProfileConfig, machineImages []core.MachineImage, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	machineImagesPath := fldPath.Child("machineImages")
	if len(cloudProfile.MachineImages) == 0 {
		allErrs = append(allErrs, field.Required(machineImagesPath, "must provide at least one machine image"))
	}
	for i, machineImage := range cloudProfile.MachineImages {
		idxPath := machineImagesPath.Index(i)
		allErrs = append(allErrs, ValidateProviderMachineImage(idxPath, machineImage)...)
	}
	allErrs = append(allErrs, validateMachineImageMapping(machineImages, cloudProfile, field.NewPath("spec").Child("machineImages"))...)

	return allErrs
}

// ValidateProviderMachineImage validates a CloudProfileConfig MachineImages entry.
func ValidateProviderMachineImage(validationPath *field.Path, machineImage apisaws.MachineImages) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(machineImage.Name) == 0 {
		allErrs = append(allErrs, field.Required(validationPath.Child("name"), "must provide a name"))
	}

	if len(machineImage.Versions) == 0 {
		allErrs = append(allErrs, field.Required(validationPath.Child("versions"), fmt.Sprintf("must provide at least one version for machine image %q", machineImage.Name)))
	}
	for j, version := range machineImage.Versions {
		jdxPath := validationPath.Child("versions").Index(j)

		if len(version.Version) == 0 {
			allErrs = append(allErrs, field.Required(jdxPath.Child("version"), "must provide a version"))
		}

		if len(version.Regions) == 0 {
			allErrs = append(allErrs, field.Required(jdxPath.Child("regions"), fmt.Sprintf("must provide at least one region for machine image %q and version %q", machineImage.Name, version.Version)))
		}
		for k, region := range version.Regions {
			kdxPath := jdxPath.Child("regions").Index(k)
			arch := ptr.Deref(region.Architecture, v1beta1constants.ArchitectureAMD64)

			if len(region.Name) == 0 {
				allErrs = append(allErrs, field.Required(kdxPath.Child("name"), "must provide a name"))
			}
			if len(region.AMI) == 0 {
				allErrs = append(allErrs, field.Required(kdxPath.Child("ami"), "must provide an ami"))
			}
			if !slices.Contains(v1beta1constants.ValidArchitectures, arch) {
				allErrs = append(allErrs, field.NotSupported(kdxPath.Child("architecture"), arch, v1beta1constants.ValidArchitectures))
			}
		}
	}

	return allErrs
}

// NewProviderImagesContext creates a new ImagesContext for provider images.
func NewProviderImagesContext(providerImages []apisaws.MachineImages) *gardener.ImagesContext[apisaws.MachineImages, apisaws.MachineImageVersion] {
	return gardener.NewImagesContext(
		utils.CreateMapFromSlice(providerImages, func(mi apisaws.MachineImages) string { return mi.Name }),
		func(mi apisaws.MachineImages) map[string]apisaws.MachineImageVersion {
			return utils.CreateMapFromSlice(mi.Versions, func(v apisaws.MachineImageVersion) string { return v.Version })
		},
	)
}

// validateMachineImageMapping validates that for each machine image there is a corresponding cpConfig image.
func validateMachineImageMapping(machineImages []core.MachineImage, cpConfig *apisaws.CloudProfileConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	providerImages := NewProviderImagesContext(cpConfig.MachineImages)

	// validate machine images
	for idxImage, machineImage := range machineImages {
		if len(machineImage.Versions) == 0 {
			continue
		}
		machineImagePath := fldPath.Index(idxImage)
		// validate that for each machine image there is a corresponding cpConfig image
		if _, existsInConfig := providerImages.GetImage(machineImage.Name); !existsInConfig {
			allErrs = append(allErrs, field.Required(machineImagePath,
				fmt.Sprintf("must provide an image mapping for image %q in providerConfig", machineImage.Name)))
			continue
		}
		// validate that for each machine image version entry a mapped entry in cpConfig exists
		for idxVersion, version := range machineImage.Versions {
			machineImageVersionPath := machineImagePath.Child("versions").Index(idxVersion)
			for _, expectedArchitecture := range version.Architectures {
				// validate machine image version architectures
				if !slices.Contains(v1beta1constants.ValidArchitectures, expectedArchitecture) {
					allErrs = append(allErrs, field.NotSupported(
						machineImageVersionPath.Child("architectures"),
						expectedArchitecture, v1beta1constants.ValidArchitectures))
				}
				// validate that machine image version exists in cpConfig
				imageVersion, exists := providerImages.GetImageVersion(machineImage.Name, version.Version)
				if !exists {
					allErrs = append(allErrs, field.Required(machineImageVersionPath,
						fmt.Sprintf("machine image version %s@%s is not defined in the providerConfig",
							machineImage.Name, version.Version),
					))
					continue
				}
				// validate that machine image version with architecture x exists in cpConfig
				architecturesMap := utils.CreateMapFromSlice(imageVersion.Regions, func(re apisaws.RegionAMIMapping) string {
					return ptr.Deref(re.Architecture, v1beta1constants.ArchitectureAMD64)
				})
				architectures := slices.Collect(maps.Keys(architecturesMap))
				if !slices.Contains(architectures, expectedArchitecture) {
					allErrs = append(allErrs, field.Required(machineImageVersionPath,
						fmt.Sprintf("missing providerConfig mapping for machine image version %s@%s and architecture: %s",
							machineImage.Name, version.Version, expectedArchitecture),
					))
					continue
				}
			}
		}
	}

	return allErrs
}
