// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"maps"
	"slices"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencorehelper "github.com/gardener/gardener/pkg/apis/core/helper"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/utils"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateCloudProfileConfig validates a CloudProfileConfig object.
func ValidateCloudProfileConfig(cpConfig *apisaws.CloudProfileConfig, machineImages []core.MachineImage, capabilitiesDefinitions []core.CapabilityDefinition, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	machineImagesPath := fldPath.Child("machineImages")
	if len(cpConfig.MachineImages) == 0 {
		allErrs = append(allErrs, field.Required(machineImagesPath, "must provide at least one machine image"))
	}
	for i, machineImage := range cpConfig.MachineImages {
		idxPath := machineImagesPath.Index(i)
		allErrs = append(allErrs, ValidateProviderMachineImage(idxPath, machineImage, capabilitiesDefinitions)...)
	}
	allErrs = append(allErrs, validateMachineImageMapping(machineImages, cpConfig, capabilitiesDefinitions, field.NewPath("spec").Child("machineImages"))...)

	return allErrs
}

// ValidateProviderMachineImage validates a CloudProfileConfig MachineImages entry.
func ValidateProviderMachineImage(validationPath *field.Path, providerImage apisaws.MachineImages, capabilitiesDefinitions []core.CapabilityDefinition) field.ErrorList {
	allErrs := field.ErrorList{}
	hasCloudProfileCapabilities := len(capabilitiesDefinitions) > 0

	if len(providerImage.Name) == 0 {
		allErrs = append(allErrs, field.Required(validationPath.Child("name"), "must provide a name"))
	}

	if len(providerImage.Versions) == 0 {
		allErrs = append(allErrs, field.Required(validationPath.Child("versions"), fmt.Sprintf("must provide at least one version for machine image %q", providerImage.Name)))
	}
	for j, version := range providerImage.Versions {
		jdxPath := validationPath.Child("versions").Index(j)

		if len(version.Version) == 0 {
			allErrs = append(allErrs, field.Required(jdxPath.Child("version"), "must provide a version"))
		}

		if hasCloudProfileCapabilities {
			for k, capabilitySet := range version.CapabilitySets {
				kdxPath := jdxPath.Child("capabilitySets").Index(k)
				allErrs = append(allErrs, gutil.ValidateCapabilities(capabilitySet.Capabilities, capabilitiesDefinitions, kdxPath.Child("capabilities"))...)
				allErrs = append(allErrs, validateRegions(capabilitySet.Regions, providerImage.Name, version.Version, hasCloudProfileCapabilities, kdxPath)...)
			}
			if len(version.Regions) > 0 {
				allErrs = append(allErrs, field.Forbidden(jdxPath.Child("regions"), "must not be set as CloudProfile defines capabilities. Use capabilitySets.regions instead."))
			}
		} else {
			allErrs = append(allErrs, validateRegions(version.Regions, providerImage.Name, version.Version, hasCloudProfileCapabilities, jdxPath)...)
			if len(version.CapabilitySets) > 0 {
				allErrs = append(allErrs, field.Forbidden(jdxPath.Child("capabilitySets"), "must not be set as CloudProfile does not define capabilities. Use regions instead."))
			}
		}
	}

	return allErrs
}

func validateRegions(regions []apisaws.RegionAMIMapping, version, name string, hasCloudProfileCapabilities bool, jdxPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if len(regions) == 0 {
		return append(allErrs, field.Required(jdxPath.Child("regions"), fmt.Sprintf("must provide at least one region for machine image %q and version %q", name, version)))
	}

	for k, region := range regions {
		kdxPath := jdxPath.Child("regions").Index(k)
		arch := ptr.Deref(region.Architecture, v1beta1constants.ArchitectureAMD64)

		if len(region.Name) == 0 {
			allErrs = append(allErrs, field.Required(kdxPath.Child("name"), "must provide a name"))
		}
		if len(region.AMI) == 0 {
			allErrs = append(allErrs, field.Required(kdxPath.Child("ami"), "must provide an ami"))
		}
		if !hasCloudProfileCapabilities {
			if !slices.Contains(v1beta1constants.ValidArchitectures, arch) {
				allErrs = append(allErrs, field.NotSupported(kdxPath.Child("architecture"), arch, v1beta1constants.ValidArchitectures))
			}
		}
		// This should be commented in once the defaulting of the architecture field is implemented via mutating webhook
		// currently there is no way to distinguish between a user set architecture and the default one
		if hasCloudProfileCapabilities {
			// If Capabilities are defined in the CloudProfile, the architecture gets defaulted to "ignore" during runtime if not set.
			architecture := ptr.Deref(region.Architecture, "ignore")
			if architecture != "ignore" {
				allErrs = append(allErrs, field.Forbidden(kdxPath.Child("architecture"), "must be defined in .capabilities.architecture"+architecture))
			}
		}
	}
	return allErrs
}

// NewProviderImagesContext creates a new ImagesContext for provider images.
func NewProviderImagesContext(providerImages []apisaws.MachineImages) *gutil.ImagesContext[apisaws.MachineImages, apisaws.MachineImageVersion] {
	return gutil.NewImagesContext(
		utils.CreateMapFromSlice(providerImages, func(mi apisaws.MachineImages) string { return mi.Name }),
		func(mi apisaws.MachineImages) map[string]apisaws.MachineImageVersion {
			return utils.CreateMapFromSlice(mi.Versions, func(v apisaws.MachineImageVersion) string { return v.Version })
		},
	)
}

// validateMachineImageMapping validates that for each machine image there is a corresponding cpConfig image.
func validateMachineImageMapping(machineImages []core.MachineImage, cpConfig *apisaws.CloudProfileConfig, capabilitiesDefinitions []core.CapabilityDefinition, fldPath *field.Path) field.ErrorList {
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

			if len(capabilitiesDefinitions) > 0 {
				// check that each CapabilitySet in version.CapabilitySets has a corresponding imageVersion.CapabilitySets
				imageVersion, exists := providerImages.GetImageVersion(machineImage.Name, version.Version)
				if !exists {
					allErrs = append(allErrs, field.Required(machineImageVersionPath,
						fmt.Sprintf("machine image version %s@%s is not defined in the providerConfig",
							machineImage.Name, version.Version),
					))
					continue
				}

				coreDefaultedCapabilitySets := gardencorehelper.GetCapabilitySetsWithAppliedDefaults(version.CapabilitySets, capabilitiesDefinitions)

				for idxCapability, coreDefaultedCapabilitySet := range coreDefaultedCapabilitySets {
					isFound := false
					// search for the corresponding imageVersion.CapabilitySet
					for _, providerCapabilitySet := range imageVersion.CapabilitySets {
						providerDefaultedCapabilities := gardencorehelper.GetCapabilitiesWithAppliedDefaults(providerCapabilitySet.Capabilities, capabilitiesDefinitions)
						if gutil.AreCapabilitiesEqual(coreDefaultedCapabilitySet.Capabilities, providerDefaultedCapabilities) {
							isFound = true
						}
					}
					if !isFound {
						allErrs = append(allErrs, field.Required(machineImageVersionPath.Child("capabilitySets").Index(idxCapability),
							fmt.Sprintf("missing providerConfig mapping for machine image version %s@%s and capabilitySet %v",
								machineImage.Name, version.Version, coreDefaultedCapabilitySet.Capabilities)))
					}
				}
				continue
			}

			for _, expectedArchitecture := range version.Architectures {
				// validate that machine image version exists in cpConfig
				imageVersion, exists := providerImages.GetImageVersion(machineImage.Name, version.Version)
				if !exists {
					allErrs = append(allErrs, field.Required(machineImageVersionPath,
						fmt.Sprintf("machine image version %s@%s is not defined in the providerConfig",
							machineImage.Name, version.Version),
					))
					continue
				}
				// validate machine image version architectures
				if !slices.Contains(v1beta1constants.ValidArchitectures, expectedArchitecture) {
					allErrs = append(allErrs, field.NotSupported(
						machineImageVersionPath.Child("architectures"),
						expectedArchitecture, v1beta1constants.ValidArchitectures))
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
