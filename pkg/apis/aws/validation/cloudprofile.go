// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"maps"
	"slices"

	gardencoreapi "github.com/gardener/gardener/pkg/api"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"github.com/gardener/gardener/pkg/utils"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateCloudProfileConfig validates a CloudProfileConfig object.
func ValidateCloudProfileConfig(cpConfig *apisaws.CloudProfileConfig, machineImages []core.MachineImage, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	machineImagesPath := fldPath.Child("machineImages")

	// Validate machine images section
	allErrs = append(allErrs, validateMachineImages(cpConfig.MachineImages, capabilityDefinitions, machineImagesPath)...)

	// Validate machine image mappings
	allErrs = append(allErrs, validateMachineImageMapping(machineImages, cpConfig, capabilityDefinitions, field.NewPath("spec").Child("machineImages"))...)

	return allErrs
}

// validateMachineImages validates the machine images section of CloudProfileConfig
func validateMachineImages(machineImages []apisaws.MachineImages, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	// Ensure at least one machine image is provided
	if len(machineImages) == 0 {
		allErrs = append(allErrs, field.Required(fldPath, "must provide at least one machine image"))
		return allErrs
	}

	// Validate each machine image
	for i, machineImage := range machineImages {
		idxPath := fldPath.Index(i)
		allErrs = append(allErrs, ValidateProviderMachineImage(machineImage, capabilityDefinitions, idxPath)...)
	}

	return allErrs
}

// ValidateProviderMachineImage validates a CloudProfileConfig MachineImages entry.
func ValidateProviderMachineImage(providerImage apisaws.MachineImages, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, validationPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(providerImage.Name) == 0 {
		allErrs = append(allErrs, field.Required(validationPath.Child("name"), "must provide a name"))
	}

	if len(providerImage.Versions) == 0 {
		allErrs = append(allErrs, field.Required(validationPath.Child("versions"), fmt.Sprintf("must provide at least one version for machine image %q", providerImage.Name)))
	}

	// Validate each version
	for j, version := range providerImage.Versions {
		jdxPath := validationPath.Child("versions").Index(j)
		allErrs = append(allErrs, validateMachineImageVersion(providerImage, capabilityDefinitions, version, jdxPath)...)
	}

	return allErrs
}

// validateMachineImageVersion validates a specific machine image version
func validateMachineImageVersion(providerImage apisaws.MachineImages, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, version apisaws.MachineImageVersion, jdxPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(version.Version) == 0 {
		allErrs = append(allErrs, field.Required(jdxPath.Child("version"), "must provide a version"))
	}

	if len(capabilityDefinitions) > 0 {
		allErrs = append(allErrs, validateCapabilityFlavors(providerImage, version, capabilityDefinitions, jdxPath)...)
	} else {
		allErrs = append(allErrs, validateRegions(version.Regions, providerImage.Name, version.Version, capabilityDefinitions, jdxPath)...)
		if len(version.CapabilityFlavors) > 0 {
			allErrs = append(allErrs, field.Forbidden(jdxPath.Child("capabilityFlavors"), "must not be set as CloudProfile does not define capabilities. Use regions instead."))
		}
	}
	return allErrs
}

// validateCapabilityFlavors validates the capability flavors of a machine image version.
func validateCapabilityFlavors(providerImage apisaws.MachineImages, version apisaws.MachineImageVersion, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, jdxPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	// When using capabilities, regions must not be set
	if len(version.Regions) > 0 {
		allErrs = append(allErrs, field.Forbidden(jdxPath.Child("regions"), "must not be set as CloudProfile defines capabilities. Use capabilityFlavors.regions instead."))
	}

	// Validate each flavor's capabilities and regions
	for k, capabilitySet := range version.CapabilityFlavors {
		kdxPath := jdxPath.Child("capabilityFlavors").Index(k)
		allErrs = append(allErrs, gutil.ValidateCapabilities(capabilitySet.Capabilities, capabilityDefinitions, kdxPath.Child("capabilities"))...)
		allErrs = append(allErrs, validateRegions(capabilitySet.Regions, providerImage.Name, version.Version, capabilityDefinitions, kdxPath)...)
	}
	return allErrs
}

// validateRegions validates the regions of a machine image version or capability flavor.
func validateRegions(regions []apisaws.RegionAMIMapping, version, name string, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, jdxPath *field.Path) field.ErrorList {
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
		if len(capabilityDefinitions) == 0 {
			if !slices.Contains(v1beta1constants.ValidArchitectures, arch) {
				allErrs = append(allErrs, field.NotSupported(kdxPath.Child("architecture"), arch, v1beta1constants.ValidArchitectures))
			}
		}
		// This should be commented in once the defaulting of the architecture field is implemented via mutating webhook
		// currently there is no way to distinguish between a user set architecture and the default one
		if len(capabilityDefinitions) > 0 {
			// If Capabilities are defined in the CloudProfile, the architecture gets defaulted to "ignore" during runtime if not set.
			architecture := ptr.Deref(region.Architecture, "ignore")
			if architecture != "ignore" {
				allErrs = append(allErrs, field.Forbidden(kdxPath.Child("architecture"), "must be defined in .capabilities.architecture"))
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
func validateMachineImageMapping(machineImages []core.MachineImage, cpConfig *apisaws.CloudProfileConfig, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, fldPath *field.Path) field.ErrorList {
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
			allErrs = append(allErrs, field.Required(machineImagePath, fmt.Sprintf("must provide an image mapping for image %q in providerConfig", machineImage.Name)))
			continue
		}

		allErrs = append(allErrs, validateMachineImageVersionMapping(machineImage, machineImagePath, capabilityDefinitions, providerImages)...)
	}

	return allErrs
}

func validateMachineImageVersionMapping(machineImage core.MachineImage, machineImagePath *field.Path, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, providerImages *gutil.ImagesContext[apisaws.MachineImages, apisaws.MachineImageVersion]) field.ErrorList {
	allErrs := field.ErrorList{}

	// validate that for each machine image version entry a mapped entry in cpConfig exists
	for idxVersion, version := range machineImage.Versions {
		machineImageVersionPath := machineImagePath.Child("versions").Index(idxVersion)

		if len(capabilityDefinitions) > 0 {
			// check that each MachineImageFlavor in version.CapabilityFlavors has a corresponding imageVersion.CapabilityFlavors
			imageVersion, exists := providerImages.GetImageVersion(machineImage.Name, version.Version)
			if !exists {
				allErrs = append(allErrs, field.Required(machineImageVersionPath,
					fmt.Sprintf("machine image version %s@%s is not defined in the providerConfig",
						machineImage.Name, version.Version),
				))
				continue
			}
			allErrs = append(allErrs, validateImageFlavorMapping(machineImage, version, machineImageVersionPath, capabilityDefinitions, imageVersion)...)
		} else {
			for _, expectedArchitecture := range version.Architectures {
				// validate that machine image version exists in cpConfig
				imageVersion, exists := providerImages.GetImageVersion(machineImage.Name, version.Version)
				if !exists {
					allErrs = append(allErrs, field.Required(machineImageVersionPath,
						fmt.Sprintf("machine image version %s@%s is not defined in the providerConfig", machineImage.Name, version.Version)))
					continue
				}
				// validate machine image version architectures
				if !slices.Contains(v1beta1constants.ValidArchitectures, expectedArchitecture) {
					allErrs = append(allErrs, field.NotSupported(machineImageVersionPath.Child("architectures"), expectedArchitecture, v1beta1constants.ValidArchitectures))
				}

				// validate that machine image version with architecture x exists in cpConfig
				architecturesMap := utils.CreateMapFromSlice(imageVersion.Regions, func(re apisaws.RegionAMIMapping) string {
					return ptr.Deref(re.Architecture, v1beta1constants.ArchitectureAMD64)
				})

				architectures := slices.Collect(maps.Keys(architecturesMap))
				if !slices.Contains(architectures, expectedArchitecture) {
					allErrs = append(allErrs, field.Required(machineImageVersionPath,
						fmt.Sprintf("missing providerConfig mapping for machine image version %s@%s and architecture: %s", machineImage.Name, version.Version, expectedArchitecture)))
					continue
				}
			}
		}
	}
	return allErrs
}

// validateImageFlavorMapping validates that each flavor in a version has a corresponding mapping
func validateImageFlavorMapping(machineImage core.MachineImage, version core.MachineImageVersion, machineImageVersionPath *field.Path, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, imageVersion apisaws.MachineImageVersion) field.ErrorList {
	allErrs := field.ErrorList{}

	var v1beta1Version gardencorev1beta1.MachineImageVersion
	if err := gardencoreapi.Scheme.Convert(&version, &v1beta1Version, nil); err != nil {
		return append(allErrs, field.InternalError(machineImageVersionPath, err))
	}

	defaultedCapabilityFlavors := gardencorev1beta1helper.GetImageFlavorsWithAppliedDefaults(v1beta1Version.CapabilityFlavors, capabilityDefinitions)
	for idxCapability, defaultedCapabilitySet := range defaultedCapabilityFlavors {
		isFound := false
		// search for the corresponding imageVersion.MachineImageFlavor
		for _, providerCapabilitySet := range imageVersion.CapabilityFlavors {
			providerDefaultedCapabilities := gardencorev1beta1helper.GetCapabilitiesWithAppliedDefaults(providerCapabilitySet.Capabilities, capabilityDefinitions)
			if gardencorev1beta1helper.AreCapabilitiesEqual(defaultedCapabilitySet.Capabilities, providerDefaultedCapabilities) {
				isFound = true
				break
			}
		}
		if !isFound {
			allErrs = append(allErrs, field.Required(machineImageVersionPath.Child("capabilityFlavors").Index(idxCapability),
				fmt.Sprintf("missing providerConfig mapping for machine image version %s@%s and capabilitySet %v", machineImage.Name, version.Version, defaultedCapabilitySet.Capabilities)))
		}
	}
	return allErrs
}
