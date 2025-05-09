// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"maps"
	"slices"

	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/utils"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateCloudProfileConfig validates a CloudProfileConfig object.
func ValidateCloudProfileConfig(cloudProfile *apisaws.CloudProfileConfig, machineImages []core.MachineImage, capabilitiesDefinition core.Capabilities, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	machineImagesPath := fldPath.Child("machineImages")
	if len(cloudProfile.MachineImages) == 0 {
		allErrs = append(allErrs, field.Required(machineImagesPath, "must provide at least one machine image"))
	}
	for i, machineImage := range cloudProfile.MachineImages {
		idxPath := machineImagesPath.Index(i)
		allErrs = append(allErrs, ValidateProviderMachineImage(idxPath, machineImage, capabilitiesDefinition)...)
	}
	allErrs = append(allErrs, validateMachineImageMapping(machineImages, cloudProfile, capabilitiesDefinition, field.NewPath("spec").Child("machineImages"))...)

	return allErrs
}

// ValidateProviderMachineImage validates a CloudProfileConfig MachineImages entry.
func ValidateProviderMachineImage(validationPath *field.Path, machineImage apisaws.MachineImages, capabilitiesDefinition core.Capabilities) field.ErrorList {
	allErrs := field.ErrorList{}
	hasCloudProfileCapabilities := len(capabilitiesDefinition) > 0

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

		if hasCloudProfileCapabilities {
			for k, capabilitySet := range version.CapabilitySets {
				kdxPath := jdxPath.Child("capabilitySets").Index(k)
				allErrs = append(allErrs, ValidateCapabilities(capabilitySet.Capabilities, capabilitiesDefinition, kdxPath.Child("capabilities"))...)
				allErrs = append(allErrs, validateRegions(capabilitySet.Regions, machineImage.Name, version.Version, hasCloudProfileCapabilities, kdxPath)...)
			}
			if len(version.Regions) > 0 {
				allErrs = append(allErrs, field.Forbidden(jdxPath.Child("regions"), "must not be set as CloudProfile defines capabilities. Use capabilitySets.regions instead."))
			}
		} else {
			allErrs = append(allErrs, validateRegions(version.Regions, machineImage.Name, version.Version, hasCloudProfileCapabilities, jdxPath)...)
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
		} else {
			if region.Architecture != nil {
				allErrs = append(allErrs, field.Forbidden(kdxPath.Child("architecture"), "must be defined in ..capabilities.architecture"+*region.Architecture))
			}
		}
	}
	return allErrs
}

// NewProviderImagesContext creates a new ImagesContext for provider images.
func NewProviderImagesContext(providerImages []apisaws.MachineImages) *util.ImagesContext[apisaws.MachineImages, apisaws.MachineImageVersion] {
	return util.NewImagesContext(
		utils.CreateMapFromSlice(providerImages, func(mi apisaws.MachineImages) string { return mi.Name }),
		func(mi apisaws.MachineImages) map[string]apisaws.MachineImageVersion {
			return utils.CreateMapFromSlice(mi.Versions, func(v apisaws.MachineImageVersion) string { return v.Version })
		},
	)
}

// validateMachineImageMapping validates that for each machine image there is a corresponding cpConfig image.
func validateMachineImageMapping(machineImages []core.MachineImage, cpConfig *apisaws.CloudProfileConfig, capabilitiesDefinition core.Capabilities, fldPath *field.Path) field.ErrorList {
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

			if len(capabilitiesDefinition) > 0 {
				// check that each CapabilitySet in version.CapabilitySets has a corresponding imageVersion.CapabilitySets
				imageVersion, exists := providerImages.GetImageVersion(machineImage.Name, version.Version)
				if !exists {
					allErrs = append(allErrs, field.Required(machineImageVersionPath,
						fmt.Sprintf("machine image version %s@%s is not defined in the providerConfig",
							machineImage.Name, version.Version),
					))
					continue
				}

				versionCapabilitySets := GetVersionCapabilitySets(version, capabilitiesDefinition)

				for idxCapability, coreCapabilitySet := range versionCapabilitySets {
					isFound := false
					// search for the corresponding imageVersion.CapabilitySet
					for _, providerCapabilitySet := range imageVersion.CapabilitySets {
						if AreCapabilitiesEqual(coreCapabilitySet.Capabilities, providerCapabilitySet.Capabilities, capabilitiesDefinition) {
							isFound = true
						}
					}
					if !isFound {
						allErrs = append(allErrs, field.Required(machineImageVersionPath.Child("capabilitySets").Index(idxCapability),
							fmt.Sprintf("missing providerConfig mapping for machine image version %s@%s and capabilitySet %v",
								machineImage.Name, version.Version, coreCapabilitySet.Capabilities)))
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

// GetVersionCapabilitySets returns the capability for a given machine image version and adds the default capabilitySet if applicable.
func GetVersionCapabilitySets(version core.MachineImageVersion, capabilitiesDefinition core.Capabilities) []core.CapabilitySet {
	versionCapabilitySets := version.CapabilitySets
	if len(version.CapabilitySets) == 0 {
		// It is allowed not to define capabilitySets in the machine image version if there is only one architecture
		// if so the capabilityDefinition is used as default
		if len(capabilitiesDefinition[v1beta1constants.ArchitectureName]) == 1 {
			versionCapabilitySets = []core.CapabilitySet{{Capabilities: capabilitiesDefinition}}
		}
	}
	return versionCapabilitySets
}

// SetDefaultCapabilities sets the default capabilities based on a capabilitiesDefinition for a machine type or machine image.
func SetDefaultCapabilities(capabilities, capabilitiesDefinition core.Capabilities) core.Capabilities {
	if len(capabilities) == 0 {
		capabilities = make(core.Capabilities)
	}

	for key, values := range capabilitiesDefinition {
		if _, exists := capabilities[key]; !exists {
			capabilities[key] = values
		}
	}

	return capabilities
}

// ValidateCapabilities validates the capabilities of a machine type or machine image.
// It checks if the capabilities are supported by the cloud profile and if the architecture is defined correctly.
// It returns a list of field errors if any validation fails.
// THIS FUNCTION SHOULD BE MOVED TO GARDENER CORE AS IT WILL BE USED BY OTHER PROVIDERS AS WELL
func ValidateCapabilities(capabilities core.Capabilities, capabilitiesDefinition core.Capabilities, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	supportedCapabilityKeys := slices.Collect(maps.Keys(capabilitiesDefinition))

	for capabilityKey, capability := range capabilities {
		supportedValues, keyExists := capabilitiesDefinition[capabilityKey]
		if !keyExists {
			allErrs = append(allErrs, field.NotSupported(fldPath, capabilityKey, supportedCapabilityKeys))
			continue
		}
		for i, value := range capability {
			if !slices.Contains(supportedValues, value) {
				allErrs = append(allErrs, field.NotSupported(fldPath.Child(capabilityKey).Index(i), value, supportedValues))
			}
		}
	}

	// Check additional requirements for architecture
	//  must be defined when multiple architectures are supported by the cloud profile
	supportedArchitectures := capabilitiesDefinition[v1beta1constants.ArchitectureName]
	architectures := capabilities[v1beta1constants.ArchitectureName]
	if len(supportedArchitectures) > 1 && len(architectures) != 1 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child(v1beta1constants.ArchitectureName), architectures, "must define exactly one architecture when multiple architectures are supported by the cloud profile"))
	}

	return allErrs
}

// AreCapabilitiesEqual checks if two capabilities are equal.
// It compares the keys and values of the capabilities maps.
// THIS FUNCTION SHOULD BE MOVED TO GARDENER CORE AS IT WILL BE USED BY OTHER PROVIDERS AS WELL
func AreCapabilitiesEqual(a, b, capabilitiesDefinition core.Capabilities) bool {
	a = SetDefaultCapabilities(a, capabilitiesDefinition)
	b = SetDefaultCapabilities(b, capabilitiesDefinition)
	for key, valuesA := range a {
		valuesB, exists := b[key]
		if !exists || len(valuesA) != len(valuesB) {
			return false
		}
		for _, value := range valuesA {
			if !slices.Contains(valuesB, value) {
				return false
			}
		}
	}
	return true
}

// CapabilityDefinitionsToCapabilities takes the capability definitions and converts them to capabilities.
func CapabilityDefinitionsToCapabilities(capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) gardencorev1beta1.Capabilities {
	if len(capabilityDefinitions) == 0 {
		return nil
	}
	capabilities := make(gardencorev1beta1.Capabilities, len(capabilityDefinitions))
	for _, capability := range capabilityDefinitions {
		capabilities[capability.Name] = capability.Values
	}
	return capabilities
}
