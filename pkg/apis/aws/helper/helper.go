// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/controller/worker"
	"github.com/gardener/gardener/extensions/pkg/util"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

// NormalizeCapabilityDefinitions ensures that capability definitions always include at least
// the architecture capability. This allows all downstream code to assume capabilities are always present,
// eliminating the need for conditional logic based on whether capabilities are defined.
func NormalizeCapabilityDefinitions(capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) []gardencorev1beta1.CapabilityDefinition {
	if len(capabilityDefinitions) > 0 {
		return capabilityDefinitions
	}
	return []gardencorev1beta1.CapabilityDefinition{{
		Name:   v1beta1constants.ArchitectureName,
		Values: []string{v1beta1constants.ArchitectureAMD64, v1beta1constants.ArchitectureARM64},
	}}
}

// NormalizeMachineTypeCapabilities ensures that machine type capabilities include the architecture
// capability. This transforms the legacy architecture-based selection into capability-based selection.
// The architecture is determined in the following priority order:
// 1. If capabilities already has architecture, use it as-is
// 2. If capabilityDefinitions has exactly one architecture value, use that value
// 3. Otherwise, use workerArchitecture (defaulting to amd64)
func NormalizeMachineTypeCapabilities(capabilities gardencorev1beta1.Capabilities, workerArchitecture *string, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) gardencorev1beta1.Capabilities {
	if capabilities == nil {
		capabilities = make(gardencorev1beta1.Capabilities)
	}
	// If architecture capability is already present, return as-is
	if _, hasArch := capabilities[v1beta1constants.ArchitectureName]; hasArch {
		return capabilities
	}

	// Check if capabilityDefinitions has exactly one architecture value
	for _, def := range capabilityDefinitions {
		if def.Name == v1beta1constants.ArchitectureName && len(def.Values) == 1 {
			capabilities[v1beta1constants.ArchitectureName] = []string{def.Values[0]}
			return capabilities
		}
	}

	// Fall back to workerArchitecture or default
	arch := ptr.Deref(workerArchitecture, v1beta1constants.ArchitectureAMD64)
	capabilities[v1beta1constants.ArchitectureName] = []string{arch}
	return capabilities
}

// FindInstanceProfileForPurpose takes a list of instance profiles and tries to find the first entry
// whose purpose matches with the given purpose. If no such entry is found then an error will be
// returned.
func FindInstanceProfileForPurpose(instanceProfiles []api.InstanceProfile, purpose string) (*api.InstanceProfile, error) {
	for _, instanceProfile := range instanceProfiles {
		if instanceProfile.Purpose == purpose {
			return &instanceProfile, nil
		}
	}
	return nil, fmt.Errorf("no instance profile with purpose %q found", purpose)
}

// FindRoleForPurpose takes a list of roles and tries to find the first entry
// whose purpose matches with the given purpose. If no such entry is found then an error will be
// returned.
func FindRoleForPurpose(roles []api.Role, purpose string) (*api.Role, error) {
	for _, role := range roles {
		if role.Purpose == purpose {
			return &role, nil
		}
	}
	return nil, fmt.Errorf("no role with purpose %q found", purpose)
}

// FindSecurityGroupForPurpose takes a list of security groups and tries to find the first entry
// whose purpose matches with the given purpose. If no such entry is found then an error will be
// returned.
func FindSecurityGroupForPurpose(securityGroups []api.SecurityGroup, purpose string) (*api.SecurityGroup, error) {
	for _, securityGroup := range securityGroups {
		if securityGroup.Purpose == purpose {
			return &securityGroup, nil
		}
	}
	return nil, fmt.Errorf("no security group with purpose %q found", purpose)
}

// FindSubnetForPurpose takes a list of subnets and tries to find the first entry
// whose purpose matches with the given purpose. If no such entry is found then
// an error will be returned.
func FindSubnetForPurpose(subnets []api.Subnet, purpose string) (*api.Subnet, error) {
	for _, subnet := range subnets {
		if subnet.Purpose == purpose {
			return &subnet, nil
		}
	}
	return nil, fmt.Errorf("no subnet with purpose %q found", purpose)
}

// FindSubnetForPurposeAndZone takes a list of subnets and tries to find the first entry
// whose purpose and zone matches with the given purpose and zone. If no such entry is found then
// an error will be returned.
func FindSubnetForPurposeAndZone(subnets []api.Subnet, purpose, zone string) (*api.Subnet, error) {
	for _, subnet := range subnets {
		if subnet.Purpose == purpose && subnet.Zone == zone {
			return &subnet, nil
		}
	}
	return nil, fmt.Errorf("no subnet with purpose %q in zone %q found", purpose, zone)
}

// FindImageInCloudProfile takes a list of machine images and tries to find the first entry whose name, version and capabilities
// matches with the machineTypeCapabilities. If no such entry is found then an error will be returned.
// Note: capabilityDefinitions and machineTypeCapabilities are expected to be normalized
// by the caller using NormalizeCapabilityDefinitions() and NormalizeMachineTypeCapabilities()
func FindImageInCloudProfile(
	cloudProfileConfig *api.CloudProfileConfig,
	name, version, region string,
	machineCapabilities gardencorev1beta1.Capabilities,
	capabilityDefinitions []gardencorev1beta1.CapabilityDefinition,
) (*api.MachineImageFlavor, error) {
	if cloudProfileConfig == nil {
		return nil, fmt.Errorf("cloud profile config is nil")
	}
	machineImages := cloudProfileConfig.MachineImages

	for _, machineImage := range machineImages {
		if machineImage.Name != name {
			continue
		}

		// Collect all versions with matching version string (mixed format support)
		var matchingVersions []api.MachineImageVersion
		for _, v := range machineImage.Versions {
			if version == v.Version {
				matchingVersions = append(matchingVersions, v)
			}
		}

		if len(matchingVersions) == 0 {
			continue
		}

		// Convert old format (regions with architecture) versions to capability flavors if required
		// as there may be multiple version entries for the same version with different architectures
		// the normalization for capability flavors is done here instead of the caller to keep the caller code simpler
		capabilityFlavors := convertLegacyVersionsToCapabilityFlavors(matchingVersions)

		// Filter capability flavors by region
		filteredCapabilityFlavors := filterCapabilityFlavorsByRegion(capabilityFlavors, region)

		if len(filteredCapabilityFlavors) > 0 {
			bestMatch, err := worker.FindBestImageFlavor(filteredCapabilityFlavors, machineCapabilities, capabilityDefinitions)
			if err != nil {
				return nil, fmt.Errorf("could not determine best flavor: %w", err)
			}
			return bestMatch, nil
		}
	}
	return nil, fmt.Errorf("could not find an AMI for region %q, image %q, version %q that supports %v", region, name, version, machineCapabilities)
}

// convertLegacyVersionsToCapabilityFlavors converts old format (regions with architecture) versions
// to capability flavors for mixed format support.
func convertLegacyVersionsToCapabilityFlavors(versions []api.MachineImageVersion) []api.MachineImageFlavor {
	var capabilityFlavors []api.MachineImageFlavor
	for _, version := range versions {
		if len(version.Regions) > 0 && len(version.CapabilityFlavors) == 0 {
			// Old format: regions with architecture - convert to capability flavors
			capabilityFlavors = append(capabilityFlavors, convertRegionsToCapabilityFlavors(version.Regions)...)
		} else {
			// New format: use capability flavors directly
			capabilityFlavors = append(capabilityFlavors, version.CapabilityFlavors...)
		}
	}
	return capabilityFlavors
}

// FindImageInWorkerStatus takes a list of machine images from the worker status and tries to find the first entry whose name, version, architecture
// capabilities and zone matches with the machineTypeCapabilities. If no such entry is found then an error will be returned.
func FindImageInWorkerStatus(machineImages []api.MachineImage, name string, version string, architecture *string, machineCapabilities gardencorev1beta1.Capabilities, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) (*api.MachineImage, error) {
	// If no capabilityDefinitions are specified, return the (legacy) architecture format field as no Capabilities are used.
	if len(capabilityDefinitions) == 0 {
		for _, statusMachineImage := range machineImages {
			if statusMachineImage.Architecture == nil {
				statusMachineImage.Architecture = ptr.To(v1beta1constants.ArchitectureAMD64)
			}
			if statusMachineImage.Name == name && statusMachineImage.Version == version && ptr.Equal(architecture, statusMachineImage.Architecture) {
				return &statusMachineImage, nil
			}
		}
		return nil, fmt.Errorf("no machine image found for image %q with version %q and architecture %q", name, version, *architecture)
	}

	// If capabilityDefinitions are specified, we need to find the best matching capability set.
	for _, statusMachineImage := range machineImages {
		var statusMachineImageV1alpha1 v1alpha1.MachineImage
		if err := v1alpha1.Convert_aws_MachineImage_To_v1alpha1_MachineImage(&statusMachineImage, &statusMachineImageV1alpha1, nil); err != nil {
			return nil, fmt.Errorf("failed to convert machine image: %w", err)
		}
		if statusMachineImage.Name == name && statusMachineImage.Version == version && gardencorev1beta1helper.AreCapabilitiesCompatible(statusMachineImageV1alpha1.Capabilities, machineCapabilities, capabilityDefinitions) {
			return &statusMachineImage, nil
		}
	}
	return nil, fmt.Errorf("no machine image found for image %q with version %q and capabilities %v", name, version, machineCapabilities)
}

// convertRegionsToCapabilityFlavors converts old format (regions with architecture) to capability flavors
func convertRegionsToCapabilityFlavors(regions []api.RegionAMIMapping) []api.MachineImageFlavor {
	// Group regions by architecture
	architectureRegions := make(map[string][]api.RegionAMIMapping)
	for _, region := range regions {
		arch := ptr.Deref(region.Architecture, v1beta1constants.ArchitectureAMD64)
		// Remove architecture field from region mapping when converting to capability flavors
		// as architecture is now expressed through the Capabilities field
		regionWithoutArch := api.RegionAMIMapping{
			Name: region.Name,
			AMI:  region.AMI,
		}
		architectureRegions[arch] = append(architectureRegions[arch], regionWithoutArch)
	}

	// Create a capability flavor for each architecture
	var capabilityFlavors []api.MachineImageFlavor
	for arch, regionMappings := range architectureRegions {
		capabilityFlavors = append(capabilityFlavors, api.MachineImageFlavor{
			Capabilities: gardencorev1beta1.Capabilities{
				v1beta1constants.ArchitectureName: []string{arch},
			},
			Regions: regionMappings,
		})
	}

	return capabilityFlavors
}

// filterCapabilityFlavorsByRegion returns a new list with capabilityFlavors that only contain RegionAMIMappings
// of the region to filter for.
func filterCapabilityFlavorsByRegion(capabilityFlavors []api.MachineImageFlavor, regionName string) []*api.MachineImageFlavor {
	var compatibleFlavors []*api.MachineImageFlavor

	for _, capabilityFlavor := range capabilityFlavors {
		var regionAMIMapping *api.RegionAMIMapping
		for _, region := range capabilityFlavor.Regions {
			if region.Name == regionName {
				regionAMIMapping = &region
			}
		}
		if regionAMIMapping != nil {
			compatibleFlavors = append(compatibleFlavors, &api.MachineImageFlavor{
				Regions:      []api.RegionAMIMapping{*regionAMIMapping},
				Capabilities: capabilityFlavor.Capabilities,
			})
		}
	}
	return compatibleFlavors
}

// FindDataVolumeByName takes a list of data volumes and a data volume name. It tries to find the data volume entry for
// the given name. If it cannot find it then `nil` will be returned.
func FindDataVolumeByName(dataVolumes []api.DataVolume, name string) *api.DataVolume {
	for _, dv := range dataVolumes {
		if dv.Name == name {
			return &dv
		}
	}
	return nil
}

// DecodeBackupBucketConfig decodes the `BackupBucketConfig` from the given `RawExtension`.
func DecodeBackupBucketConfig(decoder runtime.Decoder, config *runtime.RawExtension) (*api.BackupBucketConfig, error) {
	backupBucketConfig := &api.BackupBucketConfig{}

	if config != nil && config.Raw != nil {
		if err := util.Decode(decoder, config.Raw, backupBucketConfig); err != nil {
			return nil, err
		}
	}

	return backupBucketConfig, nil
}
