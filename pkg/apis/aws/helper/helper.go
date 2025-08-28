// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"fmt"
	"maps"
	"slices"

	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorehelper "github.com/gardener/gardener/pkg/apis/core/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

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

// FindImageInCloudProfile takes a list of machine images and tries to find the first entry
// whose name, version, region, architecture, capabilities and zone matches with the given ones. If no such entry is
// found then an error will be returned.
func FindImageInCloudProfile(
	cloudProfileConfig *api.CloudProfileConfig,
	name, version, region string,
	arch *string,
	machineCapabilities gardencorev1beta1.Capabilities,
	capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition,
) (*api.CapabilitySet, error) {
	if cloudProfileConfig == nil {
		return nil, fmt.Errorf("cloud profile config is nil")
	}
	machineImages := cloudProfileConfig.MachineImages

	capabilitySet, err := findCapabilitySetFromMachineImages(machineImages, name, version, region, arch, machineCapabilities, capabilitiesDefinitions)
	if err != nil {
		return nil, fmt.Errorf("could not find an AMI for region %q, image %q, version %q that supports %v: %w", region, name, version, machineCapabilities, err)
	}

	if capabilitySet != nil && len(capabilitySet.Regions) > 0 && capabilitySet.Regions[0].AMI != "" {
		return capabilitySet, nil
	}
	return nil, fmt.Errorf("could not find an AMI for region %q, image %q, version %q that supports %v", region, name, version, machineCapabilities)
}

// FindImageInWorkerStatus takes a list of machine images from the worker status and tries to find the first entry
// whose name, version, architecture, capabilities and zone matches with the given ones. If no such entry is
// found then an error will be returned.
func FindImageInWorkerStatus(machineImages []api.MachineImage, name string, version string, architecture *string, machineCapabilities gardencorev1beta1.Capabilities, capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition) (*api.MachineImage, error) {
	// If no capabilitiesDefinitions are specified, return the (legacy) architecture format field as no Capabilities are used.
	if len(capabilitiesDefinitions) == 0 {
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

	// If capabilitiesDefinitions are specified, we need to find the best matching capability set.
	for _, statusMachineImage := range machineImages {
		var statusMachineImageV1alpha1 v1alpha1.MachineImage
		if err := v1alpha1.Convert_aws_MachineImage_To_v1alpha1_MachineImage(&statusMachineImage, &statusMachineImageV1alpha1, nil); err != nil {
			return nil, fmt.Errorf("failed to convert machine image: %w", err)
		}
		if statusMachineImage.Name == name && statusMachineImage.Version == version && AreCapabilitiesCompatible(statusMachineImageV1alpha1.Capabilities, machineCapabilities, capabilitiesDefinitions) {
			return &statusMachineImage, nil
		}
	}
	return nil, fmt.Errorf("no machine image found for image %q with version %q and capabilities %v", name, version, machineCapabilities)
}

func findCapabilitySetFromMachineImages(
	machineImages []api.MachineImages,
	imageName, imageVersion, region string,
	arch *string,
	machineCapabilities gardencorev1beta1.Capabilities,
	capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition,
) (*api.CapabilitySet, error) {
	for _, machineImage := range machineImages {
		if machineImage.Name != imageName {
			continue
		}
		for _, version := range machineImage.Versions {
			if imageVersion != version.Version {
				continue
			}

			if len(capabilitiesDefinitions) == 0 {
				for _, mapping := range version.Regions {
					if region == mapping.Name && ptr.Equal(arch, mapping.Architecture) {
						return &api.CapabilitySet{
							Regions:      []api.RegionAMIMapping{mapping},
							Capabilities: core.Capabilities{},
						}, nil
					}
				}
				continue
			}

			bestMatch, err := FindBestCapabilitySet(version.CapabilitySets, machineCapabilities, capabilitiesDefinitions, region)
			if err != nil {
				return nil, fmt.Errorf("could not determine best capabilitySet %w", err)
			}

			return bestMatch, nil
		}
	}
	return nil, nil
}

// FindBestCapabilitySet finds the most appropriate capability set from the provided capability sets
// based on the requested machine capabilities and the definitions of capabilities.
func FindBestCapabilitySet(
	capabilitySets []api.CapabilitySet,
	machineCapabilities gardencorev1beta1.Capabilities,
	capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition,
	regionName string,
) (*api.CapabilitySet, error) {
	compatibleCapabilitySets, err := findCompatibleCapabilitySets(capabilitySets, machineCapabilities, capabilitiesDefinitions, regionName)
	if err != nil {
		return nil, err
	}

	if len(compatibleCapabilitySets) == 0 {
		return nil, fmt.Errorf("no compatible capability set found")
	}

	// Convert the slice of values to a slice of pointers
	compatiblePointers := make([]*api.CapabilitySet, len(compatibleCapabilitySets))
	for i := range compatibleCapabilitySets {
		compatiblePointers[i] = &compatibleCapabilitySets[i]
	}
	bestMatch, err := SelectBestCapabilitySet(compatiblePointers, capabilitiesDefinitions)
	if err != nil {
		return nil, err
	}
	return bestMatch, nil
}

// HasCapabilities defines an interface for types that contain Capabilities
type HasCapabilities interface {
	GetCapabilities() core.Capabilities
	SetCapabilities(core.Capabilities)
}

// TODO @Roncossek move this function gardener/gardener fpr reusability in other extensions

// SelectBestCapabilitySet selects the most appropriate capability set based on the priority
// of capabilities and their values as defined in capabilitiesDefinitions.
//
// Selection follows a priority-based approach:
// 1. Capabilities are ordered by priority in the definitions list (highest priority first)
// 2. Within each capability, values are ordered by preference (most preferred first)
// 3. Selection is determined by the first capability value difference found
func SelectBestCapabilitySet[T HasCapabilities](
	compatibleSets []T,
	capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition,
) (T, error) {
	var zeroValue T
	if len(compatibleSets) == 1 {
		return compatibleSets[0], nil
	}

	// Apply capability defaults for better comparison
	normalizedSets := make([]T, len(compatibleSets))
	copy(normalizedSets, compatibleSets)

	coreCapabilitiesDefinitions, err := GetCoreCapabilitiesDefinitions(capabilitiesDefinitions)
	if err != nil {
		return zeroValue, err
	}

	// Normalize capability sets by applying defaults
	for i := range normalizedSets {
		normalizedSets[i].SetCapabilities(gardencorehelper.GetCapabilitiesWithAppliedDefaults(
			normalizedSets[i].GetCapabilities(),
			coreCapabilitiesDefinitions,
		))
	}

	// Evaluate capability sets based on capability definitions priority
	remainingSets := normalizedSets

	// For each capability (in priority order)
	for _, capabilityDef := range capabilitiesDefinitions {
		// For each preferred value (in preference order)
		for _, capabilityValue := range capabilityDef.Values {
			var setsWithPreferredValue []T

			// Find sets that support this capability value
			for _, set := range remainingSets {
				if slices.Contains(set.GetCapabilities()[capabilityDef.Name], capabilityValue) {
					setsWithPreferredValue = append(setsWithPreferredValue, set)
				}
			}

			// If we found sets with this value, narrow down our selection
			if len(setsWithPreferredValue) > 0 {
				remainingSets = setsWithPreferredValue

				// If only one set remains, we've found our match
				if len(remainingSets) == 1 {
					return remainingSets[0], nil
				}
			}
		}
	}

	// If we couldn't determine a single best match, this indicates a problem with the cloud profile
	if len(remainingSets) != 1 {
		return zeroValue, fmt.Errorf("found multiple capability sets with identical capabilities; this indicates an invalid cloudprofile was admitted. Please open a bug report at https://github.com/gardener/gardener/issues")
	}

	return remainingSets[0], nil
}

// findCompatibleCapabilitySets returns all capability sets that are compatible with the given machine capabilities.
func findCompatibleCapabilitySets(
	capabilitySets []api.CapabilitySet,
	machineCapabilities gardencorev1beta1.Capabilities,
	capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition,
	regionName string,
) ([]api.CapabilitySet, error) {
	var compatibleSets []api.CapabilitySet

	for _, capabilitySet := range capabilitySets {
		var regionAMIMapping *api.RegionAMIMapping
		for _, region := range capabilitySet.Regions {
			if region.Name == regionName {
				regionAMIMapping = &region
			}
		}
		if regionAMIMapping == nil {
			continue
		}
		var v1alphaCapabilitySet v1alpha1.CapabilitySet
		err := v1alpha1.Convert_aws_CapabilitySet_To_v1alpha1_CapabilitySet(&capabilitySet, &v1alphaCapabilitySet, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to convert capability set: %w", err)
		}

		if AreCapabilitiesCompatible(v1alphaCapabilitySet.Capabilities, machineCapabilities, capabilitiesDefinitions) {
			compatibleSets = append(compatibleSets,
				api.CapabilitySet{
					Regions:      []api.RegionAMIMapping{*regionAMIMapping},
					Capabilities: capabilitySet.Capabilities,
				})
		}
	}
	return compatibleSets, nil
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

// AreCapabilitiesCompatible checks if two sets of capabilities are compatible.
// It applies defaults from the capability definitions to both sets before checking compatibility.
// TODO @Roncossek remove this function once the gardener-core is updated to a version that contains it.
// github.com/gardener/gardener/pkg/apis/core/v1beta1/helper
func AreCapabilitiesCompatible(capabilities1, capabilities2 gardencorev1beta1.Capabilities, capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition) bool {
	defaultedCapabilities1 := v1beta1helper.GetCapabilitiesWithAppliedDefaults(capabilities1, capabilitiesDefinitions)
	defaultedCapabilities2 := v1beta1helper.GetCapabilitiesWithAppliedDefaults(capabilities2, capabilitiesDefinitions)

	isSupported := true
	commonCapabilities := getCapabilitiesIntersection(defaultedCapabilities1, defaultedCapabilities2)
	// If the intersection has at least one value for each capability, the capabilities are supported.
	for _, values := range commonCapabilities {
		if len(values) == 0 {
			isSupported = false
			break
		}
	}

	return isSupported
}

// TODO @Roncossek remove this function once the gardener-core is updated to a version that contains it.
// github.com/gardener/gardener/pkg/apis/core/v1beta1/helper
func getCapabilitiesIntersection(capabilitiesList ...gardencorev1beta1.Capabilities) gardencorev1beta1.Capabilities {
	intersection := make(gardencorev1beta1.Capabilities)

	if len(capabilitiesList) == 0 {
		return intersection
	}

	// Initialize intersection with the first capabilities object
	maps.Copy(intersection, capabilitiesList[0])

	intersect := func(slice1, slice2 []string) []string {
		elementSet1 := sets.New(slice1...)
		elementSet2 := sets.New(slice2...)

		return elementSet1.Intersection(elementSet2).UnsortedList()
	}

	// Iterate through the remaining capabilities objects and refine the intersection
	for _, capabilities := range capabilitiesList[1:] {
		for key, values := range intersection {
			intersection[key] = intersect(values, capabilities[key])
		}
	}

	return intersection
}

// GetCoreCapabilitiesDefinitions function in the helper package.
// TODO @Roncossek remove this function once the gardener-core is updated to a version that contains it.
// GetCoreCapabilitiesDefinitions converts v1beta1.CapabilityDefinition objects to core.CapabilityDefinition objects.
// gardencorehelper "github.com/gardener/gardener/pkg/apis/core/helper"
func GetCoreCapabilitiesDefinitions(capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition) ([]core.CapabilityDefinition, error) {
	var coreCapabilitiesDefinitions []core.CapabilityDefinition
	for _, capabilityDefinition := range capabilitiesDefinitions {
		var coreCapabilityDefinition core.CapabilityDefinition
		err := gardencorev1beta1.Convert_v1beta1_CapabilityDefinition_To_core_CapabilityDefinition(&capabilityDefinition, &coreCapabilityDefinition, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to convert capability definition: %w", err)
		}
		coreCapabilitiesDefinitions = append(coreCapabilitiesDefinitions, coreCapabilityDefinition)
	}
	return coreCapabilitiesDefinitions, nil
}
