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
	capabilityDefinitions []gardencorev1beta1.CapabilityDefinition,
) (*api.MachineImageFlavor, error) {
	if cloudProfileConfig == nil {
		return nil, fmt.Errorf("cloud profile config is nil")
	}
	machineImages := cloudProfileConfig.MachineImages

	capabilitySet, err := findCapabilitySetFromMachineImages(machineImages, name, version, region, arch, machineCapabilities, capabilityDefinitions)
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

func findCapabilitySetFromMachineImages(
	machineImages []api.MachineImages,
	imageName, imageVersion, region string,
	arch *string,
	machineCapabilities gardencorev1beta1.Capabilities,
	capabilityDefinitions []gardencorev1beta1.CapabilityDefinition,
) (*api.MachineImageFlavor, error) {
	for _, machineImage := range machineImages {
		if machineImage.Name != imageName {
			continue
		}
		for _, version := range machineImage.Versions {
			if imageVersion != version.Version {
				continue
			}

			if len(capabilityDefinitions) == 0 {
				for _, mapping := range version.Regions {
					if region == mapping.Name && ptr.Equal(arch, mapping.Architecture) {
						return &api.MachineImageFlavor{
							Regions:      []api.RegionAMIMapping{mapping},
							Capabilities: gardencorev1beta1.Capabilities{},
						}, nil
					}
				}
				continue
			}

			filteredCapabilityFlavors := filterCapabilityFlavorsByRegion(version.CapabilityFlavors, region)
			bestMatch, err := worker.FindBestImageFlavor(filteredCapabilityFlavors, machineCapabilities, capabilityDefinitions)
			if err != nil {
				return nil, fmt.Errorf("could not determine best capabilitySet %w", err)
			}

			return bestMatch, nil
		}
	}
	return nil, nil
}

// filterCapabilityFlavorsByRegion returns a new list with capabilityFlavors that only contain RegionAMIMappings
// of the region to filter for.
func filterCapabilityFlavorsByRegion(capabilityFlavors []api.MachineImageFlavor, regionName string) []*api.MachineImageFlavor {
	var compatibleSets []*api.MachineImageFlavor

	for _, capabilitySet := range capabilityFlavors {
		var regionAMIMapping *api.RegionAMIMapping
		for _, region := range capabilitySet.Regions {
			if region.Name == regionName {
				regionAMIMapping = &region
			}
		}
		if regionAMIMapping != nil {
			compatibleSets = append(compatibleSets, &api.MachineImageFlavor{
				Regions:      []api.RegionAMIMapping{*regionAMIMapping},
				Capabilities: capabilitySet.Capabilities,
			})
		}
	}
	return compatibleSets
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
