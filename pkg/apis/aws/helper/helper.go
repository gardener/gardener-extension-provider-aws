// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"fmt"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"k8s.io/utils/pointer"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
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

// FindMachineImage takes a list of machine images and tries to find the first entry
// whose name, version, architecture and zone matches with the given name, version, architecture and region. If no such entry is
// found then an error will be returned.
func FindMachineImage(machineImages []api.MachineImage, name, version string, arch *string) (*api.MachineImage, error) {
	for _, machineImage := range machineImages {
		if machineImage.Architecture == nil {
			machineImage.Architecture = pointer.String(v1beta1constants.ArchitectureAMD64)
		}
		if machineImage.Name == name && machineImage.Version == version && pointer.StringEqual(arch, machineImage.Architecture) {
			return &machineImage, nil
		}
	}
	return nil, fmt.Errorf("no machine image found with name %q, architecture %q and version %q", name, *arch, version)
}

// FindAMIForRegionFromCloudProfile takes a list of machine images, and the desired image name, version, architecture and region. It tries
// to find the image with the given name, architecture and version in the desired region. If it cannot be found then an error
// is returned.
func FindAMIForRegionFromCloudProfile(cloudProfileConfig *api.CloudProfileConfig, imageName, imageVersion, regionName string, arch *string) (string, error) {
	if cloudProfileConfig != nil {
		for _, machineImage := range cloudProfileConfig.MachineImages {
			if machineImage.Name != imageName {
				continue
			}
			for _, version := range machineImage.Versions {
				if imageVersion != version.Version {
					continue
				}
				for _, mapping := range version.Regions {
					if regionName == mapping.Name && pointer.StringEqual(arch, mapping.Architecture) {
						return mapping.AMI, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("could not find an AMI for region %q, name %q and architecture %q in version %q", regionName, imageName, *arch, imageVersion)
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
