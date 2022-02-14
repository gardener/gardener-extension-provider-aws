// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helper_test

import (
	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Helper", func() {
	DescribeTable("#FindInstanceProfileForPurpose",
		func(instanceProfiles []api.InstanceProfile, purpose string, expectedInstanceProfile *api.InstanceProfile, expectErr bool) {
			instanceProfile, err := FindInstanceProfileForPurpose(instanceProfiles, purpose)
			expectResults(instanceProfile, expectedInstanceProfile, err, expectErr)
		},

		Entry("list is nil", nil, "foo", nil, true),
		Entry("empty list", []api.InstanceProfile{}, "foo", nil, true),
		Entry("entry not found", []api.InstanceProfile{{Name: "bar", Purpose: "baz"}}, "foo", nil, true),
		Entry("entry exists", []api.InstanceProfile{{Name: "bar", Purpose: "baz"}}, "baz", &api.InstanceProfile{Name: "bar", Purpose: "baz"}, false),
	)

	DescribeTable("#FindRoleForPurpose",
		func(roles []api.Role, purpose string, expectedRole *api.Role, expectErr bool) {
			role, err := FindRoleForPurpose(roles, purpose)
			expectResults(role, expectedRole, err, expectErr)
		},

		Entry("list is nil", nil, "foo", nil, true),
		Entry("empty list", []api.Role{}, "foo", nil, true),
		Entry("entry not found", []api.Role{{ARN: "bar", Purpose: "baz"}}, "foo", nil, true),
		Entry("entry exists", []api.Role{{ARN: "bar", Purpose: "baz"}}, "baz", &api.Role{ARN: "bar", Purpose: "baz"}, false),
	)

	DescribeTable("#FindSecurityGroupForPurpose",
		func(securityGroups []api.SecurityGroup, purpose string, expectedSecurityGroup *api.SecurityGroup, expectErr bool) {
			securityGroup, err := FindSecurityGroupForPurpose(securityGroups, purpose)
			expectResults(securityGroup, expectedSecurityGroup, err, expectErr)
		},

		Entry("list is nil", nil, "foo", nil, true),
		Entry("empty list", []api.SecurityGroup{}, "foo", nil, true),
		Entry("entry not found", []api.SecurityGroup{{ID: "bar", Purpose: "baz"}}, "foo", nil, true),
		Entry("entry exists", []api.SecurityGroup{{ID: "bar", Purpose: "baz"}}, "baz", &api.SecurityGroup{ID: "bar", Purpose: "baz"}, false),
	)

	DescribeTable("#FindSubnetForPurposeAndZone",
		func(subnets []api.Subnet, purpose, zone string, expectedSubnet *api.Subnet, expectErr bool) {
			subnet, err := FindSubnetForPurposeAndZone(subnets, purpose, zone)
			expectResults(subnet, expectedSubnet, err, expectErr)
		},

		Entry("list is nil", nil, "foo", "europe", nil, true),
		Entry("empty list", []api.Subnet{}, "foo", "europe", nil, true),
		Entry("entry not found (no purpose)", []api.Subnet{{ID: "bar", Purpose: "baz", Zone: "europe"}}, "foo", "europe", nil, true),
		Entry("entry not found (no zone)", []api.Subnet{{ID: "bar", Purpose: "baz", Zone: "europe"}}, "foo", "asia", nil, true),
		Entry("entry exists", []api.Subnet{{ID: "bar", Purpose: "baz", Zone: "europe"}}, "baz", "europe", &api.Subnet{ID: "bar", Purpose: "baz", Zone: "europe"}, false),
	)

	DescribeTable("#FindMachineImage",
		func(machineImages []api.MachineImage, name, version string, expectedMachineImage *api.MachineImage, expectErr bool) {
			machineImage, err := FindMachineImage(machineImages, name, version)
			expectResults(machineImage, expectedMachineImage, err, expectErr)
		},

		Entry("list is nil", nil, "foo", "1.2.3", nil, true),
		Entry("empty list", []api.MachineImage{}, "foo", "1.2.3", nil, true),
		Entry("entry not found (no name)", []api.MachineImage{{Name: "bar", Version: "1.2.3"}}, "foo", "1.2.3", nil, true),
		Entry("entry not found (no version)", []api.MachineImage{{Name: "bar", Version: "1.2.3"}}, "foo", "1.2.3", nil, true),
		Entry("entry exists", []api.MachineImage{{Name: "bar", Version: "1.2.3"}}, "bar", "1.2.3", &api.MachineImage{Name: "bar", Version: "1.2.3"}, false),
	)

	DescribeTable("#FindAMIForRegion",
		func(profileImages []api.MachineImages, imageName, version, regionName, expectedAMI string) {
			cfg := &api.CloudProfileConfig{}
			cfg.MachineImages = profileImages
			ami, err := FindAMIForRegionFromCloudProfile(cfg, imageName, version, regionName)

			Expect(ami).To(Equal(expectedAMI))
			if expectedAMI != "" {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(HaveOccurred())
			}
		},

		Entry("list is nil", nil, "ubuntu", "1", "europe", ""),

		Entry("profile empty list", []api.MachineImages{}, "ubuntu", "1", "europe", ""),
		Entry("profile entry not found (image does not exist)", makeProfileMachineImages("debian", "1", "europe", "0"), "ubuntu", "1", "europe", ""),
		Entry("profile entry not found (version does not exist)", makeProfileMachineImages("ubuntu", "2", "europe", "0"), "ubuntu", "1", "europe", ""),
		Entry("profile entry", makeProfileMachineImages("ubuntu", "1", "europe", "ami-1234"), "ubuntu", "1", "europe", "ami-1234"),
		Entry("profile non matching region", makeProfileMachineImages("ubuntu", "1", "europe", "ami-1234"), "ubuntu", "1", "china", ""),
	)

	DescribeTable("#FindDataVolumeByName",
		func(dataVolumes []api.DataVolume, name string, expectedDataVolume *api.DataVolume) {
			Expect(FindDataVolumeByName(dataVolumes, name)).To(Equal(expectedDataVolume))
		},

		Entry("list is nil", nil, "foo", nil),
		Entry("list is empty", []api.DataVolume{}, "foo", nil),
		Entry("volume not found", []api.DataVolume{{Name: "bar"}}, "foo", nil),
		Entry("volume found (single entry)", []api.DataVolume{{Name: "foo"}}, "foo", &api.DataVolume{Name: "foo"}),
		Entry("volume found (multiple entries)", []api.DataVolume{{Name: "bar"}, {Name: "foo"}, {Name: "baz"}}, "foo", &api.DataVolume{Name: "foo"}),
	)
})

func makeProfileMachineImages(name, version, region, ami string) []api.MachineImages {
	versions := []api.MachineImageVersion{
		{
			Version: version,
			Regions: []api.RegionAMIMapping{
				{
					Name: region,
					AMI:  ami,
				},
			},
		},
	}

	return []api.MachineImages{
		{
			Name:     name,
			Versions: versions,
		},
	}
}

func expectResults(result, expected interface{}, err error, expectErr bool) {
	if !expectErr {
		Expect(result).To(Equal(expected))
		Expect(err).NotTo(HaveOccurred())
	} else {
		Expect(result).To(BeNil())
		Expect(err).To(HaveOccurred())
	}
}
