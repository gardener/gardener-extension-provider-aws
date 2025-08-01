// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper_test

import (
	"reflect"
	"time"

	"github.com/gardener/gardener/pkg/apis/core"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/ptr"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	apiv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
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
		func(machineImages []api.MachineImage, name, version string, arch *string, expectedMachineImage *api.MachineImage, expectErr bool) {
			machineImage, err := FindMachineImage(machineImages, name, version, arch)
			expectResults(machineImage, expectedMachineImage, err, expectErr)
		},

		Entry("list is nil", nil, "foo", "1.2.3", ptr.To("foo"), nil, true),
		Entry("empty list", []api.MachineImage{}, "foo", "1.2.3", ptr.To("foo"), nil, true),
		Entry("entry not found (no name)", []api.MachineImage{{Name: "bar", Version: "1.2.3"}}, "foo", "1.2.ś", ptr.To("foo"), nil, true),
		Entry("entry not found (no version)", []api.MachineImage{{Name: "bar", Version: "1.2.3"}}, "foo", "1.2.3", ptr.To("foo"), nil, true),
		Entry("entry not found (no architecture)", []api.MachineImage{{Name: "bar", Version: "1.2.3", Architecture: ptr.To("bar")}}, "foo", "1.2.3", ptr.To("foo"), nil, true),
		Entry("entry exists if architecture is nil", []api.MachineImage{{Name: "bar", Version: "1.2.3"}}, "bar", "1.2.3", ptr.To("amd64"), &api.MachineImage{Name: "bar", Version: "1.2.3", Architecture: ptr.To("amd64")}, false),
		Entry("entry exists", []api.MachineImage{{Name: "bar", Version: "1.2.3", Architecture: ptr.To("foo")}}, "bar", "1.2.3", ptr.To("foo"), &api.MachineImage{Name: "bar", Version: "1.2.3", Architecture: ptr.To("foo")}, false),
	)

	DescribeTable("#FindAMIForRegion",
		func(profileImages []api.MachineImages, imageName, version, regionName string, arch *string, expectedAMI string) {
			cfg := &api.CloudProfileConfig{}
			cfg.MachineImages = profileImages
			ami, err := FindAMIForRegionFromCloudProfile(cfg, imageName, version, regionName, arch)

			Expect(ami).To(Equal(expectedAMI))
			if expectedAMI != "" {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(HaveOccurred())
			}
		},

		Entry("list is nil", nil, "ubuntu", "1", "europe", ptr.To("foo"), ""),

		Entry("profile empty list", []api.MachineImages{}, "ubuntu", "1", "europe", ptr.To("foo"), ""),
		Entry("profile entry not found (image does not exist)", makeProfileMachineImages("debian", "1", "europe", "0", ptr.To("foo")), "ubuntu", "1", "europe", ptr.To("foo"), ""),
		Entry("profile entry not found (version does not exist)", makeProfileMachineImages("ubuntu", "2", "europe", "0", ptr.To("foo")), "ubuntu", "1", "europe", ptr.To("foo"), ""),
		Entry("profile entry not found (architecture does not exist)", makeProfileMachineImages("ubuntu", "1", "europe", "0", ptr.To("bar")), "ubuntu", "1", "europe", ptr.To("foo"), ""),
		Entry("profile entry", makeProfileMachineImages("ubuntu", "1", "europe", "ami-1234", ptr.To("foo")), "ubuntu", "1", "europe", ptr.To("foo"), "ami-1234"),
		Entry("profile non matching region", makeProfileMachineImages("ubuntu", "1", "europe", "ami-1234", ptr.To("foo")), "ubuntu", "1", "china", ptr.To("foo"), ""),
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

	Describe("Decode", func() {
		var (
			decoder runtime.Decoder
			scheme  *runtime.Scheme
		)

		BeforeEach(func() {
			scheme = runtime.NewScheme()
			Expect(core.AddToScheme(scheme)).To(Succeed())
			Expect(api.AddToScheme(scheme)).To(Succeed())
			Expect(apiv1alpha1.AddToScheme(scheme)).To(Succeed())

			decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()

		})

		DescribeTable("DecodeBackupBucketConfig",
			func(config *runtime.RawExtension, want *api.BackupBucketConfig, wantErr bool) {
				got, err := DecodeBackupBucketConfig(decoder, config)
				if wantErr {
					Expect(err).To(HaveOccurred())
				} else {
					Expect(err).NotTo(HaveOccurred())
				}
				Expect(equalBackupBucketConfig(got, want)).To(BeTrue())
			},
			Entry("valid config", &runtime.RawExtension{Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig", "immutability": {"retentionType": "bucket", "retentionPeriod": "24h", "mode": "compliance"}}`)},
				&api.BackupBucketConfig{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "aws.provider.extensions.gardener.cloud/v1alpha1",
						Kind:       "BackupBucketConfig",
					},
					Immutability: &api.ImmutableConfig{
						RetentionType:   "bucket",
						RetentionPeriod: metav1.Duration{Duration: 24 * time.Hour},
						Mode:            "compliance",
					},
				}, false),
			Entry("invalid config", &runtime.RawExtension{Raw: []byte(`invalid`)}, nil, true),
			Entry("missing fields", &runtime.RawExtension{Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1","kind": "BackupBucketConfig"}`)},
				&api.BackupBucketConfig{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "aws.provider.extensions.gardener.cloud/v1alpha1",
						Kind:       "BackupBucketConfig",
					},
				}, false),
			Entry("different data in provider config", &runtime.RawExtension{Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1", "kind": "DifferentConfig", "someField": "someValue"}`)},
				nil, true),
		)
	})
})

func equalBackupBucketConfig(a, b *api.BackupBucketConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return reflect.DeepEqual(a.Immutability, b.Immutability)
}

//nolint:unparam
func makeProfileMachineImages(name, version, region, ami string, arch *string) []api.MachineImages {
	versions := []api.MachineImageVersion{
		{
			Version: version,
			Regions: []api.RegionAMIMapping{
				{
					Name:         region,
					AMI:          ami,
					Architecture: arch,
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
