// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper_test

import (
	"reflect"
	"time"

	"github.com/gardener/gardener/pkg/apis/core"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
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

	DescribeTableSubtree("Select Worker Images", func(hasCapabilities bool) {
		var capabilityDefinitions []v1beta1.CapabilityDefinition
		var machineCapabilities v1beta1.Capabilities
		var imageCapabilities v1beta1.Capabilities
		region := "europe"

		if hasCapabilities {
			capabilityDefinitions = []v1beta1.CapabilityDefinition{
				{Name: "architecture", Values: []string{"amd64", "arm64"}},
				{Name: "capability1", Values: []string{"value1", "value2", "value3"}},
			}
			machineCapabilities = v1beta1.Capabilities{
				"architecture": []string{"amd64"},
				"capability1":  []string{"value2"},
			}
			imageCapabilities = v1beta1.Capabilities{
				"architecture": []string{"amd64"},
				"capability1":  []string{"value2"},
			}
		}

		DescribeTable("#FindImageInWorkerStatus",
			func(machineImages []api.MachineImage, name, version string, arch *string, expectedMachineImage *api.MachineImage, expectErr bool) {
				if hasCapabilities {
					machineCapabilities["architecture"] = []string{*arch}
					if expectedMachineImage != nil {
						expectedMachineImage.Capabilities = imageCapabilities
						expectedMachineImage.Architecture = nil
					}
				}
				machineImage, err := FindImageInWorkerStatus(machineImages, name, version, arch, machineCapabilities, capabilityDefinitions)
				expectResults(machineImage, expectedMachineImage, err, expectErr)
			},

			Entry("list is nil", nil, "bar", "1.2.3", ptr.To("amd64"), nil, true),
			Entry("empty list", []api.MachineImage{}, "image", "1.2.3", ptr.To("amd64"), nil, true),
			Entry("entry not found (no name)", makeStatusMachineImages("bar", "1.2.3", "ami-1234", ptr.To("amd64"), imageCapabilities), "foo", "1.2.3", ptr.To("amd64"), nil, true),
			Entry("entry not found (no version)", makeStatusMachineImages("bar", "1.2.3", "ami-1234", ptr.To("amd64"), imageCapabilities), "bar", "1.2.ś", ptr.To("amd64"), nil, true),
			Entry("entry not found (no architecture)", []api.MachineImage{{Name: "bar", Version: "1.2.3", Architecture: ptr.To("arm64"), Capabilities: v1beta1.Capabilities{"architecture": []string{"arm64"}}}}, "bar", "1.2.3", ptr.To("amd64"), nil, true),
			Entry("entry exists if architecture is nil", makeStatusMachineImages("bar", "1.2.3", "ami-1234", nil, imageCapabilities), "bar", "1.2.3", ptr.To("amd64"), &api.MachineImage{Name: "bar", Version: "1.2.3", AMI: "ami-1234", Architecture: ptr.To("amd64")}, false),
			Entry("entry exists", makeStatusMachineImages("bar", "1.2.3", "ami-1234", ptr.To("amd64"), imageCapabilities), "bar", "1.2.3", ptr.To("amd64"), &api.MachineImage{Name: "bar", Version: "1.2.3", AMI: "ami-1234", Architecture: ptr.To("amd64")}, false),
		)

		DescribeTable("#FindImageInCloudProfile",
			func(profileImages []api.MachineImages, imageName, version, regionName string, arch *string, expectedAMI string) {
				if hasCapabilities {
					machineCapabilities["architecture"] = []string{*arch}
				}
				cfg := &api.CloudProfileConfig{}
				cfg.MachineImages = profileImages

				capabilitySet, err := FindImageInCloudProfile(cfg, imageName, version, regionName, arch, machineCapabilities, capabilityDefinitions)

				if expectedAMI != "" {
					Expect(err).NotTo(HaveOccurred())
					Expect(capabilitySet.Regions[0].AMI).To(Equal(expectedAMI))
				} else {
					Expect(err).To(HaveOccurred())
				}
			},

			Entry("list is nil", nil, "ubuntu", "1", region, ptr.To("amd64"), ""),

			Entry("profile empty list", []api.MachineImages{}, "ubuntu", "1", region, ptr.To("amd64"), ""),
			Entry("profile entry not found (image does not exist)", makeProfileMachineImages("debian", "1", region, "0", ptr.To("amd64"), imageCapabilities), "ubuntu", "1", region, ptr.To("amd64"), ""),
			Entry("profile entry not found (version does not exist)", makeProfileMachineImages("ubuntu", "2", region, "0", ptr.To("amd64"), imageCapabilities), "ubuntu", "1", region, ptr.To("amd64"), ""),
			Entry("profile entry not found (architecture does not exist)", makeProfileMachineImages("ubuntu", "1", region, "0", ptr.To("amd64"), imageCapabilities), "ubuntu", "1", region, ptr.To("arm64"), ""),
			Entry("profile entry", makeProfileMachineImages("ubuntu", "1", region, "ami-1234", ptr.To("amd64"), imageCapabilities), "ubuntu", "1", region, ptr.To("amd64"), "ami-1234"),
			Entry("profile non matching region", makeProfileMachineImages("ubuntu", "1", region, "ami-1234", ptr.To("amd64"), imageCapabilities), "ubuntu", "1", "china", ptr.To("amd64"), ""),
		)

	},
		Entry("without capabilities", false),
		Entry("with capabilities", true),
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
func makeProfileMachineImages(name, version, region, ami string, arch *string, capabilities v1beta1.Capabilities) []api.MachineImages {
	versions := []api.MachineImageVersion{{
		Version: version,
	}}

	if capabilities == nil {
		versions[0].Regions = []api.RegionAMIMapping{{
			Name:         region,
			AMI:          ami,
			Architecture: arch,
		}}
	} else {
		versions[0].CapabilityFlavors = []api.MachineImageFlavor{{
			Capabilities: capabilities,
			Regions: []api.RegionAMIMapping{{
				Name: region,
				AMI:  ami,
			}},
		}}
	}

	return []api.MachineImages{
		{
			Name:     name,
			Versions: versions,
		},
	}
}

//nolint:unparam
func makeStatusMachineImages(name, version, ami string, arch *string, capabilities v1beta1.Capabilities) []api.MachineImage {
	if capabilities != nil {
		capabilities["architecture"] = []string{ptr.Deref(arch, "")}
		return []api.MachineImage{
			{
				Name:         name,
				Version:      version,
				AMI:          ami,
				Capabilities: capabilities,
			},
		}
	}
	return []api.MachineImage{
		{
			Name:         name,
			Version:      version,
			AMI:          ami,
			Architecture: arch,
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
