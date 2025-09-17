// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"github.com/gardener/gardener/pkg/apis/core"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

var _ = Describe("CloudProfileConfig validation", func() {
	DescribeTableSubtree("#ValidateCloudProfileConfig", func(isCapabilitiesCloudProfile bool) {
		var (
			capabilityDefinitions []v1beta1.CapabilityDefinition
			cloudProfileConfig    *apisaws.CloudProfileConfig
			machineImages         []core.MachineImage
			machineImageName      string
			machineImageVersion   string
			fldPath               *field.Path
		)

		BeforeEach(func() {
			regions := []apisaws.RegionAMIMapping{{
				Name: "eu",
				AMI:  "ami-1234",
			}}
			var capabilityFlavors []apisaws.MachineImageFlavor

			if isCapabilitiesCloudProfile {
				capabilityDefinitions = []v1beta1.CapabilityDefinition{{
					Name:   v1beta1constants.ArchitectureName,
					Values: []string{v1beta1constants.ArchitectureAMD64},
				}}
				capabilityFlavors = []apisaws.MachineImageFlavor{{
					Regions: regions,
					Capabilities: v1beta1.Capabilities{
						v1beta1constants.ArchitectureName: []string{v1beta1constants.ArchitectureAMD64},
					}}}
				regions = nil
			} else {
				regions[0].Architecture = ptr.To(v1beta1constants.ArchitectureAMD64)
			}

			machineImageName = "ubuntu"
			machineImageVersion = "1.2.3"
			cloudProfileConfig = &apisaws.CloudProfileConfig{
				MachineImages: []apisaws.MachineImages{
					{
						Name: machineImageName,
						Versions: []apisaws.MachineImageVersion{
							{
								Version:           machineImageVersion,
								Regions:           regions,
								CapabilityFlavors: capabilityFlavors,
							},
						},
					},
				},
			}
			machineImages = []core.MachineImage{
				{
					Name: machineImageName,
					Versions: []core.MachineImageVersion{
						{
							ExpirableVersion: core.ExpirableVersion{Version: machineImageVersion},
							Architectures:    []string{v1beta1constants.ArchitectureAMD64},
						},
					},
				},
			}
		})

		Context("machine image validation", func() {
			It("should pass validation with valid config", func() {
				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)
				Expect(errorList).To(BeEmpty())
			})

			It("should enforce that at least one machine image has been defined", func() {
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("machineImages"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.machineImages[0]"),
				}))))
			})

			It("should forbid unsupported machine image configuration", func() {
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{{}}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("machineImages[0].name"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("machineImages[0].versions"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.machineImages[0]"),
				}))))
			})

			It("should forbid unsupported machine image version configuration", func() {
				var matcher types.GomegaMatcher

				cloudProfileConfig.MachineImages = []apisaws.MachineImages{
					{
						Name:     "abc",
						Versions: []apisaws.MachineImageVersion{{}},
					},
				}
				if isCapabilitiesCloudProfile {
					matcher = Equal("machineImages[0].versions[0].capabilityFlavors[0].regions")
					cloudProfileConfig.MachineImages[0].Versions[0].CapabilityFlavors = []apisaws.MachineImageFlavor{{}}
				} else {
					matcher = Equal("machineImages[0].versions[0].regions")
				}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("machineImages[0].versions[0].version"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": matcher,
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Detail": Equal("must provide an image mapping for image \"ubuntu\" in providerConfig"),
					"Field":  Equal("spec.machineImages[0]"),
				}))))
			})

			It("should forbid unsupported machine image region configuration", func() {
				var machineImageVersion apisaws.MachineImageVersion
				var nameMatcher, amiMatcher types.GomegaMatcher
				if isCapabilitiesCloudProfile {
					nameMatcher = Equal("machineImages[0].versions[0].capabilityFlavors[0].regions[0].name")
					amiMatcher = Equal("machineImages[0].versions[0].capabilityFlavors[0].regions[0].ami")
					machineImageVersion = apisaws.MachineImageVersion{
						Version: "1.2.3",
						CapabilityFlavors: []apisaws.MachineImageFlavor{{
							Regions:      []apisaws.RegionAMIMapping{{}},
							Capabilities: v1beta1.Capabilities{v1beta1constants.ArchitectureName: {v1beta1constants.ArchitectureAMD64}},
						}},
					}
				} else {
					nameMatcher = Equal("machineImages[0].versions[0].regions[0].name")
					amiMatcher = Equal("machineImages[0].versions[0].regions[0].ami")
					machineImageVersion = apisaws.MachineImageVersion{
						Version: "1.2.3",
						Regions: []apisaws.RegionAMIMapping{{Architecture: ptr.To("amd64")}},
					}
				}
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{
					{
						Name:     "abc",
						Versions: []apisaws.MachineImageVersion{machineImageVersion},
					},
				}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Detail": Equal("must provide a name"),
					"Field":  nameMatcher,
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Detail": Equal("must provide an ami"),
					"Field":  amiMatcher,
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.machineImages[0]"),
				}))))
			})

			It("should forbid unsupported machine image architecture configuration", func() {
				var notSupportedField, requiredField types.GomegaMatcher
				if isCapabilitiesCloudProfile {
					cloudProfileConfig.MachineImages[0].Versions[0].CapabilityFlavors[0].Capabilities[v1beta1constants.ArchitectureName] = []string{"foo"}
					notSupportedField = Equal("machineImages[0].versions[0].capabilityFlavors[0].capabilities.architecture[0]")
					requiredField = Equal("spec.machineImages[0].versions[0].capabilityFlavors[0]")
				} else {
					cloudProfileConfig.MachineImages[0].Versions[0].Regions[0].Architecture = ptr.To("foo")
					notSupportedField = Equal("machineImages[0].versions[0].regions[0].architecture")
					requiredField = Equal("spec.machineImages[0].versions[0]")

				}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeNotSupported),
					"Field": notSupportedField,
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  requiredField,
					"Detail": ContainSubstring("missing providerConfig mapping for machine image version"),
				}))))
			})

			It("should forbid missing architecture or capabilitySet mapping", func() {
				var fieldMatcher types.GomegaMatcher
				if isCapabilitiesCloudProfile {
					machineImages[0].Versions[0].CapabilityFlavors = []core.MachineImageFlavor{
						{Capabilities: core.Capabilities{v1beta1constants.ArchitectureName: []string{v1beta1constants.ArchitectureARM64}}},
					}
					fieldMatcher = Equal("spec.machineImages[0].versions[0].capabilityFlavors[0]")
				} else {
					machineImages[0].Versions[0].Architectures = []string{v1beta1constants.ArchitectureARM64}
					fieldMatcher = Equal("spec.machineImages[0].versions[0]")
				}
				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)
				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeRequired), "Field": fieldMatcher})),
				))
			})

			It("should automatically use amd64 (or default to capabilityDefinitions)", func() {
				if !isCapabilitiesCloudProfile {
					cloudProfileConfig.MachineImages[0].Versions[0].Regions[0].Architecture = nil
				}
				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)
				Expect(errorList).To(BeEmpty())
			})

			It("should reject when machineImage.regions and machineImage.capabilityFlavors is set", func() {
				var fieldMatcher types.GomegaMatcher
				if isCapabilitiesCloudProfile {
					fieldMatcher = Equal("machineImages[0].versions[0].regions")
				} else {
					fieldMatcher = Equal("machineImages[0].versions[0].capabilityFlavors")
				}
				cloudProfileConfig.MachineImages[0].Versions[0].Regions = append(cloudProfileConfig.MachineImages[0].Versions[0].Regions, apisaws.RegionAMIMapping{
					Name:         "eu",
					AMI:          "ami-1234",
					Architecture: ptr.To(v1beta1constants.ArchitectureAMD64),
				})
				cloudProfileConfig.MachineImages[0].Versions[0].CapabilityFlavors = append(cloudProfileConfig.MachineImages[0].Versions[0].CapabilityFlavors, apisaws.MachineImageFlavor{
					Regions: []apisaws.RegionAMIMapping{{Name: "eu", AMI: "ami-1234"}},
				})

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, capabilityDefinitions, fldPath)
				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeForbidden),
					"Field":  fieldMatcher,
					"Detail": ContainSubstring("must not be set as CloudProfile"),
				}))))
			})
		})
	},
		Entry("CloudProfile uses regions only", false),
		Entry("CloudProfile uses capabilities", true))
})
