// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"github.com/gardener/gardener/pkg/apis/core"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

var _ = Describe("CloudProfileConfig validation", func() {
	Describe("#ValidateCloudProfileConfig", func() {
		var (
			cloudProfileConfig  *apisaws.CloudProfileConfig
			machineImages       []core.MachineImage
			machineImageName    string
			machineImageVersion string
			fldPath             *field.Path
		)

		BeforeEach(func() {
			machineImageName = "ubuntu"
			machineImageVersion = "1.2.3"
			cloudProfileConfig = &apisaws.CloudProfileConfig{
				MachineImages: []apisaws.MachineImages{
					{
						Name: machineImageName,
						Versions: []apisaws.MachineImageVersion{
							{
								Version: machineImageVersion,
								Regions: []apisaws.RegionAMIMapping{
									{
										Name:         "eu",
										AMI:          "ami-1234",
										Architecture: ptr.To(v1beta1constants.ArchitectureAMD64),
									},
								},
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
			It("should pass validation", func() {
				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, fldPath)
				Expect(errorList).To(BeEmpty())
			})

			It("should enforce that at least one machine image has been defined", func() {
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, fldPath)

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

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, fldPath)

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
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{
					{
						Name:     "abc",
						Versions: []apisaws.MachineImageVersion{{}},
					},
				}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("machineImages[0].versions[0].version"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("machineImages[0].versions[0].regions"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.machineImages[0]"),
				}))))
			})

			It("should forbid unsupported machine image region configuration", func() {
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{
					{
						Name: "abc",
						Versions: []apisaws.MachineImageVersion{
							{
								Version: "1.2.3",
								Regions: []apisaws.RegionAMIMapping{{Architecture: ptr.To("amd64")}},
							},
						},
					},
				}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("machineImages[0].versions[0].regions[0].name"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("machineImages[0].versions[0].regions[0].ami"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.machineImages[0]"),
				}))))
			})

			It("should forbid unsupported machine image architecture configuration", func() {
				cloudProfileConfig.MachineImages[0].Versions[0].Regions[0].Architecture = ptr.To("foo")

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeNotSupported),
					"Field": Equal("machineImages[0].versions[0].regions[0].architecture"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.machineImages[0].versions[0]"),
				}))))
			})

			It("should forbid missing architecture mapping", func() {
				machineImages[0].Versions[0].Architectures = []string{"arm64"}
				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, fldPath)

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("spec.machineImages[0].versions[0]"),
					})),
				))
			})

			It("should automatically use amd64", func() {
				cloudProfileConfig.MachineImages[0].Versions[0].Regions[0].Architecture = nil
				errorList := ValidateCloudProfileConfig(cloudProfileConfig, machineImages, fldPath)
				Expect(errorList).To(BeEmpty())
			})
		})
	})
})
