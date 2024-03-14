// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

var _ = Describe("CloudProfileConfig validation", func() {
	Describe("#ValidateCloudProfileConfig", func() {
		var cloudProfileConfig *apisaws.CloudProfileConfig

		BeforeEach(func() {
			cloudProfileConfig = &apisaws.CloudProfileConfig{
				MachineImages: []apisaws.MachineImages{
					{
						Name: "ubuntu",
						Versions: []apisaws.MachineImageVersion{
							{
								Version: "1.2.3",
								Regions: []apisaws.RegionAMIMapping{
									{
										Name:         "eu",
										AMI:          "ami-1234",
										Architecture: pointer.String("amd64"),
									},
								},
							},
						},
					},
				},
			}
		})

		Context("machine image validation", func() {
			It("should enforce that at least one machine image has been defined", func() {
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, field.NewPath("root"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("root.machineImages"),
				}))))
			})

			It("should forbid unsupported machine image configuration", func() {
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{{}}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, field.NewPath("root"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("root.machineImages[0].name"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("root.machineImages[0].versions"),
				}))))
			})

			It("should forbid unsupported machine image version configuration", func() {
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{
					{
						Name:     "abc",
						Versions: []apisaws.MachineImageVersion{{}},
					},
				}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, field.NewPath("root"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("root.machineImages[0].versions[0].version"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("root.machineImages[0].versions[0].regions"),
				}))))
			})

			It("should forbid unsupported machine image region configuration", func() {
				cloudProfileConfig.MachineImages = []apisaws.MachineImages{
					{
						Name: "abc",
						Versions: []apisaws.MachineImageVersion{
							{
								Version: "1.2.3",
								Regions: []apisaws.RegionAMIMapping{{Architecture: pointer.String("amd64")}},
							},
						},
					},
				}

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, field.NewPath("root"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("root.machineImages[0].versions[0].regions[0].name"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("root.machineImages[0].versions[0].regions[0].ami"),
				}))))
			})

			It("should forbid unsupported machine image architecture configuration", func() {
				cloudProfileConfig.MachineImages[0].Versions[0].Regions[0].Architecture = pointer.String("foo")

				errorList := ValidateCloudProfileConfig(cloudProfileConfig, field.NewPath("root"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeNotSupported),
					"Field": Equal("root.machineImages[0].versions[0].regions[0].architecture"),
				}))))
			})
		})
	})
})
