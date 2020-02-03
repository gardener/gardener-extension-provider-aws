// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package validation_test

import (
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/gardener/gardener/pkg/utils/validation/gomega"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var _ = Describe("InfrastructureConfig validation", func() {
	var (
		infrastructureConfig *apisaws.InfrastructureConfig

		pods        = "100.96.0.0/11"
		services    = "100.64.0.0/13"
		nodes       = "10.250.0.0/16"
		vpc         = "10.0.0.0/8"
		invalidCIDR = "invalid-cidr"
		zone        = "zone1"
		zone2       = "zone2"

		awsZone2 = apisaws.Zone{
			Name:     zone2,
			Internal: "10.250.4.0/24",
			Public:   "10.250.5.0/24",
			Workers:  "10.250.6.0/24",
		}
	)

	BeforeEach(func() {
		infrastructureConfig = &apisaws.InfrastructureConfig{
			Networks: apisaws.Networks{
				VPC: apisaws.VPC{
					CIDR: &vpc,
				},
				Zones: []apisaws.Zone{
					{
						Name:     zone,
						Internal: "10.250.1.0/24",
						Public:   "10.250.2.0/24",
						Workers:  "10.250.3.0/24",
					},
				},
			},
		}
	})

	Describe("#ValidateInfrastructureConfigAgainstCloudProfile", func() {
		var (
			cloudProfile *gardencorev1beta1.CloudProfile
			shoot        *core.Shoot
			region       = "eu-west"
			region2      = "us-west"
		)
		Context("zones validation", func() {
			BeforeEach(func() {
				cloudProfile = &gardencorev1beta1.CloudProfile{
					Spec: gardencorev1beta1.CloudProfileSpec{
						Regions: []gardencorev1beta1.Region{
							{
								Name: region2,
								Zones: []gardencorev1beta1.AvailabilityZone{
									{
										Name: zone2,
									},
									{
										Name: zone,
									},
								},
							},
							{
								Name: region,
								Zones: []gardencorev1beta1.AvailabilityZone{
									{
										Name: zone2,
									},
									{
										Name: zone,
									},
								},
							},
						},
					},
				}
				shoot = &core.Shoot{
					Spec: core.ShootSpec{
						Region: region,
					},
				}
			})

			It("should pass because zone is configured in CloudProfile", func() {
				errorList := ValidateInfrastructureConfigAgainstCloudProfile(infrastructureConfig, shoot, cloudProfile, &field.Path{})

				Expect(errorList).To(BeEmpty())
			})

			It("should forbid because zone is not specified in CloudProfile", func() {
				infrastructureConfig.Networks.Zones[0].Name = "not-available"
				errorList := ValidateInfrastructureConfigAgainstCloudProfile(infrastructureConfig, shoot, cloudProfile, field.NewPath("spec"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("spec.network.zones[0].name"),
				}))))
			})
		})
	})

	Describe("#ValidateInfrastructureConfig", func() {
		Context("Zones", func() {
			It("should forbid empty zones", func() {
				infrastructureConfig.Networks.Zones = nil

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("networks.zones"),
					"Detail": Equal("must specify at least the networks for one zone"),
				}))

			})

			It("should forbid adding a zone", func() {
				infrastructureConfig.Networks.Zones = append(infrastructureConfig.Networks.Zones, awsZone2)
				infrastructureConfig.Networks.Zones[1].Name = zone

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[1].name"),
					"Detail": Equal("each zone may only be specified once"),
				}))
			})
		})

		Context("CIDR", func() {
			It("should forbid invalid VPC CIDRs", func() {
				infrastructureConfig.Networks.VPC.CIDR = &invalidCIDR

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.vpc.cidr"),
					"Detail": Equal("invalid CIDR address: invalid-cidr"),
				}))
			})

			It("should forbid invalid internal CIDR", func() {
				infrastructureConfig.Networks.Zones[0].Internal = invalidCIDR

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].internal"),
					"Detail": Equal("invalid CIDR address: invalid-cidr"),
				}))
			})

			It("should forbid invalid public CIDR", func() {
				infrastructureConfig.Networks.Zones[0].Public = invalidCIDR

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].public"),
					"Detail": Equal("invalid CIDR address: invalid-cidr"),
				}))
			})

			It("should forbid invalid workers CIDR", func() {
				infrastructureConfig.Networks.Zones[0].Workers = invalidCIDR

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].workers"),
					"Detail": Equal("invalid CIDR address: invalid-cidr"),
				}))
			})

			It("should forbid internal CIDR which is not in VPC CIDR", func() {
				infrastructureConfig.Networks.Zones[0].Internal = "1.1.1.1/32"

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].internal"),
					"Detail": Equal(`must be a subset of "networks.vpc.cidr" ("10.0.0.0/8")`),
				}))
			})

			It("should forbid public CIDR which is not in VPC CIDR", func() {
				infrastructureConfig.Networks.Zones[0].Public = "1.1.1.1/32"

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].public"),
					"Detail": Equal(`must be a subset of "networks.vpc.cidr" ("10.0.0.0/8")`),
				}))
			})

			It("should forbid workers CIDR which are not in VPC and Nodes CIDR", func() {
				infrastructureConfig.Networks.Zones[0].Workers = "1.1.1.1/32"

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].workers"),
					"Detail": Equal(`must be a subset of "" ("10.250.0.0/16")`),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].workers"),
					"Detail": Equal(`must be a subset of "networks.vpc.cidr" ("10.0.0.0/8")`),
				}))
			})

			It("should forbid Pod CIDR to overlap with VPC CIDR", func() {
				podCIDR := "10.0.0.1/32"

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &podCIDR, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Detail": Equal(`must not be a subset of "networks.vpc.cidr" ("10.0.0.0/8")`),
				}))
			})

			It("should forbid Services CIDR to overlap with VPC CIDR", func() {
				servicesCIDR := "10.0.0.1/32"

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &servicesCIDR)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Detail": Equal(`must not be a subset of "networks.vpc.cidr" ("10.0.0.0/8")`),
				}))
			})

			It("should forbid VPC CIDRs to overlap with other VPC CIDRs", func() {
				overlappingCIDR := "10.250.0.1/32"
				infrastructureConfig.Networks.Zones[0].Internal = overlappingCIDR
				infrastructureConfig.Networks.Zones[0].Public = overlappingCIDR
				infrastructureConfig.Networks.Zones[0].Workers = overlappingCIDR

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &overlappingCIDR, &pods, &services)

				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].public"),
					"Detail": Equal(`must not be a subset of "networks.zones[0].internal" ("10.250.0.1/32")`),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].workers"),
					"Detail": Equal(`must not be a subset of "networks.zones[0].internal" ("10.250.0.1/32")`),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].internal"),
					"Detail": Equal(`must not be a subset of "networks.zones[0].public" ("10.250.0.1/32")`),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].workers"),
					"Detail": Equal(`must not be a subset of "networks.zones[0].public" ("10.250.0.1/32")`),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].internal"),
					"Detail": Equal(`must not be a subset of "networks.zones[0].workers" ("10.250.0.1/32")`),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].public"),
					"Detail": Equal(`must not be a subset of "networks.zones[0].workers" ("10.250.0.1/32")`),
				}))
			})

			It("should forbid non canonical CIDRs", func() {
				vpcCIDR := "10.0.0.3/8"
				infrastructureConfig.Networks.Zones[0].Public = "10.250.2.7/24"
				infrastructureConfig.Networks.Zones[0].Internal = "10.250.1.6/24"
				infrastructureConfig.Networks.Zones[0].Workers = "10.250.3.8/24"
				infrastructureConfig.Networks.VPC = apisaws.VPC{CIDR: &vpcCIDR}

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(HaveLen(4))
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.vpc.cidr"),
					"Detail": Equal("must be valid canonical CIDR"),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].internal"),
					"Detail": Equal("must be valid canonical CIDR"),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].public"),
					"Detail": Equal("must be valid canonical CIDR"),
				}, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("networks.zones[0].workers"),
					"Detail": Equal("must be valid canonical CIDR"),
				}))
			})
		})

		Context("gatewayEndpoints", func() {
			It("should accept empty list", func() {
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(BeEmpty())
			})
			It("should reject non-alpthanumeric endpoints", func() {
				infrastructureConfig.Networks.VPC.GatewayEndpoints = []string{"s3", "my-endpoint"}
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("networks.vpc.gatewayEndpoints[1]"),
					"BadValue": Equal("my-endpoint"),
					"Detail":   Equal("must be alphanumeric"),
				}))
			})
			It("should accept all-valid lists", func() {
				infrastructureConfig.Networks.VPC.GatewayEndpoints = []string{"myservice", "s3"}
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(BeEmpty())
			})
		})
	})

	Describe("#ValidateInfrastructureConfigUpdate", func() {
		It("should return no errors for an unchanged config", func() {
			Expect(ValidateInfrastructureConfigUpdate(infrastructureConfig, infrastructureConfig)).To(BeEmpty())
		})

		It("should allow adding a zone", func() {

			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones = append(newInfrastructureConfig.Networks.Zones, awsZone2)

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(BeEmpty())
		})

		It("should forbid changing the VPC", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newCIDR := "1.2.3.4/5"
			newInfrastructureConfig.Networks.VPC.CIDR = &newCIDR

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.vpc"),
			}))))
		})

		It("should forbid changing the internal network of a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0].Internal = awsZone2.Internal

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones[0]"),
			}))))
		})

		It("should forbid changing the public network of a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0].Public = awsZone2.Public

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones[0]"),
			}))))
		})

		It("should forbid changing the workers network of a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0].Workers = awsZone2.Workers

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones[0]"),
			}))))
		})

		It("should forbid removing a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0] = awsZone2

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones"),
			}))))
		})

		It("should allow adding a zone but forbid removing a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones = append(newInfrastructureConfig.Networks.Zones, awsZone2)
			newInfrastructureConfig.Networks.Zones[0].Name = "zone3"

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones"),
			}))))
		})
	})
})
