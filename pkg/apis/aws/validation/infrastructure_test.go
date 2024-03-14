// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
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
				errorList := ValidateInfrastructureConfigAgainstCloudProfile(nil, infrastructureConfig, shoot, cloudProfile, &field.Path{})

				Expect(errorList).To(BeEmpty())
			})

			It("should forbid because zone is not specified in CloudProfile", func() {
				infrastructureConfig.Networks.Zones[0].Name = "not-available"
				errorList := ValidateInfrastructureConfigAgainstCloudProfile(nil, infrastructureConfig, shoot, cloudProfile, field.NewPath("spec"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeNotSupported),
					"Field": Equal("spec.network.zones[0].name"),
				}))))
			})

			It("should forbid because zone is duplicate", func() {
				infrastructureConfig.Networks.Zones = append(infrastructureConfig.Networks.Zones, infrastructureConfig.Networks.Zones[0])
				errorList := ValidateInfrastructureConfigAgainstCloudProfile(nil, infrastructureConfig, shoot, cloudProfile, field.NewPath("spec"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeDuplicate),
					"Field": Equal("spec.network.zones[1].name"),
				}))))
			})

			It("should forbid zone update because zone is duplicate", func() {
				oldInfra := infrastructureConfig.DeepCopy()
				infrastructureConfig.Networks.Zones = append(infrastructureConfig.Networks.Zones, infrastructureConfig.Networks.Zones[0])
				errorList := ValidateInfrastructureConfigAgainstCloudProfile(oldInfra, infrastructureConfig, shoot, cloudProfile, field.NewPath("spec"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeDuplicate),
					"Field": Equal("spec.network.zones[1].name"),
				}))))
			})

			It("should pass because zone is not specified in CloudProfile but was not changed", func() {
				infrastructureConfig.Networks.Zones[0].Name = "not-available"
				oldInfrastructureConfig := infrastructureConfig.DeepCopy()

				errorList := ValidateInfrastructureConfigAgainstCloudProfile(oldInfrastructureConfig, infrastructureConfig, shoot, cloudProfile, field.NewPath("spec"))

				Expect(errorList).To(BeEmpty())
			})

			It("should fail because zone is not specified in CloudProfile and was changed", func() {
				oldInfrastructureConfig := infrastructureConfig.DeepCopy()
				infrastructureConfig.Networks.Zones[0].Name = "not-available"

				errorList := ValidateInfrastructureConfigAgainstCloudProfile(oldInfrastructureConfig, infrastructureConfig, shoot, cloudProfile, field.NewPath("spec"))

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeNotSupported),
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

			It("should allow specifying valid config", func() {
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(BeEmpty())
			})

			It("should allow specifying valid config with podsCIDR=nil and servicesCIDR=nil", func() {
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, nil, nil)
				Expect(errorList).To(BeEmpty())
			})

			It("should allow adding the same zone", func() {
				infrastructureConfig.Networks.Zones = append(infrastructureConfig.Networks.Zones, awsZone2)
				infrastructureConfig.Networks.Zones[1].Name = zone

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)

				Expect(errorList).To(BeEmpty())
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
						"Detail": Equal(`must be a subset of "networking.nodes" ("10.250.0.0/16")`),
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
						"Detail": Equal(`must not overlap with "networks.vpc.cidr" ("10.0.0.0/8")`),
					}))
				})

				It("should forbid Services CIDR to overlap with VPC CIDR", func() {
					servicesCIDR := "10.0.0.1/32"

					errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &servicesCIDR)

					Expect(errorList).To(ConsistOfFields(Fields{
						"Type":   Equal(field.ErrorTypeInvalid),
						"Detail": Equal(`must not overlap with "networks.vpc.cidr" ("10.0.0.0/8")`),
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
						"Detail": Equal(`must not overlap with "networks.zones[0].internal" ("10.250.0.1/32")`),
					}, Fields{
						"Type":   Equal(field.ErrorTypeInvalid),
						"Field":  Equal("networks.zones[0].workers"),
						"Detail": Equal(`must not overlap with "networks.zones[0].internal" ("10.250.0.1/32")`),
					}, Fields{
						"Type":   Equal(field.ErrorTypeInvalid),
						"Field":  Equal("networks.zones[0].workers"),
						"Detail": Equal(`must not overlap with "networks.zones[0].public" ("10.250.0.1/32")`),
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

			It("should ensure that the elastic IP allocation id starts with `eipalloc-`", func() {
				infrastructureConfig.Networks.Zones[0].ElasticIPAllocationID = pointer.String("foo")
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[0].elasticIPAllocationID"),
				}))

				infrastructureConfig.Networks.Zones[0].ElasticIPAllocationID = pointer.String("eipalloc-123456")
				errorList = ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(BeEmpty())
			})

			It("should forbid the assigning same elastic IP allocation id to multiple zones", func() {
				infrastructureConfig.Networks.Zones = append(infrastructureConfig.Networks.Zones, awsZone2)
				infrastructureConfig.Networks.Zones[0].ElasticIPAllocationID = pointer.String("eipalloc-123456")
				infrastructureConfig.Networks.Zones[1].ElasticIPAllocationID = pointer.String("eipalloc-123456")

				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":  Equal(field.ErrorTypeDuplicate),
					"Field": Equal("networks.zones[1].elasticIPAllocationID"),
				}))

				infrastructureConfig.Networks.Zones[1].ElasticIPAllocationID = pointer.String("eipalloc-654321")
				errorList = ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(BeEmpty())
			})
		})

		Context("gatewayEndpoints", func() {
			It("should accept empty list", func() {
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(BeEmpty())
			})

			It("should reject non-alphanumeric endpoints", func() {
				infrastructureConfig.Networks.VPC.GatewayEndpoints = []string{"s3", "my-endpoint"}
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("networks.vpc.gatewayEndpoints[1]"),
					"BadValue": Equal("my-endpoint"),
					"Detail":   Equal("must be a valid domain name"),
				}))
			})

			It("should accept all-valid lists", func() {
				infrastructureConfig.Networks.VPC.GatewayEndpoints = []string{"myservice", "s3", "my.other.service"}
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).To(BeEmpty())
			})
		})

		Context("ignoreTags", func() {
			It("should forbid ignoring reserved tags", func() {
				infrastructureConfig.IgnoreTags = &apisaws.IgnoreTags{
					Keys:        []string{"Name"},
					KeyPrefixes: []string{"kubernetes.io/", "gardener.cloud/"},
				}
				errorList := ValidateInfrastructureConfig(infrastructureConfig, &nodes, &pods, &services)
				Expect(errorList).NotTo(BeEmpty())
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

		It("should allow changing gateway endpoints inside vpc", func() {
			newInfraConfig := infrastructureConfig.DeepCopy()
			newInfraConfig.Networks.VPC.GatewayEndpoints = []string{"myep"}
			Expect(ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfraConfig)).To(BeEmpty())
		})

		It("should forbid changing the VPC ID", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newid := "the-new-id"
			newInfrastructureConfig.Networks.VPC.ID = &newid

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.vpc.id"),
			}))))
		})

		It("should forbid changing the VPC CIDR", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newCIDR := "1.2.3.4/5"
			newInfrastructureConfig.Networks.VPC.CIDR = &newCIDR

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.vpc.cidr"),
			}))))
		})

		It("should forbid changing the internal network of a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0].Internal = awsZone2.Internal

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones[0].internal"),
			}))))
		})

		It("should forbid changing the public network of a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0].Public = awsZone2.Public

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones[0].public"),
			}))))
		})

		It("should forbid changing the workers network of a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0].Workers = awsZone2.Workers

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones[0].workers"),
			}))))
		})

		It("should allow changing the elastic IP allocation ID of a zone", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0].ElasticIPAllocationID = pointer.String("some-id")

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(BeEmpty())
		})

		It("should forbid removing a zone", func() {
			infrastructureConfig.Networks.Zones = append(infrastructureConfig.Networks.Zones, awsZone2)
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones = newInfrastructureConfig.Networks.Zones[:1]

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeForbidden),
				"Field": Equal("networks.zones"),
			}))))
		})

		It("should allow adding a zone but forbid changing one", func() {
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones = append(newInfrastructureConfig.Networks.Zones, awsZone2)
			newInfrastructureConfig.Networks.Zones[0].Name = "zone3"

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("networks.zones[0].name"),
			}))))
		})

		It("should forbid changing the order of zones", func() {
			infrastructureConfig.Networks.Zones = append(infrastructureConfig.Networks.Zones, awsZone2)
			newInfrastructureConfig := infrastructureConfig.DeepCopy()
			newInfrastructureConfig.Networks.Zones[0] = infrastructureConfig.Networks.Zones[1]
			newInfrastructureConfig.Networks.Zones[1] = infrastructureConfig.Networks.Zones[0]

			errorList := ValidateInfrastructureConfigUpdate(infrastructureConfig, newInfrastructureConfig)

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[0].name"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[0].public"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[0].internal"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[0].workers"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[1].name"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[1].public"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[1].internal"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networks.zones[1].workers"),
				})),
			))
		})
	})

	Describe("#ValidateIgnoreTags", func() {
		var (
			fldPath *field.Path
		)

		BeforeEach(func() {
			fldPath = field.NewPath("ignoreTags")
		})

		It("should accept empty ignoreTags", func() {
			errorList := ValidateIgnoreTags(fldPath, nil)
			Expect(errorList).To(BeEmpty())
		})

		It("should accept valid ignoreTags", func() {
			errorList := ValidateIgnoreTags(fldPath, &apisaws.IgnoreTags{
				Keys:        []string{"foo", "bar"},
				KeyPrefixes: []string{"custom/prefix", "another-prefix-"},
			})
			Expect(errorList).To(BeEmpty())
		})

		It("should forbid empty values", func() {
			errorList := ValidateIgnoreTags(fldPath, &apisaws.IgnoreTags{
				Keys:        []string{"foo", ""},
				KeyPrefixes: []string{"custom/prefix", ""},
			})
			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keys[1]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[1]"),
				})),
			))
		})

		It("should forbid ignoring Name tag", func() {
			errorList := ValidateIgnoreTags(fldPath, &apisaws.IgnoreTags{
				Keys:        []string{"Name"},
				KeyPrefixes: []string{"Na", "Name", "NameFooIsAllowed"},
			})
			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keys[0]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[0]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[1]"),
				})),
			))
		})

		It("should forbid ignoring tags starting with kubernetes.io", func() {
			errorList := ValidateIgnoreTags(fldPath, &apisaws.IgnoreTags{
				Keys:        []string{"kube", "kubernetes.io", "kubernetes.io/cluster/name"},
				KeyPrefixes: []string{"kube", "kubernetes.io", "kubernetes.io/", "kubernetes.io/cluster/"},
			})
			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keys[1]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keys[2]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[0]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[1]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[2]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[3]"),
				})),
			))
		})

		It("should forbid ignoring tags starting with gardener.cloud", func() {
			errorList := ValidateIgnoreTags(fldPath, &apisaws.IgnoreTags{
				Keys:        []string{"garden", "gardener.cloud", "gardener.cloud/cluster/name"},
				KeyPrefixes: []string{"garden", "gardener.cloud", "gardener.cloud/", "gardener.cloud/cluster/"},
			})
			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keys[1]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keys[2]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[0]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[1]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[2]"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("ignoreTags.keyPrefixes[3]"),
				})),
			))
		})
	})
})
