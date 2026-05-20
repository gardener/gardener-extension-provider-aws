// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"fmt"
	"strings"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/pkg/apis/core"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

var _ = Describe("ValidateWorkerConfig", func() {
	Describe("#ValidateWorkerConfig", func() {
		var (
			io1type          = string(apisaws.VolumeTypeIO1)
			io1iops    int32 = 200
			gp2type          = string(apisaws.VolumeTypeGP2)
			gp2iops    int32 = 400
			gp3type          = string(apisaws.VolumeTypeGP3)
			gp3iops    int32 = 4000
			throughput int32 = 200

			rootVolumeIO1 = &core.Volume{Type: &io1type}
			rootVolumeGP2 = &core.Volume{Type: &gp2type}
			rootVolumeGP3 = &core.Volume{Type: &gp3type}

			dataVolume1Name = "foo"
			dataVolume2Name = "bar"
			dataVolume3Name = "baz"
			dataVolumes     []core.DataVolume
			nodeTemplate    *extensionsv1alpha1.NodeTemplate

			iamInstanceProfileName = "name"
			iamInstanceProfileARN  = "arn:aws:iam::123456789012:instance-profile/path/to/profile-name"

			worker  *apisaws.WorkerConfig
			fldPath = field.NewPath("config")
		)

		BeforeEach(func() {
			dataVolumes = []core.DataVolume{
				{
					Name: dataVolume1Name,
					Type: &io1type,
				},
				{
					Name: dataVolume2Name,
					Type: &gp2type,
				},
				{
					Name: dataVolume3Name,
					Type: &gp3type,
				},
			}

			worker = &apisaws.WorkerConfig{
				Volume: &apisaws.Volume{
					IOPS: &io1iops,
				},
				DataVolumes: []apisaws.DataVolume{
					{
						Name: dataVolume1Name,
						Volume: apisaws.Volume{
							IOPS: &io1iops,
						},
					},
				},
				NodeTemplate: nodeTemplate,
			}
		})

		It("should return no errors for a valid io1 configuration", func() {
			worker.Volume.Throughput = &throughput
			worker.DataVolumes[0].Throughput = &throughput
			Expect(ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)).To(BeEmpty()) // this will later fail on aws side as currently throughput cannot be configured for io1
		})

		It("should return no errors for a valid nodeTemplate configuration", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				Capacity: corev1.ResourceList{
					"cpu":    resource.MustParse("1"),
					"memory": resource.MustParse("50Gi"),
					"gpu":    resource.MustParse("0"),
				},
			}
			Expect(ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should return errors for an invalid nodeTemplate configuration", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				Capacity: corev1.ResourceList{
					"cpu":    resource.MustParse("-1"),
					"memory": resource.MustParse("50Gi"),
					"gpu":    resource.MustParse("0"),
				},
			}
			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("config.nodeTemplate.capacity.cpu"),
				"Detail": Equal("cpu value must not be negative"),
			}))))
		})

		It("should return no errors for non-whole capacities", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				Capacity: corev1.ResourceList{
					"gpu": resource.MustParse("200m"),
					"foo": resource.MustParse("1.5"),
				},
			}
			Expect(ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should return no error for an empty nodeTemplate", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{}
			Expect(ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should return no error if only virtualCapacities are set", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				VirtualCapacity: corev1.ResourceList{
					"foo": resource.MustParse("1"),
					"bar": resource.MustParse("50Gi"),
				},
			}
			Expect(ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should return no error if both virtualCapacities and capacities are set", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				Capacity: corev1.ResourceList{
					"cpu":    resource.MustParse("1"),
					"memory": resource.MustParse("50Gi"),
					"gpu":    resource.MustParse("0"),
				},
				VirtualCapacity: corev1.ResourceList{
					"foo":    resource.MustParse("1"),
					"bar":    resource.MustParse("50Gi"),
					"foobar": resource.MustParse("0"),
				},
			}
			Expect(ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should return errors for negative virtualCapacities", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				VirtualCapacity: corev1.ResourceList{
					"foo": resource.MustParse("-1"),
					"bar": resource.MustParse("50Gi"),
				},
			}
			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("config.nodeTemplate.virtualCapacity.foo"),
				"Detail": Equal("foo value must not be negative"),
			}))))
		})

		It("should return errors for virtualCapacities which are not whole numbers", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				VirtualCapacity: corev1.ResourceList{
					"foo": resource.MustParse("1500m"), // equal to 1.5 and thus not a whole number
				},
			}
			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("config.nodeTemplate.virtualCapacity.foo"),
				"Detail": Equal("foo value must be a whole number"),
			}))))
		})

		It("should return no errors for a valid gp2 configuration", func() {
			worker.Volume.IOPS = nil
			worker.Volume.Throughput = nil
			Expect(ValidateWorkerConfig(worker, rootVolumeGP2, dataVolumes, fldPath)).To(BeEmpty())
			worker.Volume.IOPS = &gp2iops          // this will later fail on aws side because currently iops cannot be set for gp2.
			worker.Volume.Throughput = &throughput // this will later fail on aws side because currently throughput cannot be set for gp2.
			Expect(ValidateWorkerConfig(worker, rootVolumeGP2, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should return no errors for a valid gp3 configuration", func() {
			worker.Volume.IOPS = nil
			worker.Volume.Throughput = nil
			Expect(ValidateWorkerConfig(worker, rootVolumeGP3, dataVolumes, fldPath)).To(BeEmpty())
			worker.Volume.IOPS = &gp3iops
			worker.Volume.Throughput = &throughput
			Expect(ValidateWorkerConfig(worker, rootVolumeGP3, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should enforce that IOPS is provided for io1 volumes", func() {
			worker.Volume.IOPS = nil
			worker.DataVolumes[0].IOPS = nil

			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("config.volume.iops"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("config.dataVolumes[0].iops"),
				})),
			))
		})

		It("should enforce that the IOPS is positive", func() {
			var negative int32 = -100
			worker.Volume.IOPS = &negative
			worker.DataVolumes[0].IOPS = &negative

			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("config.volume.iops"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("config.dataVolumes[0].iops"),
				})),
			))
		})

		It("should prevent duplicate entries for data volumes in workerconfig", func() {
			worker.DataVolumes = append(worker.DataVolumes, apisaws.DataVolume{Name: dataVolume1Name})

			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeDuplicate),
				"Field": Equal("config.dataVolumes[1].name"),
			}))))
		})

		It("should enforce that the throughput is positive", func() {
			var negative int32 = -100
			worker.Volume.Throughput = &negative
			worker.DataVolumes[0].Throughput = &negative

			errorList := ValidateWorkerConfig(worker, rootVolumeGP3, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.volume.throughput"),
					"Detail": Equal("throughput must be a positive value"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.dataVolumes[0].throughput"),
					"Detail": Equal("throughput must be a positive value"),
				})),
			))
		})

		It("should prevent data volume entries in workerconfig for non-existing data volumes shoot", func() {
			worker.DataVolumes = append(worker.DataVolumes, apisaws.DataVolume{Name: "broken"})

			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("config.dataVolumes[1].name"),
			}))))
		})

		It("should reject invalid snapshot ID", func() {
			worker.DataVolumes[0].SnapshotID = ptr.To("must-start-with-snap")

			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("config.dataVolumes[0].snapshotID"),
				"Detail": Equal(fmt.Sprintf("does not match expected regex %s", SnapshotIDRegex)),
			}))))
		})

		Context("iamInstanceProfile", func() {
			It("should prevent not specifying both IAM name and arn", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.iamInstanceProfile"),
					"Detail": Equal("exactly one of 'name' or 'arn' must be specified"),
				}))))
			})

			It("should prevent specifying both IAM name and arn", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					Name: &iamInstanceProfileName,
					ARN:  &iamInstanceProfileARN,
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.iamInstanceProfile"),
					"Detail": Equal("exactly one of 'name' or 'arn' must be specified"),
				}))))
			})

			It("should forbid specifying an invalid IAM name", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					Name: ptr.To("invalidChar{"),
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.iamInstanceProfile.name"),
					"Detail": Equal(fmt.Sprintf("does not match expected regex %s", IamInstanceProfileNameRegex)),
				}))))
			})

			It("should forbid specifying an invalid IAM arn", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					ARN: ptr.To("must-start-with-arn:aws:iam::"),
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.iamInstanceProfile.arn"),
					"Detail": Equal(fmt.Sprintf("does not match expected regex %s", IamInstanceProfileArnRegex)),
				}))))
			})

			It("should allow specifying a valid IAM name", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					Name: &iamInstanceProfileName,
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(BeEmpty())
			})

			It("should allow specifying a valid IAM arn", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					ARN: &iamInstanceProfileARN,
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(BeEmpty())
			})
		})

		Context("instanceMetadata", func() {
			It("should allow disabling IMDS from pods", func() {
				v := apisaws.HTTPTokensRequired
				worker.InstanceMetadataOptions = &apisaws.InstanceMetadataOptions{
					HTTPPutResponseHopLimit: ptr.To[int32](1),
					HTTPTokens:              &v,
				}

				errList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)
				Expect(errList).To(BeEmpty())
			})

			It("httpTokens should only contain valid values", func() {
				v := apisaws.HTTPTokensValue("foobar")
				worker.InstanceMetadataOptions = &apisaws.InstanceMetadataOptions{
					HTTPTokens: &v,
				}

				errList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)
				Expect(errList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.instanceMetadataOptions.httpTokens"),
					"Detail": Equal("only the following values are allowed: [required optional]"),
				}))))
			})

			It("httpPutResponseHopLimit should only contain valid values", func() {
				worker.InstanceMetadataOptions = &apisaws.InstanceMetadataOptions{
					HTTPPutResponseHopLimit: ptr.To[int32](100),
				}

				errList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)
				Expect(errList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.instanceMetadataOptions.httpPutResponseHopLimit"),
					"Detail": Equal("only values between 1 and 64 are allowed"),
				}))))
			})
		})

		Context("cpuOptions", func() {
			var (
				rootVolume  *core.Volume      // nil or minimal volume, not relevant for cpuOptions tests
				dataVolumes []core.DataVolume // empty
				fldPath     = field.NewPath("config")
			)

			// helper to run validation
			validate := func(wc *apisaws.WorkerConfig) field.ErrorList {
				return ValidateWorkerConfig(wc, rootVolume, dataVolumes, fldPath)
			}

			It("should return no errors when cpuOptions is nil", func() {
				wc := &apisaws.WorkerConfig{}
				Expect(validate(wc)).To(BeEmpty())
			})

			It("should return no errors when neither CoreCount nor ThreadsPerCore are set", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{},
				}
				Expect(validate(wc)).To(BeEmpty())
			})

			It("should require ThreadsPerCore when CoreCount is set", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						CoreCount: ptr.To[int32](4),
					},
				}
				errs := validate(wc)
				Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("config.cpuOptions.threadsPerCore"),
					"Detail": Equal("ThreadsPerCore is required when CoreCount is set"),
				}))))
			})

			It("should require CoreCount when ThreadsPerCore is set", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						ThreadsPerCore: ptr.To[int32](2),
					},
				}
				errs := validate(wc)
				Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("config.cpuOptions.coreCount"),
					"Detail": Equal("CoreCount is required when ThreadsPerCore is set"),
				}))))
			})

			It("should reject ThreadsPerCore values other than 1 or 2", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						CoreCount:      ptr.To[int32](8),
						ThreadsPerCore: ptr.To[int32](3),
					},
				}
				errs := validate(wc)
				Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.cpuOptions.threadsPerCore"),
					"Detail": Equal("ThreadsPerCore must be 1 or 2"),
				}))))
			})

			It("should accept ThreadsPerCore == 1", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						CoreCount:      ptr.To[int32](4),
						ThreadsPerCore: ptr.To[int32](1),
					},
				}
				Expect(validate(wc)).To(BeEmpty())
			})

			It("should accept ThreadsPerCore == 2", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						CoreCount:      ptr.To[int32](4),
						ThreadsPerCore: ptr.To[int32](2),
					},
				}
				Expect(validate(wc)).To(BeEmpty())
			})

			It("should reject invalid AmdSevSnp value", func() {
				v := "invalid"
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						AmdSevSnp: ptr.To(v),
					},
				}
				errs := validate(wc)

				allowed := ec2types.AmdSevSnpSpecificationEnabled.Values()
				quoted := make([]string, len(allowed))
				for i, v := range allowed {
					quoted[i] = fmt.Sprintf("%q", v)
				}
				Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeNotSupported),
					"Field":  Equal("config.cpuOptions.amdSevSnp"),
					"Detail": Equal(fmt.Sprintf("supported values: %s", strings.Join(quoted, ", "))),
				}))))
			})

			It("should accept valid AmdSevSnp value 'enabled'", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						AmdSevSnp: ptr.To("enabled"),
					},
				}
				Expect(validate(wc)).To(BeEmpty())
			})

			It("should accept valid AmdSevSnp value 'disabled'", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						AmdSevSnp: ptr.To("disabled"),
					},
				}
				Expect(validate(wc)).To(BeEmpty())
			})

			It("should report only the invalid ThreadsPerCore error when both counts are set but ThreadsPerCore invalid", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						CoreCount:      ptr.To[int32](16),
						ThreadsPerCore: ptr.To[int32](5),
					},
				}
				errs := validate(wc)
				Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.cpuOptions.threadsPerCore"),
					"Detail": Equal("ThreadsPerCore must be 1 or 2"),
				}))))
			})

			It("should return no errors for a fully valid configuration", func() {
				wc := &apisaws.WorkerConfig{
					CpuOptions: &apisaws.CpuOptions{
						CoreCount:      ptr.To[int32](8),
						ThreadsPerCore: ptr.To[int32](2),
						AmdSevSnp:      ptr.To("enabled"),
					},
				}
				Expect(validate(wc)).To(BeEmpty())
			})
		})

		Context("NetworkInterfaces validation", func() {
			validate := func(wc *apisaws.WorkerConfig) field.ErrorList {
				return ValidateWorkerConfig(wc, nil, nil, fldPath)
			}

			It("should reject invalid type value", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](0), Type: ptr.To("invalid-type")}}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeNotSupported), "Field": Equal("config.networkInterfaces[0].type")}))))
			})

			It("should reject empty type value (use nil to default to interface)", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](0), Type: ptr.To("")}}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeNotSupported), "Field": Equal("config.networkInterfaces[0].type")}))))
			})

			It("should reject efa-only as the first interface", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](0), Type: ptr.To("efa-only")}}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].type")}))))
			})

			It("should reject efa-only on the primary NIC when it is not the first slice entry", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{
					{NetworkCardIndex: ptr.To[int64](1), DeviceIndex: ptr.To[int64](1), Type: ptr.To("efa")},
					{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](0), Type: ptr.To("efa-only")},
				}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[1].type")}))))
			})

			It("should reject efa-only on the primary NIC when index fields are nil (default to 0,0)", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{Type: ptr.To("efa-only")}}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].type")}))))
			})

			It("should reject efa-only when range covers (0,0)", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{
					NetworkCardIndexRange: &apisaws.IndexRange{From: 0, To: 1},
					DeviceIndexRange:      &apisaws.IndexRange{From: 0, To: 1},
					Type:                  ptr.To("efa-only"),
				}}}
				Expect(validate(wc)).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].type")}))))
			})

			It("should accept efa-only on a non-primary NIC", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{
					{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](0), Type: ptr.To("efa")},
					{NetworkCardIndex: ptr.To[int64](1), DeviceIndex: ptr.To[int64](1), Type: ptr.To("efa-only")},
				}}
				Expect(validate(wc)).To(BeEmpty())
			})

			It("should accept efa-only on a range that does not cover (0,0)", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{
					{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](0), Type: ptr.To("efa")},
					{
						NetworkCardIndexRange: &apisaws.IndexRange{From: 1, To: 3},
						DeviceIndexRange:      &apisaws.IndexRange{From: 1, To: 3},
						Type:                  ptr.To("efa-only"),
					},
				}}
				Expect(validate(wc)).To(BeEmpty())
			})

			It("should reject networkCardIndex and networkCardIndexRange together", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndex: ptr.To[int64](0), NetworkCardIndexRange: &apisaws.IndexRange{From: 1, To: 3}, DeviceIndex: ptr.To[int64](0)}}}
				Expect(validate(wc)).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Detail": Equal("networkCardIndex and networkCardIndexRange are mutually exclusive")}))))
			})

			It("should reject negative networkCardIndex", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndex: ptr.To[int64](-1), DeviceIndex: ptr.To[int64](0)}}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].networkCardIndex")}))))
			})

			It("should reject negative networkCardIndexRange.from", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndexRange: &apisaws.IndexRange{From: -1, To: 3}, DeviceIndexRange: &apisaws.IndexRange{From: 0, To: 4}}}}
				Expect(validate(wc)).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].networkCardIndexRange.from")}))))
			})

			It("should reject networkCardIndexRange from > to", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndexRange: &apisaws.IndexRange{From: 5, To: 1}}}}
				Expect(validate(wc)).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].networkCardIndexRange")}))))
			})

			It("should reject deviceIndex and deviceIndexRange together", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndexRange: &apisaws.IndexRange{From: 1, To: 3}, DeviceIndex: ptr.To[int64](1), DeviceIndexRange: &apisaws.IndexRange{From: 1, To: 3}}}}
				Expect(validate(wc)).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Detail": Equal("deviceIndex and deviceIndexRange are mutually exclusive")}))))
			})

			It("should reject negative deviceIndex", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](-1)}}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].deviceIndex")}))))
			})

			It("should reject deviceIndexRange without networkCardIndexRange", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndex: ptr.To[int64](0), DeviceIndexRange: &apisaws.IndexRange{From: 0, To: 3}}}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeForbidden), "Field": Equal("config.networkInterfaces[0].deviceIndexRange")}))))
			})

			It("should reject mismatched range lengths", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndexRange: &apisaws.IndexRange{From: 1, To: 3}, DeviceIndexRange: &apisaws.IndexRange{From: 1, To: 5}}}}
				Expect(validate(wc)).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].deviceIndexRange"), "Detail": ContainSubstring("same length")}))))
			})

			It("should reject negative ipv6AddressCount", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](0), Type: ptr.To("efa"), Ipv6AddressCount: ptr.To[int64](-1)}}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.networkInterfaces[0].ipv6AddressCount")}))))
			})

			It("should accept valid config", func() {
				wc := &apisaws.WorkerConfig{NetworkInterfaces: []apisaws.NetworkInterface{
					{NetworkCardIndex: ptr.To[int64](0), DeviceIndex: ptr.To[int64](0), Type: ptr.To("efa")},
					{NetworkCardIndexRange: &apisaws.IndexRange{From: 1, To: 3}, DeviceIndexRange: &apisaws.IndexRange{From: 1, To: 3}, Type: ptr.To("efa-only")},
				}}
				Expect(validate(wc)).To(BeEmpty())
			})
		})

		Context("InstanceMarketOptions validation", func() {
			validate := func(wc *apisaws.WorkerConfig) field.ErrorList {
				return ValidateWorkerConfig(wc, nil, nil, fldPath)
			}

			It("should reject invalid marketType", func() {
				wc := &apisaws.WorkerConfig{InstanceMarketOptions: &apisaws.InstanceMarketOptions{MarketType: "invalid"}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeNotSupported), "Field": Equal("config.instanceMarketOptions.marketType")}))))
			})

			It("should accept valid marketType", func() {
				wc := &apisaws.WorkerConfig{InstanceMarketOptions: &apisaws.InstanceMarketOptions{MarketType: "capacity-block"}}
				Expect(validate(wc)).To(BeEmpty())
			})
		})

		Context("Placement validation", func() {
			validate := func(wc *apisaws.WorkerConfig) field.ErrorList {
				return ValidateWorkerConfig(wc, nil, nil, fldPath)
			}

			It("should reject invalid tenancy", func() {
				wc := &apisaws.WorkerConfig{Placement: &apisaws.Placement{Tenancy: ptr.To("invalid")}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeNotSupported), "Field": Equal("config.placement.tenancy")}))))
			})

			It("should reject invalid affinity", func() {
				wc := &apisaws.WorkerConfig{Placement: &apisaws.Placement{Affinity: ptr.To("invalid")}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeNotSupported), "Field": Equal("config.placement.affinity")}))))
			})

			It("should reject hostId without tenancy host", func() {
				wc := &apisaws.WorkerConfig{Placement: &apisaws.Placement{HostID: ptr.To("h-123")}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeForbidden), "Field": Equal("config.placement.hostId")}))))
			})

			It("should reject partitionNumber less than 1", func() {
				wc := &apisaws.WorkerConfig{Placement: &apisaws.Placement{PartitionNumber: ptr.To[int64](0)}}
				Expect(validate(wc)).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("config.placement.partitionNumber")}))))
			})

			It("should accept valid placement", func() {
				wc := &apisaws.WorkerConfig{Placement: &apisaws.Placement{GroupID: ptr.To("pg-123"), Tenancy: ptr.To("host"), HostID: ptr.To("h-123")}}
				Expect(validate(wc)).To(BeEmpty())
			})
		})
	})
})
