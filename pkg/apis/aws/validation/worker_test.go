// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"github.com/gardener/gardener/pkg/apis/core"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

var _ = Describe("ValidateWorkerConfig", func() {
	Describe("#ValidateWorkerConfig", func() {
		var (
			io1type          = string(apisaws.VolumeTypeIO1)
			io1iops    int64 = 200
			gp2type          = string(apisaws.VolumeTypeGP2)
			gp2iops    int64 = 400
			gp3type          = string(apisaws.VolumeTypeGP3)
			gp3iops    int64 = 4000
			throughput int64 = 200

			rootVolumeIO1 = &core.Volume{Type: &io1type}
			rootVolumeGP2 = &core.Volume{Type: &gp2type}
			rootVolumeGP3 = &core.Volume{Type: &gp3type}

			dataVolume1Name = "foo"
			dataVolume2Name = "bar"
			dataVolume3Name = "baz"
			dataVolumes     []core.DataVolume
			nodeTemplate    *extensionsv1alpha1.NodeTemplate

			iamInstanceProfileName = "name"
			iamInstanceProfileARN  = "arn"

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

		It("should return no errors for a valid nodetemplate configuration", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				Capacity: corev1.ResourceList{
					"cpu":    resource.MustParse("1"),
					"memory": resource.MustParse("50Gi"),
					"gpu":    resource.MustParse("0"),
				},
			}
			Expect(ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should return errors for a invalid nodetemplate configuration", func() {
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

		It("should return errors for a invalid nodetemplate configuration", func() {
			worker.NodeTemplate = &extensionsv1alpha1.NodeTemplate{
				Capacity: corev1.ResourceList{
					"memory": resource.MustParse("50Gi"),
					"gpu":    resource.MustParse("0"),
				},
			}
			errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":   Equal(field.ErrorTypeRequired),
				"Field":  Equal("config.nodeTemplate.capacity"),
				"Detail": Equal("cpu is a mandatory field"),
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
			var negative int64 = -100
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
			var negative int64 = -100
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

		Context("iamInstanceProfile", func() {
			It("should prevent not specifying both IAM name and arn", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("config.iamInstanceProfile"),
				}))))
			})

			It("should prevent specifying both IAM name and arn", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					Name: &iamInstanceProfileName,
					ARN:  &iamInstanceProfileARN,
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("config.iamInstanceProfile"),
				}))))
			})

			It("should forbid specifying an invalid IAM name", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					Name: pointer.String(""),
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("config.iamInstanceProfile.name"),
				}))))
			})

			It("should forbid specifying an invalid IAM arn", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					ARN: pointer.String(""),
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("config.iamInstanceProfile.arn"),
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
					HTTPPutResponseHopLimit: pointer.Int64(1),
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
					HTTPPutResponseHopLimit: pointer.Int64(100),
				}

				errList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)
				Expect(errList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("config.instanceMetadataOptions.httpPutResponseHopLimit"),
					"Detail": Equal("only values between 1 and 64 are allowed"),
				}))))
			})
		})
	})
})
