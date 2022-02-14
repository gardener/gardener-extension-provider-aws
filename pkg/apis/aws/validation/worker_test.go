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

package validation_test

import (
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"

	"github.com/gardener/gardener/pkg/apis/core"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"
)

var _ = Describe("ValidateWorkerConfig", func() {
	Describe("#ValidateWorkerConfig", func() {
		var (
			io1type       = string(apisaws.VolumeTypeIO1)
			io1iops int64 = 200
			gp2type       = string(apisaws.VolumeTypeGP2)
			gp2iops int64 = 400
			footype       = "foo"

			rootVolumeIO1 = &core.Volume{Type: &io1type}
			rootVolumeGP2 = &core.Volume{Type: &gp2type}

			dataVolume1Name = "foo"
			dataVolume2Name = "bar"
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
			Expect(ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)).To(BeEmpty())
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
			worker.Volume.IOPS = &gp2iops
			Expect(ValidateWorkerConfig(worker, &core.Volume{Type: &gp2type}, dataVolumes, fldPath)).To(BeEmpty())
		})

		It("should enforce that IOPS are provided for io1 volumes", func() {
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

		It("should enforce that the IOPS for gp2 volumes is within the allowed range", func() {
			var tooLarge int64 = 123123123
			worker.Volume.IOPS = &tooLarge
			worker.DataVolumes = append(worker.DataVolumes, apisaws.DataVolume{
				Name: dataVolume2Name,
				Volume: apisaws.Volume{
					IOPS: &tooLarge,
				},
			})

			errorList := ValidateWorkerConfig(worker, rootVolumeGP2, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("config.volume.iops"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("config.dataVolumes[1].iops"),
				})),
			))
		})

		It("should enforce that the IOPS for io1 volumes is within the allowed range", func() {
			var tooLarge int64 = 123123123
			worker.Volume.IOPS = &tooLarge
			worker.DataVolumes[0].IOPS = &tooLarge

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

		It("should return an error if IOPS is set for a non-supported volume type", func() {
			dataVolumes = append(dataVolumes, core.DataVolume{
				Name: "broken",
				Type: &footype,
			})
			worker.DataVolumes = append(worker.DataVolumes, apisaws.DataVolume{
				Name: "broken",
				Volume: apisaws.Volume{
					IOPS: &io1iops,
				},
			})

			errorList := ValidateWorkerConfig(worker, &core.Volume{Type: &footype}, dataVolumes, fldPath)

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("config.volume.iops"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("config.dataVolumes[2].iops"),
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
					Name: pointer.StringPtr(""),
				}

				errorList := ValidateWorkerConfig(worker, rootVolumeIO1, dataVolumes, fldPath)

				Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("config.iamInstanceProfile.name"),
				}))))
			})

			It("should forbid specifying an invalid IAM arn", func() {
				worker.IAMInstanceProfile = &apisaws.IAMInstanceProfile{
					ARN: pointer.StringPtr(""),
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
	})
})
