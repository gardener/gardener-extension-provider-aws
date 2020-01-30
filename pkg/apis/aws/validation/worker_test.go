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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var _ = Describe("ValidateWorkerConfig", func() {
	Describe("#ValidateWorkerConfig", func() {
		var (
			io1type       = "io1"
			io1iops int64 = 200
			gp2type       = "gp2"
			gp2iops int64 = 400

			worker *apisaws.WorkerConfig
		)

		BeforeEach(func() {
			worker = &apisaws.WorkerConfig{
				Volume: &apisaws.Volume{
					IOPS: &io1iops,
				},
			}
		})

		It("should return no errors for a valid configuration", func() {
			Expect(ValidateWorkerConfig(worker, &io1type)).To(BeEmpty())
		})

		It("should return no errors for a valid configuration", func() {
			worker.Volume.IOPS = &gp2iops
			Expect(ValidateWorkerConfig(worker, &gp2type)).To(BeEmpty())
		})

		It("should enforce that the IOPS for gp2 volumes is within the allowed range", func() {
			var tooLarge int64 = 123123123
			worker.Volume.IOPS = &tooLarge

			errorList := ValidateWorkerConfig(worker, &gp2type)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeForbidden),
				"Field": Equal("volume.iops"),
			}))))
		})

		It("should enforce that the IOPS for io1 volumes is within the allowed range", func() {
			var tooLarge int64 = 123123123
			worker.Volume.IOPS = &tooLarge

			errorList := ValidateWorkerConfig(worker, &io1type)

			Expect(errorList).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeForbidden),
				"Field": Equal("volume.iops"),
			}))))
		})
	})
})
