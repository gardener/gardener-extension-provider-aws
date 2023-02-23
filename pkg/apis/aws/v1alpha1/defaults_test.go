// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package v1alpha1_test

import (
	"github.com/onsi/gomega/gstruct"
	"k8s.io/utils/pointer"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var _ = Describe("Defaults", func() {
	Describe("#SetDefaults_ControlPlaneConfig", func() {
		It("should default storage to non nil", func() {
			obj := &ControlPlaneConfig{}

			SetDefaults_ControlPlaneConfig(obj)

			Expect(obj.Storage).NotTo(BeNil())
		})
	})

	Describe("#SetDefaults_Storage", func() {
		It("should default ManagedDefaultClass to true", func() {
			obj := &Storage{}

			SetDefaults_Storage(obj)

			Expect(*obj.ManagedDefaultClass).To(BeTrue())
		})
	})

	Describe("#SetDefaults_RegionAMIMapping", func() {
		It("should default the architecture to amd64", func() {
			obj := &RegionAMIMapping{}

			SetDefaults_RegionAMIMapping(obj)

			Expect(*obj.Architecture).To(Equal(v1beta1constants.ArchitectureAMD64))
		})
	})

	Describe("#SetDefaults_MachineImage", func() {
		It("should default the architecture to amd64", func() {
			obj := &MachineImage{}

			SetDefaults_MachineImage(obj)

			Expect(*obj.Architecture).To(Equal(v1beta1constants.ArchitectureAMD64))
		})
	})

	Describe("#SetDefaults_InstanceMetadata", func() {
		It("should default response hop limit to 2", func() {
			obj := &InstanceMetadata{
				EnableInstanceMetadataV2: true,
			}

			SetDefaults_InstanceMetadata(obj)

			Expect(obj.HTTPPutResponseHopLimit).NotTo(BeNil())
			Expect(obj.HTTPPutResponseHopLimit).To(gstruct.PointTo(Equal(int64(2))))
		})
		It("should respect user changes", func() {
			obj := &InstanceMetadata{
				EnableInstanceMetadataV2: true,
				HTTPPutResponseHopLimit:  pointer.Int64(10),
			}

			SetDefaults_InstanceMetadata(obj)

			Expect(obj.HTTPPutResponseHopLimit).NotTo(BeNil())
			Expect(obj.HTTPPutResponseHopLimit).To(gstruct.PointTo(Equal(int64(10))))
		})
	})
})
