// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1_test

import (
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
})
