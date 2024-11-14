// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion

import (
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"
)

var _ = Describe("Bastion Options", func() {
	var region = "test-region"
	var image = "gardenlinux"
	var version = "1.0.0"
	var ami = "test-ami"
	var machineName = "test-machine"
	var architecture = "amd64"
	var amiMapping []apisaws.RegionAMIMapping
	var machineImageVersion apisaws.MachineImageVersion
	var machineImages []apisaws.MachineImages
	var vmDetails VmDetails

	BeforeEach(func() {
		amiMapping = []apisaws.RegionAMIMapping{
			{
				Name:         region,
				AMI:          ami,
				Architecture: ptr.To(architecture),
			},
		}
		machineImageVersion = apisaws.MachineImageVersion{
			Version: version,
			Regions: amiMapping,
		}
		machineImages = []apisaws.MachineImages{
			{
				Name:     image,
				Versions: []apisaws.MachineImageVersion{machineImageVersion},
			},
		}
		vmDetails = VmDetails{
			MachineName:   machineName,
			Architecture:  architecture,
			ImageBaseName: image,
			ImageVersion:  version,
		}
	})

	Context("getProviderSpecificImage", func() {
		It("should succeed for existing image and version", func() {
			machineImageVersion, err := getProviderSpecificImage(machineImages, vmDetails)
			Expect(err).NotTo(HaveOccurred())
			Expect(machineImageVersion).To(Equal(machineImageVersion))
		})

		It("fail if image name does not exist", func() {
			vmDetails.ImageBaseName = "unknown"
			_, err := getProviderSpecificImage(machineImages, vmDetails)
			Expect(err).To(HaveOccurred())
		})

		It("fail if image version does not exist", func() {
			vmDetails.ImageVersion = "6.6.6"
			_, err := getProviderSpecificImage(machineImages, vmDetails)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("findImageAMIByRegion", func() {
		It("should find image AMI by region", func() {
			imageAmi, err := findImageAMIByRegion(machineImageVersion, vmDetails, region)
			Expect(err).NotTo(HaveOccurred())
			Expect(imageAmi).To(Equal(ami))
		})

		It("fail if region does not match", func() {
			_, err := findImageAMIByRegion(machineImageVersion, vmDetails, "unknown")
			Expect(err).To(HaveOccurred())
		})

		It("fail if architecture does not match", func() {
			vmDetails.Architecture = "x86"
			_, err := findImageAMIByRegion(machineImageVersion, vmDetails, region)
			Expect(err).To(HaveOccurred())
		})
	})
})
