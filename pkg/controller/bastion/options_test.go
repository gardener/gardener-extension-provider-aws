// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion

import (
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var _ = Describe("Bastion Options", func() {
	var region = "test-region"
	var image = "gardenlinux"
	var ami = "test-ami"
	var cloudProfileConfig *apisaws.CloudProfileConfig
	var shoot *v1beta1.Shoot

	BeforeEach(func() {
		cloudProfileConfig = &apisaws.CloudProfileConfig{
			MachineImages: []apisaws.MachineImages{
				{
					Name: image,
					Versions: []apisaws.MachineImageVersion{
						{
							Regions: []apisaws.RegionAMIMapping{
								{
									Name: region,
									AMI:  ami,
								},
							},
						},
					},
				},
			},
		}
		shoot = &v1beta1.Shoot{
			Spec: v1beta1.ShootSpec{
				Region: region,
			},
		}
	})

	Context("determineImageID", func() {
		var supportedGardenLinuxVersion = "1312.2.0"
		var unsupportedGardenLinuxVersion = "1443.1.0"

		It("should find imageID", func() {
			cloudProfileConfig.MachineImages[0].Versions[0].Version = supportedGardenLinuxVersion
			foundAmi, err := determineImageID(shoot, cloudProfileConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(foundAmi).To(Equal(ami))
		})

		It("should fail for unsupported image version", func() {
			cloudProfileConfig.MachineImages[0].Versions[0].Version = unsupportedGardenLinuxVersion
			_, err := determineImageID(shoot, cloudProfileConfig)
			Expect(err).To(HaveOccurred())
		})

		It("unsupported image version should pass for none gardenlinux images", func() {
			cloudProfileConfig.MachineImages[0].Versions[0].Version = unsupportedGardenLinuxVersion
			cloudProfileConfig.MachineImages[0].Name = "ubuntu"
			foundAmi, err := determineImageID(shoot, cloudProfileConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(foundAmi).To(Equal(ami))
		})
	})
})
