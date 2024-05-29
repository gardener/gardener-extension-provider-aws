// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion

import (
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bastion Options", func() {
	var region = "test-region"
	var image = "test-image"
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
		var supportedVersion = "1312.2.0"
		var unsupportedVersion = "1443.1.0"

		It("should find imageID", func() {
			cloudProfileConfig.MachineImages[0].Versions[0].Version = supportedVersion
			foundAmi, err := determineImageID(shoot, cloudProfileConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(foundAmi).To(Equal(ami))
		})

		It("should fail for unsupported image version", func() {
			cloudProfileConfig.MachineImages[0].Versions[0].Version = unsupportedVersion
			_, err := determineImageID(shoot, cloudProfileConfig)
			Expect(err).To(HaveOccurred())
		})
	})
})
