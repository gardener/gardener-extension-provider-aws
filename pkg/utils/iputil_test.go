// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("iputil", func() {
	Describe("IsIPv6CIDR", func() {
		It("should return true for valid IPv6 CIDR", func() {
			Expect(IsIPv6CIDR("2001:db8::/64")).To(BeTrue())
		})

		It("should return false for valid IPv4 CIDR", func() {
			Expect(IsIPv6CIDR("192.168.0.0/24")).To(BeFalse())
		})

		It("should return false for invalid CIDR", func() {
			Expect(IsIPv6CIDR("invalid-cidr")).To(BeFalse())
		})
	})

	Describe("HasIPv6NodeCIDR", func() {
		It("should return true if any node CIDR is IPv6", func() {
			cluster := &extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{
						Networking: &gardencorev1beta1.NetworkingStatus{
							Nodes: []string{"192.168.0.0/24", "2001:db8::/64"},
						},
					},
				},
			}
			Expect(HasIPv6NodeCIDR(cluster)).To(BeTrue())
		})

		It("should return false if all node CIDRs are IPv4", func() {
			cluster := &extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{
						Networking: &gardencorev1beta1.NetworkingStatus{
							Nodes: []string{"192.168.0.0/24"},
						},
					},
				},
			}
			Expect(HasIPv6NodeCIDR(cluster)).To(BeFalse())
		})

		It("should return false if cluster or networking is nil", func() {
			Expect(HasIPv6NodeCIDR(nil)).To(BeFalse())
			Expect(HasIPv6NodeCIDR(&extensionscontroller.Cluster{})).To(BeFalse())
			Expect(HasIPv6NodeCIDR(&extensionscontroller.Cluster{Shoot: &gardencorev1beta1.Shoot{}})).To(BeFalse())
			Expect(HasIPv6NodeCIDR(&extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{
						Networking: nil,
					},
				},
			})).To(BeFalse())
		})
	})
})
