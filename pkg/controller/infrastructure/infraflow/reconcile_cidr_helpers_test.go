// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("#cidrSubnet", func() {
	DescribeTable("should, for a given base CIDR, prefix length, and subnet index, calculate",
		func(baseCIDR string, prefixLen int, subnetIndex int, expectedSubnet string) {
			subnet, err := cidrSubnet(baseCIDR, prefixLen, subnetIndex)
			Expect(err).ToNot(HaveOccurred())
			Expect(subnet).To(Equal(expectedSubnet))
		},
		Entry("the first IPv4 subnet", "10.0.0.0/16", 24, 0, "10.0.0.0/24"),
		Entry("the second IPv4 subnet", "10.0.0.0/16", 24, 1, "10.0.1.0/24"),
		Entry("the last IPv4 subnet", "10.0.0.0/16", 24, 255, "10.0.255.0/24"),
		Entry("the first IPv6 subnet", "2001:db8:500::/40", 60, 0, "2001:db8:500::/60"),
		Entry("the second IPv6 subnet", "2001:db8:500::/40", 60, 1, "2001:db8:500:10::/60"),
		Entry("the last IPv6 subnet", "2001:db8:500::/40", 60, 0xfffff, "2001:db8:5ff:fff0::/60"),
	)
	It("should return an error when the base CIDR is invalid", func() {
		_, err := cidrSubnet("invalid-cidr", 24, 0)
		Expect(err).To(HaveOccurred())
	})
	It("should return an error when the prefix length is greater than the address length", func() {
		_, err := cidrSubnet("10.0.0.0/16", 33, 0)
		Expect(err).To(HaveOccurred())
		_, err = cidrSubnet("2001:db8:500::/40", 129, 0)
		Expect(err).To(HaveOccurred())
	})
	// One could argue that this should not be an error, as it is a valid mapping of a single subnet to the base CIDR
	It("should return an error when the prefix length equals the base cidr prefix length", func() {
		_, err := cidrSubnet("10.0.0.0/16", 16, 0)
		Expect(err).To(HaveOccurred())
		_, err = cidrSubnet("2001:db8:500::/40", 40, 0)
		Expect(err).To(HaveOccurred())
	})
	It("should return an error when the prefix length is less than the base cidr prefix length", func() {
		_, err := cidrSubnet("10.0.0.0/16", 15, 0)
		Expect(err).To(HaveOccurred())
		_, err = cidrSubnet("2001:db8:500::/40", 39, 0)
		Expect(err).To(HaveOccurred())
	})
	It("should return an error when the subnet index is negative", func() {
		_, err := cidrSubnet("10.0.0.0/16", 24, -1)
		Expect(err).To(HaveOccurred())
		_, err = cidrSubnet("2001:db8:500::/40", 60, -1)
		Expect(err).To(HaveOccurred())
	})
	It("should return an error when the IPv4 subnet index is out of range", func() {
		_, err := cidrSubnet("10.0.0.0/16", 24, 256)
		Expect(err).To(HaveOccurred())
	})
	It("should return an error when the IPv6 subnet index is out of range", func() {
		_, err := cidrSubnet("2001:db8:500::/40", 60, 0x100000)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("#calcNextIPv6CidrBlock", func() {
	DescribeTable("should calculate the ",
		func(currentCIDR string, expectedNextCIDR string) {
			nextCIDR, err := calcNextIPv6CidrBlock(currentCIDR)
			Expect(err).ToNot(HaveOccurred())
			Expect(nextCIDR).To(Equal(expectedNextCIDR))
		},
		Entry("next IPv6 CIDR block for 2001:db8::1/64", "2001:db8:0:1::/64", "2001:db8:0:2::/64"),
		Entry("next IPv6 CIDR block for 2001:db8:ffff:fffe::/64", "2001:db8:ffff:fffe::/64", "2001:db8:ffff:ffff::/64"),
	)
	It("Should return an error when the last IPv6 CIDR block is reached", func() {
		// The corresponding /56 block is 2001:db8:ffff:ff00::/56, and the last /64 block is 2001:db8:ffff:ffff::/64
		_, err := calcNextIPv6CidrBlock("2001:db8:ffff:ffff::/64")
		Expect(err).To(HaveOccurred())
	})
	It("Should return an error when the input CIDR is invalid", func() {
		_, err := calcNextIPv6CidrBlock("invalid-cidr")
		Expect(err).To(HaveOccurred())
	})
	It("Should return an error when the input CIDR is not IPv6", func() {
		_, err := calcNextIPv6CidrBlock("10.0.0.0/16")
		Expect(err).To(HaveOccurred())
	})
})
