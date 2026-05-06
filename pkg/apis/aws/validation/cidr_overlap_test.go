// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

var _ = Describe("CIDRsOverlap", func() {
	It("should detect overlapping CIDRs", func() {
		Expect(CIDRsOverlap("10.0.0.0/16", "10.0.1.0/24")).To(BeTrue())
	})

	It("should detect identical CIDRs", func() {
		Expect(CIDRsOverlap("10.0.0.0/16", "10.0.0.0/16")).To(BeTrue())
	})

	It("should not overlap for distinct CIDRs", func() {
		Expect(CIDRsOverlap("10.0.0.0/16", "10.1.0.0/16")).To(BeFalse())
	})

	It("should not overlap for completely separate ranges", func() {
		Expect(CIDRsOverlap("10.0.0.0/8", "172.16.0.0/12")).To(BeFalse())
	})

	It("should handle invalid CIDRs gracefully", func() {
		Expect(CIDRsOverlap("invalid", "10.0.0.0/16")).To(BeFalse())
		Expect(CIDRsOverlap("10.0.0.0/16", "invalid")).To(BeFalse())
	})

	It("should detect supernet containing subnet", func() {
		Expect(CIDRsOverlap("10.0.0.0/8", "10.180.0.0/16")).To(BeTrue())
	})
})

var _ = Describe("ValidateShootCIDROverlap", func() {
	var (
		fldPath  *field.Path
		reserved []ReservedCIDR
	)

	BeforeEach(func() {
		fldPath = field.NewPath("spec", "networking", "nodes")
		reserved = []ReservedCIDR{
			{CIDR: "10.180.0.0/16", Owner: "shoot-a", Reason: "shoot VPC CIDR"},
			{CIDR: "10.250.0.0/20", Owner: "runtime cluster", Reason: "runtime VPC"},
			{CIDR: "10.60.0.0/16", Owner: "management", Reason: "globalVPC"},
		}
	})

	It("should reject overlapping CIDR", func() {
		errs := ValidateShootCIDROverlap(fldPath, "10.180.0.0/16", "new-shoot", nil, reserved, nil)
		Expect(errs).NotTo(BeEmpty())
		Expect(errs[0].Detail).To(ContainSubstring("overlaps"))
	})

	It("should accept non-overlapping CIDR", func() {
		errs := ValidateShootCIDROverlap(fldPath, "10.101.0.0/16", "new-shoot", nil, reserved, nil)
		Expect(errs).To(BeEmpty())
	})

	It("should allow empty CIDR", func() {
		errs := ValidateShootCIDROverlap(fldPath, "", "new-shoot", nil, reserved, nil)
		Expect(errs).To(BeEmpty())
	})

	It("should allow empty reserved list", func() {
		errs := ValidateShootCIDROverlap(fldPath, "10.180.0.0/16", "new-shoot", nil, nil, nil)
		Expect(errs).To(BeEmpty())
	})

	It("should detect overlap with runtime VPC", func() {
		errs := ValidateShootCIDROverlap(fldPath, "10.250.0.0/24", "new-shoot", nil, reserved, nil)
		Expect(errs).NotTo(BeEmpty())
		Expect(errs[0].Detail).To(ContainSubstring("runtime VPC"))
	})
})

var _ = Describe("BuildReservedCIDRs", func() {
	It("should include seed nodes, runtime VPC, and globalVPC CIDRs", func() {
		seedConfig := &apisaws.SeedProviderConfig{
			TransitGateway: &apisaws.TransitGateway{
				Enabled: true,
				GlobalVPCs: []apisaws.GlobalVPC{
					{Name: "management", CIDRs: []string{"10.60.0.0/16"}},
				},
			},
		}
		reserved := BuildReservedCIDRs("my-seed", seedConfig, "10.180.0.0/16", "10.250.0.0/20", nil, "")

		Expect(reserved).To(HaveLen(3))
		cidrs := make([]string, len(reserved))
		for i, r := range reserved {
			cidrs[i] = r.CIDR
		}
		Expect(cidrs).To(ContainElements("10.250.0.0/20", "10.180.0.0/16", "10.60.0.0/16"))
	})

	It("should exclude current shoot from existing shoots", func() {
		existing := map[string]string{
			"shoot-a": "10.101.0.0/16",
			"shoot-b": "10.102.0.0/16",
		}
		reserved := BuildReservedCIDRs("my-seed", nil, "", "", existing, "shoot-a")

		cidrs := make([]string, len(reserved))
		for i, r := range reserved {
			cidrs[i] = r.CIDR
		}
		Expect(cidrs).To(ContainElement("10.102.0.0/16"))
		Expect(cidrs).NotTo(ContainElement("10.101.0.0/16"))
	})

	It("should handle nil seed config", func() {
		reserved := BuildReservedCIDRs("my-seed", nil, "10.180.0.0/16", "", nil, "")
		Expect(reserved).To(HaveLen(1))
		Expect(reserved[0].CIDR).To(Equal("10.180.0.0/16"))
	})
})
