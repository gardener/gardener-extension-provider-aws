// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var _ = Describe("computeNodesSecurityGroupBaseRules", func() {
	containsSelfEgress := func(rules []*awsclient.SecurityGroupRule) bool {
		for _, r := range rules {
			if r.Type == awsclient.SecurityGroupRuleTypeEgress && r.Self && r.Protocol == "-1" {
				return true
			}
		}
		return false
	}

	It("no EFA worker → no self-referencing egress rule", func() {
		c := &FlowContext{
			networking:   &v1beta1.Networking{IPFamilies: []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}},
			hasEFAWorker: false,
		}
		rules := c.computeNodesSecurityGroupBaseRules()

		Expect(rules).To(HaveLen(4))
		Expect(containsSelfEgress(rules)).To(BeFalse())
	})

	It("EFA worker → self-referencing egress rule appended", func() {
		c := &FlowContext{
			networking:   &v1beta1.Networking{IPFamilies: []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}},
			hasEFAWorker: true,
		}
		rules := c.computeNodesSecurityGroupBaseRules()

		Expect(rules).To(HaveLen(5))
		Expect(containsSelfEgress(rules)).To(BeTrue())

		last := rules[len(rules)-1]
		Expect(last.Type).To(Equal(awsclient.SecurityGroupRuleTypeEgress))
		Expect(last.Protocol).To(Equal("-1"))
		Expect(last.Self).To(BeTrue())
		Expect(last.CidrBlocks).To(BeNil())
		Expect(last.CidrBlocksv6).To(BeNil())
	})

	It("base rules unchanged when EFA enabled", func() {
		cNoEFA := &FlowContext{
			networking:   &v1beta1.Networking{IPFamilies: []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}},
			hasEFAWorker: false,
		}
		cWithEFA := &FlowContext{
			networking:   &v1beta1.Networking{IPFamilies: []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}},
			hasEFAWorker: true,
		}

		baseRules := cNoEFA.computeNodesSecurityGroupBaseRules()
		efaRules := cWithEFA.computeNodesSecurityGroupBaseRules()

		Expect(efaRules[:4]).To(Equal(baseRules))
	})

	It("IPv6-only worker pool emits IPv6 CIDRs and still gets EFA rule", func() {
		c := &FlowContext{
			networking:   &v1beta1.Networking{IPFamilies: []v1beta1.IPFamily{v1beta1.IPFamilyIPv6}},
			hasEFAWorker: true,
		}
		rules := c.computeNodesSecurityGroupBaseRules()

		Expect(rules).To(HaveLen(5))
		Expect(rules[3].Type).To(Equal(awsclient.SecurityGroupRuleTypeEgress))
		Expect(rules[3].CidrBlocks).To(BeNil())
		Expect(rules[3].CidrBlocksv6).To(Equal([]string{allIPv6}))
		Expect(rules[4].Self).To(BeTrue())
		Expect(rules[4].CidrBlocks).To(BeNil())
		Expect(rules[4].CidrBlocksv6).To(BeNil())
	})
})
