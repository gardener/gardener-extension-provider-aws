// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"testing"

	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/gomega"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

func TestComputeNodesSecurityGroupBaseRules(t *testing.T) {
	containsSelfEgress := func(rules []*awsclient.SecurityGroupRule) bool {
		for _, r := range rules {
			if r.Type == awsclient.SecurityGroupRuleTypeEgress && r.Self && r.Protocol == "-1" {
				return true
			}
		}
		return false
	}

	t.Run("no EFA worker → no self-referencing egress rule", func(t *testing.T) {
		g := NewWithT(t)
		c := &FlowContext{
			networking:   &v1beta1.Networking{IPFamilies: []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}},
			hasEFAWorker: false,
		}
		rules := c.computeNodesSecurityGroupBaseRules()

		g.Expect(rules).To(HaveLen(4))
		g.Expect(containsSelfEgress(rules)).To(BeFalse())
	})

	t.Run("EFA worker → self-referencing egress rule appended", func(t *testing.T) {
		g := NewWithT(t)
		c := &FlowContext{
			networking:   &v1beta1.Networking{IPFamilies: []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}},
			hasEFAWorker: true,
		}
		rules := c.computeNodesSecurityGroupBaseRules()

		g.Expect(rules).To(HaveLen(5))
		g.Expect(containsSelfEgress(rules)).To(BeTrue())

		// last rule should be the EFA self-ref egress rule
		last := rules[len(rules)-1]
		g.Expect(last.Type).To(Equal(awsclient.SecurityGroupRuleTypeEgress))
		g.Expect(last.Protocol).To(Equal("-1"))
		g.Expect(last.Self).To(BeTrue())
		g.Expect(last.CidrBlocks).To(BeNil())
		g.Expect(last.CidrBlocksv6).To(BeNil())
	})

	t.Run("base rules unchanged when EFA enabled", func(t *testing.T) {
		g := NewWithT(t)
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

		// the first 4 rules must match exactly
		g.Expect(efaRules[:4]).To(Equal(baseRules))
	})

	t.Run("IPv6-only worker pool emits IPv6 CIDRs and still gets EFA rule", func(t *testing.T) {
		g := NewWithT(t)
		c := &FlowContext{
			networking:   &v1beta1.Networking{IPFamilies: []v1beta1.IPFamily{v1beta1.IPFamilyIPv6}},
			hasEFAWorker: true,
		}
		rules := c.computeNodesSecurityGroupBaseRules()

		g.Expect(rules).To(HaveLen(5))
		// the v4 0.0.0.0/0 egress rule (index 3) should have only v6 CIDRs
		g.Expect(rules[3].Type).To(Equal(awsclient.SecurityGroupRuleTypeEgress))
		g.Expect(rules[3].CidrBlocks).To(BeNil())
		g.Expect(rules[3].CidrBlocksv6).To(Equal([]string{allIPv6}))
		// the EFA rule has no CIDRs
		g.Expect(rules[4].Self).To(BeTrue())
		g.Expect(rules[4].CidrBlocks).To(BeNil())
		g.Expect(rules[4].CidrBlocksv6).To(BeNil())
	})
}
