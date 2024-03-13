// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/pointer"

	. "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var _ = Describe("SecurityGroup", func() {
	var (
		rules1 = []*SecurityGroupRule{
			{
				Type:     SecurityGroupRuleTypeIngress,
				Protocol: "-1",
				Self:     true,
			},
			{
				Type:       SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "tcp",
				CidrBlocks: []string{"0.0.0.0/0"},
			},
			{
				Type:       SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "udp",
				CidrBlocks: []string{"0.0.0.0/0"},
			},
			{
				Type:       SecurityGroupRuleTypeEgress,
				Protocol:   "-1",
				CidrBlocks: []string{"0.0.0.0/0"},
			},
		}
		rules2 = []*SecurityGroupRule{
			{
				Type:       SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "udp",
				CidrBlocks: []string{"10.0.0.0/8"},
			},
			{
				Type:     SecurityGroupRuleTypeIngress,
				Protocol: "-1",
				Self:     true,
			},
		}
		sg1 = &SecurityGroup{
			GroupId:   "sg-1",
			GroupName: "sg1",
			VpcId:     pointer.String("vpc-1"),
			Rules:     rules1,
		}
		clone1  = sg1.SortedClone()
		clone1b = sg1.Clone()
		sg2     = &SecurityGroup{
			GroupId:   "sg-2",
			GroupName: "sg2",
			VpcId:     pointer.String("vpc-1"),
			Rules:     rules2,
		}
		sg3 = &SecurityGroup{
			GroupId:   "sg-3",
			GroupName: "sg3",
			VpcId:     pointer.String("vpc-1"),
		}
	)

	clone1b.Rules = clone1b.Rules[2:]

	Describe("#SortedClone", func() {
		It("should copy all rules", func() {
			Expect(clone1.GroupId).To(Equal(sg1.GroupId))
			Expect(clone1.GroupName).To(Equal(sg1.GroupName))
			Expect(clone1.VpcId).To(Equal(sg1.VpcId))
			Expect(len(clone1.Rules)).To(Equal(len(sg1.Rules)))
		outer:
			for i, r1 := range clone1.Rules {
				for _, r2 := range sg1.Rules {
					if reflect.DeepEqual(r1, r2) {
						continue outer
					}
				}
				Fail(fmt.Sprintf("rule not found: %d %v", i, *r1))
			}
		})
	})

	DescribeTable("#EquivalentRules",
		func(a, b *SecurityGroup, expectedEqual bool) {
			Expect(a.EquivalentRulesTo(b)).To(Equal(expectedEqual))
		},

		Entry("sg1-sg1", sg1, sg1, true),
		Entry("sg1-clone1", sg1, clone1, true),
		Entry("clone1-sg1", clone1, sg1, true),
		Entry("sg1-sg2", sg1, sg2, false),
	)

	DescribeTable("#DiffRules",
		func(a, b *SecurityGroup, expectedAddedCount, expectedRemovedCount int) {
			added, removed := a.DiffRules(b)
			Expect(len(added)).To(Equal(expectedAddedCount))
			Expect(len(removed)).To(Equal(expectedRemovedCount))
		},

		Entry("sg1-sg1", sg1, sg1, 0, 0),
		Entry("sg1-clone1", sg1, clone1, 0, 0),
		Entry("clone1-sg1", clone1, sg1, 0, 0),
		Entry("sg1-clone1b", sg1, clone1b, 2, 0),
		Entry("clone1-clone1b", clone1, clone1b, 2, 0),
		Entry("clone1b-sg1", clone1b, sg1, 0, 2),
		Entry("clone1b-clone1", clone1b, clone1, 0, 2),
		Entry("sg1-sg2", sg1, sg2, 3, 1),
		Entry("sg2-sg1", sg2, sg1, 1, 3),
		Entry("sg1-sg3", sg1, sg3, 4, 0),
		Entry("sg3-sg1", sg3, sg1, 0, 4),
	)
})
