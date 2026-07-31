// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var _ = DescribeTableSubtree("#ensureVpc",
	func(setup func(f *flowContextFixture), checkDesiredVpc func(f *flowContextFixture, desired *awsclient.VPC)) {
		var f flowContextFixture
		BeforeEach(func() {
			f.setup()
			setup(&f)
		})

		It("should create a new VPC if none exists", func() {
			vpcArg := &awsclient.VPC{}
			*vpcArg = *f.vpc
			vpcArg.VpcId = ""
			vpcArg.IPv6CidrBlock = ""
			f.c.state.Set(IdentifierDHCPOptions, f.dhcpOptions.DhcpOptionsId)
			f.client.EXPECT().FindVpcsByTags(f.ctx, f.tags).Return(nil, nil).Times(1)
			f.client.EXPECT().CreateVpc(f.ctx, vpcArg).Return(f.vpc, nil).Times(1)
			f.updater.EXPECT().UpdateVpc(f.ctx, gomock.Any(), f.vpc).DoAndReturn(
				func(_ context.Context, desired, _ *awsclient.VPC) (bool, error) {
					checkDesiredVpc(&f, desired)
					return true, nil
				}).Times(1)
			Expect(f.c.ensureVpc(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierVPC)).To(HaveValue(Equal(f.vpc.VpcId)))
		})

		It("should use an existing VPC if it can be found by tags", func() {
			f.c.state.Set(IdentifierDHCPOptions, f.dhcpOptions.DhcpOptionsId)
			f.client.EXPECT().FindVpcsByTags(f.ctx, f.tags).Return([]*awsclient.VPC{f.vpc}, nil).Times(1)
			f.updater.EXPECT().UpdateVpc(f.ctx, gomock.Any(), f.vpc).DoAndReturn(
				func(_ context.Context, desired, _ *awsclient.VPC) (bool, error) {
					checkDesiredVpc(&f, desired)
					return true, nil
				}).Times(1)
			Expect(f.c.ensureVpc(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierVPC)).To(HaveValue(Equal(f.vpc.VpcId)))
			if f.c.isIPv6Enabled() {
				Expect(f.c.state.Get(IdentifierVpcIPv6CidrBlock)).To(HaveValue(Equal(f.vpc.IPv6CidrBlock)))
			} else {
				Expect(f.c.state.Get(IdentifierVpcIPv6CidrBlock)).To(BeNil())
			}
		})

		It("should use an existing VPC if it can be found by ID", func() {
			f.c.state.Set(IdentifierVPC, f.vpc.VpcId)
			f.client.EXPECT().GetVpc(f.ctx, f.vpc.VpcId).Return(f.vpc, nil).Times(1)
			f.updater.EXPECT().UpdateVpc(f.ctx, gomock.Any(), f.vpc).DoAndReturn(
				func(_ context.Context, desired, _ *awsclient.VPC) (bool, error) {
					checkDesiredVpc(&f, desired)
					return true, nil
				}).Times(1)
			Expect(f.c.ensureVpc(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierVPC)).To(HaveValue(Equal(f.vpc.VpcId)))
			if f.c.isIPv6Enabled() {
				Expect(f.c.state.Get(IdentifierVpcIPv6CidrBlock)).To(HaveValue(Equal(f.vpc.IPv6CidrBlock)))
			} else {
				Expect(f.c.state.Get(IdentifierVpcIPv6CidrBlock)).To(BeNil())
			}
		})

		It("should use an existing VPC if can be found by ID passed via the provider config", func() {
			// Use a zone with a managed public CIDR so hasManagedPublicSubnets() returns true
			// and the Internet Gateway lookup is triggered (this branch conditionalizes the IGW
			// lookup on hasManagedPublicSubnets — see ensureExistingVpc).
			publicCIDR := "10.11.32.0/20"
			f.c.config.Networks.Zones = []aws.Zone{{Name: "eu-central-1a", Public: &publicCIDR}}
			f.c.config.Networks.VPC.ID = &f.vpc.VpcId
			f.client.EXPECT().GetVpc(f.ctx, f.vpc.VpcId).Return(f.vpc, nil).Times(1)
			f.client.EXPECT().GetVpcDhcpOptions(f.ctx, f.dhcpOptions.DhcpOptionsId).Return(f.dhcpOptions, nil).Times(1)
			f.client.EXPECT().FindInternetGatewayByVPC(f.ctx, f.vpc.VpcId).Return(f.internetGateway, nil).Times(1)
			if ContainsIPv6(f.c.getIpFamilies()) {
				f.client.EXPECT().FindEgressOnlyInternetGatewayByVPC(f.ctx, f.vpc.VpcId).Return(f.egressGateway, nil).Times(1)
			}
			Expect(f.c.ensureVpc(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierVPC)).To(HaveValue(Equal(f.vpc.VpcId)))
			Expect(f.c.state.Get(IdentifierInternetGateway)).To(HaveValue(Equal(f.internetGateway.InternetGatewayId)))
		})
	},
	Entry("IPv4 only",
		func(f *flowContextFixture) { f.setupIPv4Only() },
		func(_ *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
			Expect(desired.Ipv6CidrBlock).To(BeNil())
			Expect(desired.Ipv6IpamPoolId).To(BeNil())
		},
	),
	Entry("IPv6 only",
		func(f *flowContextFixture) { f.setupIPv6Only() },
		func(_ *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeTrue())
			Expect(desired.Ipv6CidrBlock).To(BeNil())
			Expect(desired.Ipv6IpamPoolId).To(BeNil())
		},
	),
	Entry("IPv6 only with IPv6 IPAM Pool",
		func(f *flowContextFixture) { f.setupIPv6Only(); f.setupIPAMPool(withoutCIDR) },
		func(f *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
			Expect(desired.Ipv6CidrBlock).To(BeNil())
			Expect(desired.Ipv6IpamPoolId).To(HaveValue(Equal(f.ipv6IPAMPoolId)))
			Expect(desired.Ipv6NetmaskLength).To(HaveValue(Equal(int32(defaultIPv6NetmaskSize))))
		},
	),
	Entry("IPv6 only with IPv6 IPAM Pool and preconfigured CIDR",
		func(f *flowContextFixture) { f.setupIPv6Only(); f.setupIPAMPool(withCIDR) },
		func(f *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
			Expect(desired.Ipv6CidrBlock).To(HaveValue(Equal(f.ipv6Cidr)))
			Expect(desired.Ipv6IpamPoolId).To(HaveValue(Equal(f.ipv6IPAMPoolId)))
			Expect(desired.Ipv6NetmaskLength).To(BeNil())
		},
	),
	Entry("DualStack via IPFamilies",
		func(f *flowContextFixture) { f.setupDualStack(dualStackViaFamilies) },
		func(_ *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeTrue())
			Expect(desired.Ipv6CidrBlock).To(BeNil())
			Expect(desired.Ipv6IpamPoolId).To(BeNil())
		},
	),
	Entry("DualStack via IPFamilies with IPv6 IPAM Pool",
		func(f *flowContextFixture) { f.setupDualStack(dualStackViaFamilies); f.setupIPAMPool(withoutCIDR) },
		func(f *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
			Expect(desired.Ipv6CidrBlock).To(BeNil())
			Expect(desired.Ipv6IpamPoolId).To(HaveValue(Equal(f.ipv6IPAMPoolId)))
			Expect(desired.Ipv6NetmaskLength).To(HaveValue(Equal(int32(defaultIPv6NetmaskSize))))
		},
	),
	Entry("DualStack via IPFamilies with IPv6 IPAM Pool and preconfigured CIDR",
		func(f *flowContextFixture) { f.setupDualStack(dualStackViaFamilies); f.setupIPAMPool(withCIDR) },
		func(f *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
			Expect(desired.Ipv6CidrBlock).To(HaveValue(Equal(f.ipv6Cidr)))
			Expect(desired.Ipv6IpamPoolId).To(HaveValue(Equal(f.ipv6IPAMPoolId)))
			Expect(desired.Ipv6NetmaskLength).To(BeNil())
		},
	),
	Entry("DualStack via InfrastructureConfig",
		func(f *flowContextFixture) { f.setupDualStack(dualStackViaInfraConfig) },
		func(_ *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeTrue())
			Expect(desired.Ipv6CidrBlock).To(BeNil())
			Expect(desired.Ipv6IpamPoolId).To(BeNil())
		},
	),
	Entry("DualStack via InfrastructureConfig with IPv6 IPAM Pool",
		func(f *flowContextFixture) { f.setupDualStack(dualStackViaInfraConfig); f.setupIPAMPool(withoutCIDR) },
		func(f *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
			Expect(desired.Ipv6CidrBlock).To(BeNil())
			Expect(desired.Ipv6IpamPoolId).To(HaveValue(Equal(f.ipv6IPAMPoolId)))
			Expect(desired.Ipv6NetmaskLength).To(HaveValue(Equal(int32(defaultIPv6NetmaskSize))))
		},
	),
	Entry("DualStack via InfrastructureConfig with IPv6 IPAM Pool and preconfigured CIDR",
		func(f *flowContextFixture) { f.setupDualStack(dualStackViaInfraConfig); f.setupIPAMPool(withCIDR) },
		func(f *flowContextFixture, desired *awsclient.VPC) {
			Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
			Expect(desired.Ipv6CidrBlock).To(HaveValue(Equal(f.ipv6Cidr)))
			Expect(desired.Ipv6IpamPoolId).To(HaveValue(Equal(f.ipv6IPAMPoolId)))
			Expect(desired.Ipv6NetmaskLength).To(BeNil())
		},
	),
)

var _ = Describe("#ensureExistingVpc", func() {
	var f flowContextFixture
	BeforeEach(func() {
		f.setup()
		f.c.config.Networks.VPC.ID = &f.vpc.VpcId
	})

	It("should skip the IGW lookup when no managed public subnets exist (fully BYO)", func() {
		// isBYOInfrastructure() = true (WorkersSubnetID set), hasManagedPublicSubnets() = false (no zone.Public)
		f.setupIPv4Only()
		workerSubnetID := "subnet-workers-byo"
		f.c.config.Networks.Zones = []aws.Zone{{Name: "eu-central-1a", WorkersSubnetID: &workerSubnetID}}
		f.client.EXPECT().GetVpc(f.ctx, f.vpc.VpcId).Return(f.vpc, nil).Times(1)
		f.client.EXPECT().GetVpcDhcpOptions(f.ctx, f.dhcpOptions.DhcpOptionsId).Return(f.dhcpOptions, nil).Times(1)
		// FindInternetGatewayByVPC must NOT be called — no managed public subnets.
		Expect(f.c.ensureVpc(f.ctx)).To(Succeed())
		Expect(f.c.state.Get(IdentifierVPC)).To(HaveValue(Equal(f.vpc.VpcId)))
		Expect(f.c.state.Get(IdentifierInternetGateway)).To(BeNil())
	})
})

var _ = Describe("#ensureVpcIPv6CidrBlock", func() {
	var f flowContextFixture
	BeforeEach(func() {
		f.setup()
		f.c.state.Set(IdentifierVPC, f.vpc.VpcId)
	})

	It("should do nothing if the cluster is IPv4 only", func() {
		f.setupIPv4Only()
		Expect(f.c.ensureVpcIPv6CidrBlock(f.ctx)).To(Succeed())
		Expect(f.c.state.Get(IdentifierVpcIPv6CidrBlock)).To(BeNil())
	})
	It("should wait for an IPv6 CIDR block if the cluster is IPv6 only", func() {
		f.setupIPv6Only()
		f.client.EXPECT().WaitForIPv6Cidr(f.ctx, f.vpc.VpcId).Return(f.ipv6Cidr, nil).Times(1)
		Expect(f.c.ensureVpcIPv6CidrBlock(f.ctx)).To(Succeed())
		Expect(f.c.state.Get(IdentifierVpcIPv6CidrBlock)).To(HaveValue(Equal(f.ipv6Cidr)))
	})
	It("should wait for an IPv6 CIDR block if the cluster is dual-stack configured via IPFamilies", func() {
		f.setupDualStack(dualStackViaFamilies)
		f.client.EXPECT().WaitForIPv6Cidr(f.ctx, f.vpc.VpcId).Return(f.ipv6Cidr, nil).Times(1)
		Expect(f.c.ensureVpcIPv6CidrBlock(f.ctx)).To(Succeed())
		Expect(f.c.state.Get(IdentifierVpcIPv6CidrBlock)).To(HaveValue(Equal(f.ipv6Cidr)))
	})
	It("should wait for an IPv6 CIDR block if the cluster is dual-stack configured via InfrastructureConfig", func() {
		f.setupDualStack(dualStackViaInfraConfig)
		f.client.EXPECT().WaitForIPv6Cidr(f.ctx, f.vpc.VpcId).Return(f.ipv6Cidr, nil).Times(1)
		Expect(f.c.ensureVpcIPv6CidrBlock(f.ctx)).To(Succeed())
		Expect(f.c.state.Get(IdentifierVpcIPv6CidrBlock)).To(HaveValue(Equal(f.ipv6Cidr)))
	})
})

var _ = DescribeTable("#computeNodesSecurityGroupBaseRules",
	func(setup func(f *flowContextFixture)) {
		var f flowContextFixture
		f.setup()
		setup(&f)

		rules := f.c.computeNodesSecurityGroupBaseRules()
		Expect(rules).ToNot(BeNil())

		v4Cidrs := func() []string {
			if containsIPv4(f.c.getIpFamilies()) {
				return []string{"0.0.0.0/0"}
			}
			return nil
		}
		v6Cidrs := func() []string {
			if ContainsIPv6(f.c.getIpFamilies()) {
				return []string{"::/0"}
			}
			return nil
		}
		checkRule := func(expected awsclient.SecurityGroupRule) {
			for i, rule := range rules {
				if rule != nil {
					if ok, _ := Equal(expected).Match(*rule); ok {
						rules[i] = nil
						return
					}
				}
			}
			Fail("expected rule not found: " + fmt.Sprintf("%+v", expected))
		}

		checkRule(awsclient.SecurityGroupRule{Type: awsclient.SecurityGroupRuleTypeIngress, Protocol: "-1", Self: true})
		checkRule(awsclient.SecurityGroupRule{
			Type: awsclient.SecurityGroupRuleTypeIngress, Protocol: "tcp",
			FromPort: ptr.To[int32](nodePortMin), ToPort: ptr.To[int32](nodePortMax),
			CidrBlocks: v4Cidrs(), CidrBlocksv6: v6Cidrs(),
		})
		checkRule(awsclient.SecurityGroupRule{
			Type: awsclient.SecurityGroupRuleTypeIngress, Protocol: "udp",
			FromPort: ptr.To[int32](nodePortMin), ToPort: ptr.To[int32](nodePortMax),
			CidrBlocks: v4Cidrs(), CidrBlocksv6: v6Cidrs(),
		})
		checkRule(awsclient.SecurityGroupRule{
			Type: awsclient.SecurityGroupRuleTypeEgress, Protocol: "-1",
			CidrBlocks: v4Cidrs(), CidrBlocksv6: v6Cidrs(),
		})
		if f.c.hasEFAWorker {
			checkRule(awsclient.SecurityGroupRule{Type: awsclient.SecurityGroupRuleTypeEgress, Protocol: "-1", Self: true})
		}

		var unchecked []*awsclient.SecurityGroupRule
		for _, r := range rules {
			if r != nil {
				unchecked = append(unchecked, r)
			}
		}
		Expect(unchecked).To(BeEmpty())
	},
	Entry("IPv4 only, no EFA", func(f *flowContextFixture) { f.setupIPv4Only() }),
	Entry("IPv6 only, no EFA", func(f *flowContextFixture) { f.setupIPv6Only() }),
	Entry("DualStack via IPFamilies, no EFA", func(f *flowContextFixture) { f.setupDualStack(dualStackViaFamilies) }),
	Entry("DualStack via InfrastructureConfig, no EFA", func(f *flowContextFixture) { f.setupDualStack(dualStackViaInfraConfig) }),
	Entry("IPv4 only, with EFA", func(f *flowContextFixture) { f.setupIPv4Only(); f.c.hasEFAWorker = true }),
	Entry("IPv6 only, with EFA", func(f *flowContextFixture) { f.setupIPv6Only(); f.c.hasEFAWorker = true }),
	Entry("DualStack via IPFamilies, with EFA", func(f *flowContextFixture) { f.setupDualStack(dualStackViaFamilies); f.c.hasEFAWorker = true }),
	Entry("DualStack via InfrastructureConfig, with EFA", func(f *flowContextFixture) { f.setupDualStack(dualStackViaInfraConfig); f.c.hasEFAWorker = true }),
)
