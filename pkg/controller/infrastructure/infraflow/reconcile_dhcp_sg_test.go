// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"

	core "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var _ = Describe("#FlowContext", func() {
	var f flowContextFixture
	BeforeEach(func() { f.setup() })

	Describe("#getIPFamilies", func() {
		It("should return IPv4 when networking is not set", func() {
			f.c.networking = nil
			Expect(f.c.getIpFamilies()).To(ConsistOf(core.IPFamilyIPv4))
		})
	})

	Describe("#getDesiredDhcpOptions", func() {
		It("should set the correct domain name for us-east-1", func() {
			f.c.infraSpec.Region = "us-east-1"
			f.dhcpOptions.DhcpOptionsId = ""
			f.dhcpOptions.DhcpConfigurations["domain-name"] = []string{"ec2.internal"}
			Expect(f.c.getDesiredDhcpOptions()).To(Equal(f.dhcpOptions))
		})
		It("should set the correct domain name for other regions", func() {
			f.dhcpOptions.DhcpOptionsId = ""
			Expect(f.c.getDesiredDhcpOptions()).To(Equal(f.dhcpOptions))
		})
	})

	Describe("#ensureDhcpOptions", func() {
		It("should create new DHCP options if none exist", func() {
			dhcpOptionsArg := &awsclient.DhcpOptions{}
			*dhcpOptionsArg = *f.dhcpOptions
			dhcpOptionsArg.DhcpOptionsId = ""
			f.client.EXPECT().FindVpcDhcpOptionsByTags(f.ctx, f.tags).Return(nil, nil).Times(1)
			f.client.EXPECT().CreateVpcDhcpOptions(f.ctx, dhcpOptionsArg).Return(f.dhcpOptions, nil).Times(1)
			Expect(f.c.ensureDhcpOptions(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierDHCPOptions)).To(HaveValue(Equal(f.dhcpOptions.DhcpOptionsId)))
		})
		It("should use existing DHCP options if they can be found by tags", func() {
			f.client.EXPECT().FindVpcDhcpOptionsByTags(f.ctx, f.tags).Return([]*awsclient.DhcpOptions{f.dhcpOptions}, nil).Times(1)
			f.updater.EXPECT().UpdateEC2Tags(f.ctx, f.dhcpOptions.DhcpOptionsId, f.c.commonTags, f.dhcpOptions.Tags).Return(false, nil).Times(1)
			Expect(f.c.ensureDhcpOptions(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierDHCPOptions)).To(HaveValue(Equal(f.dhcpOptions.DhcpOptionsId)))
		})
		It("should use existing DHCP options if they can be found by ID", func() {
			f.c.state.Set(IdentifierDHCPOptions, f.dhcpOptions.DhcpOptionsId)
			f.client.EXPECT().GetVpcDhcpOptions(f.ctx, f.dhcpOptions.DhcpOptionsId).Return(f.dhcpOptions, nil).Times(1)
			f.updater.EXPECT().UpdateEC2Tags(f.ctx, f.dhcpOptions.DhcpOptionsId, f.c.commonTags, f.dhcpOptions.Tags).Return(false, nil).Times(1)
			Expect(f.c.ensureDhcpOptions(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierDHCPOptions)).To(HaveValue(Equal(f.dhcpOptions.DhcpOptionsId)))
		})
	})

	Describe("#ensureDefaultSecurityGroup", func() {
		It("should remove all rules from the default security group", func() {
			defaultSG := &awsclient.SecurityGroup{
				GroupId: "sg-0a1b2c3d4e5f6g7h8",
				Rules: []*awsclient.SecurityGroupRule{
					{Protocol: "tcp", FromPort: ptr.To[int32](22), ToPort: ptr.To[int32](22), CidrBlocks: []string{"0.0.0.0/0"}},
				},
			}
			f.c.state.Set(IdentifierVPC, f.vpc.VpcId)
			f.client.EXPECT().FindDefaultSecurityGroupByVpcId(f.ctx, f.vpc.VpcId).Return(defaultSG, nil).Times(1)
			f.updater.EXPECT().UpdateSecurityGroup(f.ctx, gomock.Any(), defaultSG).
				DoAndReturn(func(_ context.Context, desired, _ *awsclient.SecurityGroup) (bool, error) {
					Expect(desired.GroupId).To(Equal(defaultSG.GroupId))
					Expect(desired.Rules).To(BeEmpty())
					return true, nil
				}).Times(1)
			Expect(f.c.ensureDefaultSecurityGroup(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierDefaultSecurityGroup)).To(HaveValue(Equal(defaultSG.GroupId)))
		})
	})

	Describe("#ensureNodesSecurityGroup", func() {
		// setupManagedZone configures a single zone with workers, internal LB, and public LB
		// CIDRs. It returns a helper that asserts the expected per-zone narrow NodePort rules
		// are present on the desired SG.
		setupManagedZone := func() (workersCIDR, internalCIDR, publicCIDR string, checkPerZoneRules func(desired *awsclient.SecurityGroup)) {
			workersCIDR = "10.11.8.0/24"
			internalCIDR = "10.11.32.0/20"
			publicCIDR = "10.11.48.0/20"
			f.c.config.Networks.Zones = []aws.Zone{{
				Name:     "eu-central-1a",
				Workers:  &workersCIDR,
				Internal: &internalCIDR,
				Public:   &publicCIDR,
			}}
			f.c.state.Set(IdentifierVPC, f.vpc.VpcId)

			checkPerZoneRules = func(desired *awsclient.SecurityGroup) {
				Expect(desired.Rules).To(ContainElements(
					&awsclient.SecurityGroupRule{
						Type: awsclient.SecurityGroupRuleTypeIngress, Protocol: "tcp",
						FromPort: ptr.To[int32](nodePortMin), ToPort: ptr.To[int32](nodePortMax),
						CidrBlocks: []string{internalCIDR},
					},
					&awsclient.SecurityGroupRule{
						Type: awsclient.SecurityGroupRuleTypeIngress, Protocol: "udp",
						FromPort: ptr.To[int32](nodePortMin), ToPort: ptr.To[int32](nodePortMax),
						CidrBlocks: []string{internalCIDR},
					},
					&awsclient.SecurityGroupRule{
						Type: awsclient.SecurityGroupRuleTypeIngress, Protocol: "tcp",
						FromPort: ptr.To[int32](nodePortMin), ToPort: ptr.To[int32](nodePortMax),
						CidrBlocks: []string{publicCIDR},
					},
					&awsclient.SecurityGroupRule{
						Type: awsclient.SecurityGroupRuleTypeIngress, Protocol: "udp",
						FromPort: ptr.To[int32](nodePortMin), ToPort: ptr.To[int32](nodePortMax),
						CidrBlocks: []string{publicCIDR},
					},
				))
			}
			return
		}

		It("should store the user-provided SG ID in state and skip creation when isBYOSecurityGroup", func() {
			sgID := "sg-user-provided-12345"
			f.c.config.Networks.NodesSecurityGroupID = &sgID
			// No mock expectations — no AWS calls should be made.
			Expect(f.c.ensureNodesSecurityGroup(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierNodesSecurityGroup)).To(HaveValue(Equal(sgID)))
		})

		It("should create a new nodes SG with per-zone NodePort rules when none exists", func() {
			f.setupIPv4Only()
			_, _, _, checkPerZoneRules := setupManagedZone()

			createdSG := &awsclient.SecurityGroup{GroupId: "sg-new-12345", GroupName: "-nodes", VpcId: &f.vpc.VpcId}
			f.client.EXPECT().FindSecurityGroupsByTags(f.ctx, gomock.Any()).Return(nil, nil).Times(1)
			f.client.EXPECT().CreateSecurityGroup(f.ctx, gomock.Any()).Return(createdSG, nil).Times(1)
			f.client.EXPECT().GetSecurityGroup(f.ctx, createdSG.GroupId).Return(createdSG, nil).Times(1)
			f.updater.EXPECT().UpdateSecurityGroup(f.ctx, gomock.Any(), createdSG).
				DoAndReturn(func(_ context.Context, desired, _ *awsclient.SecurityGroup) (bool, error) {
					checkPerZoneRules(desired)
					return true, nil
				}).Times(1)

			Expect(f.c.ensureNodesSecurityGroup(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierNodesSecurityGroup)).To(HaveValue(Equal(createdSG.GroupId)))
		})

		It("should update an existing nodes SG found by tags with per-zone NodePort rules", func() {
			f.setupIPv4Only()
			_, _, _, checkPerZoneRules := setupManagedZone()

			existingSG := &awsclient.SecurityGroup{GroupId: "sg-existing-99999", GroupName: "-nodes", VpcId: &f.vpc.VpcId}
			f.client.EXPECT().FindSecurityGroupsByTags(f.ctx, gomock.Any()).Return([]*awsclient.SecurityGroup{existingSG}, nil).Times(1)
			f.updater.EXPECT().UpdateSecurityGroup(f.ctx, gomock.Any(), existingSG).
				DoAndReturn(func(_ context.Context, desired, _ *awsclient.SecurityGroup) (bool, error) {
					checkPerZoneRules(desired)
					return true, nil
				}).Times(1)

			Expect(f.c.ensureNodesSecurityGroup(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierNodesSecurityGroup)).To(HaveValue(Equal(existingSG.GroupId)))
		})

		It("should include an EFS TCP/2049 ingress rule sourced from the workers CIDR when CSI EFS is enabled", func() {
			f.setupIPv4Only()
			workersCIDR := "10.11.8.0/24"
			f.c.config.Networks.Zones = []aws.Zone{{Name: "eu-central-1a", Workers: &workersCIDR}}
			f.c.config.ElasticFileSystem = &aws.ElasticFileSystemConfig{Enabled: true}
			f.c.state.Set(IdentifierVPC, f.vpc.VpcId)

			createdSG := &awsclient.SecurityGroup{GroupId: "sg-new-12345", GroupName: "-nodes", VpcId: &f.vpc.VpcId}
			f.client.EXPECT().FindSecurityGroupsByTags(f.ctx, gomock.Any()).Return(nil, nil).Times(1)
			f.client.EXPECT().CreateSecurityGroup(f.ctx, gomock.Any()).Return(createdSG, nil).Times(1)
			f.client.EXPECT().GetSecurityGroup(f.ctx, createdSG.GroupId).Return(createdSG, nil).Times(1)
			f.updater.EXPECT().UpdateSecurityGroup(f.ctx, gomock.Any(), createdSG).
				DoAndReturn(func(_ context.Context, desired, _ *awsclient.SecurityGroup) (bool, error) {
					efsRule := &awsclient.SecurityGroupRule{
						Type:       awsclient.SecurityGroupRuleTypeIngress,
						Protocol:   "tcp",
						FromPort:   ptr.To[int32](nfsPort),
						ToPort:     ptr.To[int32](nfsPort),
						CidrBlocks: []string{workersCIDR},
					}
					Expect(desired.Rules).To(ContainElement(efsRule))
					return true, nil
				}).Times(1)

			Expect(f.c.ensureNodesSecurityGroup(f.ctx)).To(Succeed())
			Expect(f.c.state.Get(IdentifierNodesSecurityGroup)).To(HaveValue(Equal(createdSG.GroupId)))
		})
	})
})
