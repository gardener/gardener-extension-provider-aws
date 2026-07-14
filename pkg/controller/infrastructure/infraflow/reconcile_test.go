package infraflow

import (
	"context"
	"fmt"

	core "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	ext "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

// Tests for self-contained functions
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
})

var _ = Describe("#FlowContext", func() {
	type dualStackMode int
	const (
		dualStackViaFamilies dualStackMode = iota
		dualStackViaInfraConfig
	)
	type ipamCIDRMode int
	const (
		withoutCIDR ipamCIDRMode = iota
		withCIDR
	)
	var (
		ipv4Cidr string
		ipv6Cidr string
		// AWS API objects
		tags            awsclient.Tags
		dhcpOptions     *awsclient.DhcpOptions
		vpc             *awsclient.VPC
		internetGateway *awsclient.InternetGateway
		egressGateway   *awsclient.EgressOnlyInternetGateway
		ipv6IPAMPoolId  string
		// Mocks and helpers
		ctrl    *gomock.Controller
		client  *mockawsclient.MockInterface
		updater *mockawsclient.MockUpdater
		ctx     context.Context
		// Object under test
		c *FlowContext

		setupIPv4Only  func()
		setupIPv6Only  func()
		setupDualStack func(mode dualStackMode)
		setupIPAMPool  func(mode ipamCIDRMode)
	)
	BeforeEach(func() {
		ipv4Cidr = "10.11.0.0/16"
		ipv6Cidr = "2001:db8:1234:56::/56"

		tags = awsclient.Tags{
			"kubernetes.io/cluster/shoot--myproject--mycluster": "1",
			"Name": "shoot--myproject--mycluster",
		}

		dhcpOptions = &awsclient.DhcpOptions{
			DhcpOptionsId: "dopt-084807a4d953f0424",
			Tags:          tags,
			DhcpConfigurations: map[string][]string{
				"domain-name":         {"eu-central-1.compute.internal"},
				"domain-name-servers": {"AmazonProvidedDNS"},
			},
		}

		// Default VPC for testing, setup as dual stack with IPv6 CIDR block assigned by AWS
		vpc = &awsclient.VPC{
			VpcId:                        "vpc-0a1b2c3d4e5f6g7h8",
			Tags:                         tags,
			CidrBlock:                    ipv4Cidr,
			IPv6CidrBlock:                ipv6Cidr,
			EnableDnsSupport:             true,
			EnableDnsHostnames:           true,
			AssignGeneratedIPv6CidrBlock: true,
			DhcpOptionsId:                &dhcpOptions.DhcpOptionsId,
			InstanceTenancy:              "default",
		}

		internetGateway = &awsclient.InternetGateway{
			Tags:              tags,
			InternetGatewayId: "igw-0a1b2c3d4e5f6g7h8",
			VpcId:             &vpc.VpcId,
		}

		egressGateway = &awsclient.EgressOnlyInternetGateway{
			Tags:                        tags,
			EgressOnlyInternetGatewayId: "eigw-0a1b2c3d4e5f6g7h8",
			VpcId:                       &vpc.VpcId,
		}

		ipv6IPAMPoolId = "ipam-pool-0a1b2c3d4e5f6g7h8"

		ctrl = gomock.NewController(GinkgoT())
		client = mockawsclient.NewMockInterface(ctrl)
		updater = mockawsclient.NewMockUpdater(ctrl)

		ctx = context.TODO()

		c = &FlowContext{
			state:      shared.NewWhiteboard(),
			commonTags: tags,
			infraSpec: ext.InfrastructureSpec{
				Region: "eu-central-1",
			},
			config: &aws.InfrastructureConfig{
				DualStack: &aws.DualStack{
					Enabled: false,
				},
				Networks: aws.Networks{
					VPC: aws.VPC{
						CIDR: &ipv4Cidr,
					},
				},
			},
			networking: &core.Networking{
				IPFamilies: []core.IPFamily{core.IPFamilyIPv4, core.IPFamilyIPv6},
			},
			client:  client,
			updater: updater,
		}
		setupIPv4Only = func() {
			c.networking.IPFamilies = []core.IPFamily{core.IPFamilyIPv4}
			vpc.AssignGeneratedIPv6CidrBlock = false
			vpc.IPv6CidrBlock = ""
		}
		setupIPv6Only = func() {
			c.networking.IPFamilies = []core.IPFamily{core.IPFamilyIPv6}
			vpc.AssignGeneratedIPv6CidrBlock = true
		}
		setupDualStack = func(mode dualStackMode) {
			if mode == dualStackViaInfraConfig {
				c.networking = nil
				c.config.DualStack.Enabled = true
			} else {
				c.networking.IPFamilies = []core.IPFamily{core.IPFamilyIPv4, core.IPFamilyIPv6}
			}
			vpc.AssignGeneratedIPv6CidrBlock = true
		}
		setupIPAMPool = func(mode ipamCIDRMode) {
			c.config.Networks.VPC.Ipv6IpamPool = &aws.IPAMPool{
				ID: &ipv6IPAMPoolId,
			}
			if mode == withCIDR {
				c.config.Networks.VPC.Ipv6IpamPool.CidrBlock = &ipv6Cidr
				vpc.Ipv6CidrBlock = &ipv6Cidr
			} else {
				c.config.Networks.VPC.Ipv6IpamPool.CidrBlock = nil
				vpc.Ipv6NetmaskLength = ptr.To[int32](defaultIPv6NetmaskSize)
			}
			vpc.Ipv6IpamPoolId = &ipv6IPAMPoolId
			vpc.AssignGeneratedIPv6CidrBlock = false
		}
	})
	Describe("#getIPFamilies", func() {
		It("should return IPv4 when networking is not set", func() {
			c.networking = nil
			families := c.getIpFamilies()
			Expect(families).ToNot(BeNil())
			Expect(families).To(HaveLen(1))
			Expect(families).To(ContainElement(core.IPFamilyIPv4))
		})
	})
	Describe("#getDesiredDhcpOptions", func() {
		It("should set the correct domain name for us-east-1", func() {
			c.infraSpec.Region = "us-east-1"
			dhcpOptions.DhcpOptionsId = ""
			dhcpOptions.DhcpConfigurations["domain-name"] = []string{"ec2.internal"}
			desiredDhcpOptions := c.getDesiredDhcpOptions()
			Expect(desiredDhcpOptions).To(Equal(dhcpOptions))
		})
		It("should set the correct domain name for other regions", func() {
			dhcpOptions.DhcpOptionsId = ""
			desiredDhcpOptions := c.getDesiredDhcpOptions()
			Expect(desiredDhcpOptions).To(Equal(dhcpOptions))
		})
	})
	Describe("#ensureDhcpOptions", func() {
		It("should create new DHCP options if none exist", func() {
			dhcpOptionsArg := &awsclient.DhcpOptions{}
			*dhcpOptionsArg = *dhcpOptions
			dhcpOptionsArg.DhcpOptionsId = ""
			client.EXPECT().FindVpcDhcpOptionsByTags(ctx, tags).Return(nil, nil).Times(1)
			client.EXPECT().CreateVpcDhcpOptions(ctx, dhcpOptionsArg).Return(dhcpOptions, nil).Times(1)
			err := c.ensureDhcpOptions(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(*c.state.Get(IdentifierDHCPOptions)).To(Equal(dhcpOptions.DhcpOptionsId))
		})
		It("should use existing DHCP options if they can be found by tags", func() {
			client.EXPECT().FindVpcDhcpOptionsByTags(ctx, tags).Return([]*awsclient.DhcpOptions{dhcpOptions}, nil).Times(1)
			updater.EXPECT().UpdateEC2Tags(ctx, dhcpOptions.DhcpOptionsId, c.commonTags, dhcpOptions.Tags).Return(false, nil).Times(1)
			err := c.ensureDhcpOptions(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(*c.state.Get(IdentifierDHCPOptions)).To(Equal(dhcpOptions.DhcpOptionsId))
		})
		It("should use existing DHCP options if they can be found by ID", func() {
			client.EXPECT().GetVpcDhcpOptions(ctx, dhcpOptions.DhcpOptionsId).Return(dhcpOptions, nil).Times(1)
			updater.EXPECT().UpdateEC2Tags(ctx, dhcpOptions.DhcpOptionsId, c.commonTags, dhcpOptions.Tags).Return(false, nil).Times(1)
			c.state.Set(IdentifierDHCPOptions, dhcpOptions.DhcpOptionsId)
			err := c.ensureDhcpOptions(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(*c.state.Get(IdentifierDHCPOptions)).To(Equal(dhcpOptions.DhcpOptionsId))
		})
	})
	DescribeTableSubtree("#ensureVpc",
		func(setup func(), checkDesiredVpc func(*awsclient.VPC)) {
			BeforeEach(func() {
				setup()
			})
			It("should create a new VPC if none exists", func() {
				vpcArg := &awsclient.VPC{}
				*vpcArg = *vpc
				vpcArg.VpcId = ""
				vpcArg.IPv6CidrBlock = ""
				c.state.Set(IdentifierDHCPOptions, dhcpOptions.DhcpOptionsId) // When creating a new VPC, the DHCP options id is read from the state
				client.EXPECT().FindVpcsByTags(ctx, tags).Return(nil, nil).Times(1)
				client.EXPECT().CreateVpc(ctx, vpcArg).Return(vpc, nil).Times(1)
				updater.EXPECT().UpdateVpc(ctx, gomock.Any(), vpc).DoAndReturn(
					func(_ context.Context, desired, _ *awsclient.VPC) (bool, error) {
						checkDesiredVpc(desired)
						return true, nil
					}).Times(1)
				err := c.ensureVpc(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(c.state.Get(IdentifierVPC)).To(Not(BeNil()))
				Expect(*c.state.Get(IdentifierVPC)).To(Equal(vpc.VpcId))
			})
			It("should use an existing VPC if it can be found by tags", func() {
				c.state.Set(IdentifierDHCPOptions, dhcpOptions.DhcpOptionsId)
				client.EXPECT().FindVpcsByTags(ctx, tags).Return([]*awsclient.VPC{vpc}, nil).Times(1)
				updater.EXPECT().UpdateVpc(ctx, gomock.Any(), vpc).DoAndReturn(
					func(_ context.Context, desired, _ *awsclient.VPC) (bool, error) {
						checkDesiredVpc(desired)
						return true, nil
					}).Times(1)
				err := c.ensureVpc(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(c.state.Get(IdentifierVPC)).To(Not(BeNil()))
				Expect(*c.state.Get(IdentifierVPC)).To(Equal(vpc.VpcId))
				if c.isIPv6Enabled() {
					Expect(c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Not(BeNil()))
					Expect(*c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Equal(vpc.IPv6CidrBlock))
				} else {
					Expect(c.state.Get(IdentifierVpcIPv6CidrBlock)).To(BeNil())
				}
			})
			It("should use an existing VPC if it can be found by ID", func() {
				c.state.Set(IdentifierVPC, vpc.VpcId)
				client.EXPECT().GetVpc(ctx, vpc.VpcId).Return(vpc, nil).Times(1)
				updater.EXPECT().UpdateVpc(ctx, gomock.Any(), vpc).DoAndReturn(
					func(_ context.Context, desired, _ *awsclient.VPC) (bool, error) {
						checkDesiredVpc(desired)
						return true, nil
					}).Times(1)
				err := c.ensureVpc(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(c.state.Get(IdentifierVPC)).To(Not(BeNil()))
				Expect(*c.state.Get(IdentifierVPC)).To(Equal(vpc.VpcId))
				if c.isIPv6Enabled() {
					Expect(c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Not(BeNil()))
					Expect(*c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Equal(vpc.IPv6CidrBlock))
				} else {
					Expect(c.state.Get(IdentifierVpcIPv6CidrBlock)).To(BeNil())
				}
			})
			It("should use an existing VPC if can be found by ID passed via the provider config", func() {
				c.config.Networks.VPC.ID = &vpc.VpcId
				client.EXPECT().GetVpc(ctx, vpc.VpcId).Return(vpc, nil).Times(1)
				client.EXPECT().GetVpcDhcpOptions(ctx, dhcpOptions.DhcpOptionsId).Return(dhcpOptions, nil).Times(1)
				client.EXPECT().FindInternetGatewayByVPC(ctx, vpc.VpcId).Return(internetGateway, nil).Times(1)
				if ContainsIPv6(c.getIpFamilies()) {
					client.EXPECT().FindEgressOnlyInternetGatewayByVPC(ctx, vpc.VpcId).Return(egressGateway, nil).Times(1)
				}
				err := c.ensureVpc(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(c.state.Get(IdentifierVPC)).To(Not(BeNil()))
				Expect(*c.state.Get(IdentifierVPC)).To(Equal(vpc.VpcId))
				Expect(c.state.Get(IdentifierInternetGateway)).To(Not(BeNil()))
				Expect(*c.state.Get(IdentifierInternetGateway)).To(Equal(internetGateway.InternetGatewayId))
			})
		},
		Entry("IPv4 only",
			func() {
				setupIPv4Only()
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
				Expect(desired.Ipv6CidrBlock).To(BeNil())
				Expect(desired.Ipv6IpamPoolId).To(BeNil())
			},
		),
		Entry("IPv6 only",
			func() {
				setupIPv6Only()
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeTrue())
				Expect(desired.Ipv6CidrBlock).To(BeNil())
				Expect(desired.Ipv6IpamPoolId).To(BeNil())
			},
		),
		Entry("IPv6 only with IPv6 IPAM Pool",
			func() {
				setupIPv6Only()
				setupIPAMPool(withoutCIDR)
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
				Expect(desired.Ipv6CidrBlock).To(BeNil())
				Expect(desired.Ipv6IpamPoolId).ToNot(BeNil())
				Expect(*desired.Ipv6IpamPoolId).To(Equal(ipv6IPAMPoolId))
				Expect(desired.Ipv6NetmaskLength).ToNot(BeNil())
				Expect(*desired.Ipv6NetmaskLength).To(Equal(int32(defaultIPv6NetmaskSize)))
			},
		),
		Entry("IPv6 only with IPv6 IPAM Pool and preconfigured CIDR",
			func() {
				setupIPv6Only()
				setupIPAMPool(withCIDR)
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
				Expect(desired.Ipv6CidrBlock).ToNot(BeNil())
				Expect(*desired.Ipv6CidrBlock).To(Equal(ipv6Cidr))
				Expect(desired.Ipv6IpamPoolId).ToNot(BeNil())
				Expect(*desired.Ipv6IpamPoolId).To(Equal(ipv6IPAMPoolId))
				Expect(desired.Ipv6NetmaskLength).To(BeNil())
			},
		),
		Entry("DualStack via IPFamilies",
			func() {
				setupDualStack(dualStackViaFamilies)
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeTrue())
				Expect(desired.Ipv6CidrBlock).To(BeNil())
				Expect(desired.Ipv6IpamPoolId).To(BeNil())
			},
		),
		Entry("DualStack via IPFamilies with IPv6 IPAM Pool",
			func() {
				setupDualStack(dualStackViaFamilies)
				setupIPAMPool(withoutCIDR)
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
				Expect(desired.Ipv6CidrBlock).To(BeNil())
				Expect(desired.Ipv6IpamPoolId).ToNot(BeNil())
				Expect(*desired.Ipv6IpamPoolId).To(Equal(ipv6IPAMPoolId))
				Expect(desired.Ipv6NetmaskLength).ToNot(BeNil())
				Expect(*desired.Ipv6NetmaskLength).To(Equal(int32(defaultIPv6NetmaskSize)))
			},
		),
		Entry("DualStack via IPFamilies with IPv6 IPAM Pool and preconfigured CIDR",
			func() {
				setupDualStack(dualStackViaFamilies)
				setupIPAMPool(withCIDR)
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
				Expect(desired.Ipv6CidrBlock).ToNot(BeNil())
				Expect(*desired.Ipv6CidrBlock).To(Equal(ipv6Cidr))
				Expect(desired.Ipv6IpamPoolId).ToNot(BeNil())
				Expect(*desired.Ipv6IpamPoolId).To(Equal(ipv6IPAMPoolId))
				Expect(desired.Ipv6NetmaskLength).To(BeNil())
			},
		),
		Entry("DualStack via InfrastructureConfig",
			func() {
				setupDualStack(dualStackViaInfraConfig)
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeTrue())
				Expect(desired.Ipv6CidrBlock).To(BeNil())
				Expect(desired.Ipv6IpamPoolId).To(BeNil())
			},
		),
		Entry("DualStack via InfrastructureConfig with IPv6 IPAM Pool",
			func() {
				setupDualStack(dualStackViaInfraConfig)
				setupIPAMPool(withoutCIDR)
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
				Expect(desired.Ipv6CidrBlock).To(BeNil())
				Expect(desired.Ipv6IpamPoolId).ToNot(BeNil())
				Expect(*desired.Ipv6IpamPoolId).To(Equal(ipv6IPAMPoolId))
				Expect(desired.Ipv6NetmaskLength).ToNot(BeNil())
				Expect(*desired.Ipv6NetmaskLength).To(Equal(int32(defaultIPv6NetmaskSize)))
			},
		),
		Entry("DualStack via InfrastructureConfig with IPv6 IPAM Pool and preconfigured CIDR",
			func() {
				setupDualStack(dualStackViaInfraConfig)
				setupIPAMPool(withCIDR)
			},
			func(desired *awsclient.VPC) {
				Expect(desired.AssignGeneratedIPv6CidrBlock).To(BeFalse())
				Expect(desired.Ipv6CidrBlock).ToNot(BeNil())
				Expect(*desired.Ipv6CidrBlock).To(Equal(ipv6Cidr))
				Expect(desired.Ipv6IpamPoolId).ToNot(BeNil())
				Expect(*desired.Ipv6IpamPoolId).To(Equal(ipv6IPAMPoolId))
				Expect(desired.Ipv6NetmaskLength).To(BeNil())
			},
		),
	)
	Describe("#ensureVpcIPv6CidrBlock", func() {
		BeforeEach(func() {
			c.state.Set(IdentifierVPC, vpc.VpcId)
		})
		It("should do nothing if the cluster is IPv4 only", func() {
			setupIPv4Only()
			err := c.ensureVpcIPv6CidrBlock(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(c.state.Get(IdentifierVpcIPv6CidrBlock)).To(BeNil())
		})
		It("should wait for an IPv6 CIDR block if the cluster isIPv6 only", func() {
			setupIPv6Only()
			client.EXPECT().WaitForIPv6Cidr(ctx, vpc.VpcId).Return(ipv6Cidr, nil).Times(1)
			err := c.ensureVpcIPv6CidrBlock(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Not(BeNil()))
			Expect(*c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Equal(ipv6Cidr))
		})
		It("should wait for an IPv6 CIDR block if the cluster is dual-stack configured via IPFamilies", func() {
			setupDualStack(dualStackViaFamilies)
			client.EXPECT().WaitForIPv6Cidr(ctx, vpc.VpcId).Return(ipv6Cidr, nil).Times(1)
			err := c.ensureVpcIPv6CidrBlock(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Not(BeNil()))
			Expect(*c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Equal(ipv6Cidr))
		})
		It("should wait for an IPv6 CIDR block if the cluster is dual-stack configured via InfrastructureConfig", func() {
			setupDualStack(dualStackViaInfraConfig)
			client.EXPECT().WaitForIPv6Cidr(ctx, vpc.VpcId).Return(ipv6Cidr, nil).Times(1)
			err := c.ensureVpcIPv6CidrBlock(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Not(BeNil()))
			Expect(*c.state.Get(IdentifierVpcIPv6CidrBlock)).To(Equal(ipv6Cidr))
		})
	})
	Describe("#ensureDefaultSecurityGroup", func() {
		It("should remove all rules from the default security group", func() {
			// sample default security group with one rule
			defaultSG := &awsclient.SecurityGroup{
				GroupId: "sg-0a1b2c3d4e5f6g7h8",
				Rules: []*awsclient.SecurityGroupRule{
					{
						Protocol:   "tcp",
						FromPort:   ptr.To[int32](22),
						ToPort:     ptr.To[int32](22),
						CidrBlocks: []string{"0.0.0.0/0"},
					},
				},
			}
			c.state.Set(IdentifierVPC, vpc.VpcId)
			client.EXPECT().FindDefaultSecurityGroupByVpcId(ctx, vpc.VpcId).Return(defaultSG, nil).Times(1)
			updater.EXPECT().UpdateSecurityGroup(ctx, gomock.Any(), defaultSG).
				DoAndReturn(func(_ context.Context, desired, _ *awsclient.SecurityGroup) (bool, error) {
					Expect(desired).NotTo(BeNil())
					Expect(desired.GroupId).To(Equal(defaultSG.GroupId))
					Expect(desired.Rules).To(BeEmpty())
					return true, nil
				}).Times(1)
			err := c.ensureDefaultSecurityGroup(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(c.state.Get(IdentifierDefaultSecurityGroup)).To(Not(BeNil()))
			Expect(*c.state.Get(IdentifierDefaultSecurityGroup)).To(Equal(defaultSG.GroupId))
		})
	})
	DescribeTable("#computeNodesSecurityGroupBaseRules",
		func(setup func()) {
			setup()
			rules := c.computeNodesSecurityGroupBaseRules()
			Expect(rules).ToNot(BeNil())
			// helper functions
			v4Cidrs := func() []string {
				if containsIPv4(c.getIpFamilies()) {
					return []string{"0.0.0.0/0"}
				} else {
					return nil
				}
			}
			v6Cidrs := func() []string {
				if ContainsIPv6(c.getIpFamilies()) {
					return []string{"::/0"}
				} else {
					return nil
				}
			}
			// checks whether a rule is present and if so, nils it (to prevent double counting)
			checkRule := func(expected awsclient.SecurityGroupRule) {
				for i, rule := range rules {
					if rule != nil {
						if ok, _ := Equal(expected).Match(*rule); ok {
							rules[i] = nil
							return
						}
					}
				}
				Fail(fmt.Sprintf("expected rule not found: %+v", expected))
			}

			// The rules should always contain a self-referencing ingress rule
			checkRule(awsclient.SecurityGroupRule{
				Type:     awsclient.SecurityGroupRuleTypeIngress,
				Protocol: "-1",
				Self:     true,
			})

			// The rules should always allow ingress to the service port range from all IPs for tcp and udp
			checkRule(awsclient.SecurityGroupRule{
				Type:         awsclient.SecurityGroupRuleTypeIngress,
				Protocol:     "tcp",
				FromPort:     ptr.To[int32](nodePortMin),
				ToPort:       ptr.To[int32](nodePortMax),
				CidrBlocks:   v4Cidrs(),
				CidrBlocksv6: v6Cidrs(),
			})
			checkRule(awsclient.SecurityGroupRule{
				Type:         awsclient.SecurityGroupRuleTypeIngress,
				Protocol:     "udp",
				FromPort:     ptr.To[int32](nodePortMin),
				ToPort:       ptr.To[int32](nodePortMax),
				CidrBlocks:   v4Cidrs(),
				CidrBlocksv6: v6Cidrs(),
			})
			// The nodes are allowed to talk to the world via all IP protocols
			checkRule(awsclient.SecurityGroupRule{
				Type:         awsclient.SecurityGroupRuleTypeEgress,
				Protocol:     "-1",
				CidrBlocks:   v4Cidrs(),
				CidrBlocksv6: v6Cidrs(),
			})
			if c.hasEFAWorker {
				// Allow outgoing SRD traffic for EFA workers within the same security group
				checkRule(awsclient.SecurityGroupRule{
					Type:     awsclient.SecurityGroupRuleTypeEgress,
					Protocol: "-1",
					Self:     true,
				})
			}
			// Don't let additional rules slip in unnoticed
			var unchecked []*awsclient.SecurityGroupRule
			for _, r := range rules {
				if r != nil {
					unchecked = append(unchecked, r)
				}
			}
			Expect(unchecked).To(BeEmpty())
		},
		Entry("IPv4 only, no EFA", func() { setupIPv4Only() }),
		Entry("IPv6 only, no EFA", func() { setupIPv6Only() }),
		Entry("DualStack via IPFamilies, no EFA", func() { setupDualStack(dualStackViaFamilies) }),
		Entry("DualStack via InfrastructureConfig, no EFA", func() { setupDualStack(dualStackViaInfraConfig) }),
		Entry("IPv4 only, with EFA", func() {
			setupIPv4Only()
			c.hasEFAWorker = true
		}),
		Entry("IPv6 only, with EFA", func() {
			setupIPv6Only()
			c.hasEFAWorker = true
		}),
		Entry("DualStack via IPFamilies, with EFA", func() {
			setupDualStack(dualStackViaFamilies)
			c.hasEFAWorker = true
		}),
		Entry("DualStack via InfrastructureConfig, with EFA", func() {
			setupDualStack(dualStackViaInfraConfig)
			c.hasEFAWorker = true
		}),
	)
})
