package infraflow

import (
	"context"

	core "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	ext "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

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
	var (
		tags    awsclient.Tags
		ctrl    *gomock.Controller
		client  *mockawsclient.MockInterface
		updater *mockawsclient.MockUpdater
		ctx     context.Context
		c       *FlowContext
	)
	BeforeEach(func() {
		tags = awsclient.Tags{
			"kubernetes.io/cluster/shoot--myproject--mycluster": "1",
			"Name": "shoot--myproject--mycluster",
		}
		ctrl = gomock.NewController(GinkgoT())
		client = mockawsclient.NewMockInterface(ctrl)

		// We don't want to test the updater here, so we just mock it to always return false and no error.
		updater = mockawsclient.NewMockUpdater(ctrl)
		updater.EXPECT().UpdateVpc(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
		updater.EXPECT().UpdateSecurityGroup(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
		updater.EXPECT().UpdateRouteTable(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
		updater.EXPECT().UpdateSubnet(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
		updater.EXPECT().UpdateIAMInstanceProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
		updater.EXPECT().UpdateIAMRole(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
		updater.EXPECT().UpdateEC2Tags(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()

		ctx = context.TODO()
		c = &FlowContext{
			state: shared.NewWhiteboard(),
			infraSpec: ext.InfrastructureSpec{
				Region: "eu-central-1",
			},
			commonTags: tags,
			client:     client,
			updater:    updater,
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
	Context("DHCP Options", func() {
		var (
			dhcpOptionsId     string
			dhcpOptions       *awsclient.DhcpOptions
			dhcpOptionsWithId *awsclient.DhcpOptions
		)
		BeforeEach(func() {
			dhcpOptions = &awsclient.DhcpOptions{
				Tags: tags,
				DhcpConfigurations: map[string][]string{
					"domain-name":         {"eu-central-1.compute.internal"},
					"domain-name-servers": {"AmazonProvidedDNS"},
				},
			}
			dhcpOptionsId = "dopt-084807a4d953f0424"
			dhcpOptionsWithId = &awsclient.DhcpOptions{}
			*dhcpOptionsWithId = *dhcpOptions
			dhcpOptionsWithId.DhcpOptionsId = dhcpOptionsId
		})
		Describe("#getDesiredDhcpOptions", func() {
			It("should set the correct domain name for us-east-1", func() {
				c.infraSpec.Region = "us-east-1"
				expectedDhcpOptions := dhcpOptions
				expectedDhcpOptions.DhcpConfigurations["domain-name"] = []string{"ec2.internal"}
				desiredDhcpOptions := c.getDesiredDhcpOptions()
				Expect(desiredDhcpOptions).To(Equal(expectedDhcpOptions))
			})
			It("should set the correct domain name for other regions", func() {
				desiredDhcpOptions := c.getDesiredDhcpOptions()
				Expect(desiredDhcpOptions).To(Equal(dhcpOptions))
			})
		})
		Describe("#ensureDhcpOptions", func() {
			It("should create new DHCP options if none exist", func() {
				client.EXPECT().FindVpcDhcpOptionsByTags(ctx, tags).Return(nil, nil).Times(1)
				client.EXPECT().CreateVpcDhcpOptions(ctx, dhcpOptions).Return(dhcpOptionsWithId, nil).Times(1)
				err := c.ensureDhcpOptions(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(*c.state.Get(IdentifierDHCPOptions)).To(Equal(dhcpOptionsId))
			})
			It("should use existing DHCP options if they can be found by tags", func() {
				client.EXPECT().FindVpcDhcpOptionsByTags(ctx, tags).Return([]*awsclient.DhcpOptions{dhcpOptionsWithId}, nil).Times(1)
				err := c.ensureDhcpOptions(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(*c.state.Get(IdentifierDHCPOptions)).To(Equal(dhcpOptionsId))
			})
			It("should use existing DHCP options if they can be found by ID", func() {
				client.EXPECT().GetVpcDhcpOptions(ctx, dhcpOptionsId).Return(dhcpOptionsWithId, nil).Times(1)
				c.state.Set(IdentifierDHCPOptions, dhcpOptionsId)
				err := c.ensureDhcpOptions(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(*c.state.Get(IdentifierDHCPOptions)).To(Equal(dhcpOptionsId))
			})
		})
	})
})
