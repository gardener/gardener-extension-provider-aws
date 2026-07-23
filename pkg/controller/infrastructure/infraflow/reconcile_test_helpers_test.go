// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"

	core "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	ext "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

// dualStackMode selects how dual-stack is signalled to the FlowContext.
type dualStackMode int

const (
	dualStackViaFamilies    dualStackMode = iota
	dualStackViaInfraConfig dualStackMode = iota
)

// ipamCIDRMode selects whether the IPAM pool has a pre-configured CIDR.
type ipamCIDRMode int

const (
	withoutCIDR ipamCIDRMode = iota
	withCIDR    ipamCIDRMode = iota
)

// flowContextFixture holds all shared state for FlowContext unit tests.
// Declare a variable of this type inside a Describe block and call setup()
// inside a BeforeEach to initialise it for each test.
type flowContextFixture struct {
	ipv4Cidr string
	ipv6Cidr string

	// AWS API objects
	tags            awsclient.Tags
	dhcpOptions     *awsclient.DhcpOptions
	vpc             *awsclient.VPC
	internetGateway *awsclient.InternetGateway
	egressGateway   *awsclient.EgressOnlyInternetGateway
	ipv6IPAMPoolId  string

	// Mocks
	ctrl    *gomock.Controller
	client  *mockawsclient.MockInterface
	updater *mockawsclient.MockUpdater
	ctx     context.Context

	// Object under test
	c *FlowContext

	// Setup helpers — assigned during setup() so they close over the fixture fields.
	setupIPv4Only  func()
	setupIPv6Only  func()
	setupDualStack func(dualStackMode)
	setupIPAMPool  func(ipamCIDRMode)
}

// setup initialises the fixture. Call from a BeforeEach.
func (f *flowContextFixture) setup() {
	f.ipv4Cidr = "10.11.0.0/16"
	f.ipv6Cidr = "2001:db8:1234:56::/56"

	f.tags = awsclient.Tags{
		"kubernetes.io/cluster/shoot--myproject--mycluster": "1",
		"Name": "shoot--myproject--mycluster",
	}

	f.dhcpOptions = &awsclient.DhcpOptions{
		DhcpOptionsId: "dopt-084807a4d953f0424",
		Tags:          f.tags,
		DhcpConfigurations: map[string][]string{
			"domain-name":         {"eu-central-1.compute.internal"},
			"domain-name-servers": {"AmazonProvidedDNS"},
		},
	}

	// Default VPC for testing, set up as dual-stack with IPv6 CIDR block assigned by AWS.
	f.vpc = &awsclient.VPC{
		VpcId:                        "vpc-0a1b2c3d4e5f6g7h8",
		Tags:                         f.tags,
		CidrBlock:                    f.ipv4Cidr,
		IPv6CidrBlock:                f.ipv6Cidr,
		EnableDnsSupport:             true,
		EnableDnsHostnames:           true,
		AssignGeneratedIPv6CidrBlock: true,
		DhcpOptionsId:                &f.dhcpOptions.DhcpOptionsId,
		InstanceTenancy:              "default",
	}

	f.internetGateway = &awsclient.InternetGateway{
		Tags:              f.tags,
		InternetGatewayId: "igw-0a1b2c3d4e5f6g7h8",
		VpcId:             &f.vpc.VpcId,
	}

	f.egressGateway = &awsclient.EgressOnlyInternetGateway{
		Tags:                        f.tags,
		EgressOnlyInternetGatewayId: "eigw-0a1b2c3d4e5f6g7h8",
		VpcId:                       &f.vpc.VpcId,
	}

	f.ipv6IPAMPoolId = "ipam-pool-0a1b2c3d4e5f6g7h8"

	f.ctrl = gomock.NewController(GinkgoT())
	f.client = mockawsclient.NewMockInterface(f.ctrl)
	f.updater = mockawsclient.NewMockUpdater(f.ctrl)
	f.ctx = context.TODO()

	f.c = &FlowContext{
		state:      shared.NewWhiteboard(),
		commonTags: f.tags,
		infraSpec: ext.InfrastructureSpec{
			Region: "eu-central-1",
		},
		config: &aws.InfrastructureConfig{
			DualStack: &aws.DualStack{Enabled: false},
			Networks: aws.Networks{
				VPC: aws.VPC{CIDR: &f.ipv4Cidr},
			},
		},
		networking: &core.Networking{
			IPFamilies: []core.IPFamily{core.IPFamilyIPv4, core.IPFamilyIPv6},
		},
		client:  f.client,
		updater: f.updater,
	}

	f.setupIPv4Only = func() {
		f.c.networking.IPFamilies = []core.IPFamily{core.IPFamilyIPv4}
		f.vpc.AssignGeneratedIPv6CidrBlock = false
		f.vpc.IPv6CidrBlock = ""
	}
	f.setupIPv6Only = func() {
		f.c.networking.IPFamilies = []core.IPFamily{core.IPFamilyIPv6}
		f.vpc.AssignGeneratedIPv6CidrBlock = true
	}
	f.setupDualStack = func(mode dualStackMode) {
		if mode == dualStackViaInfraConfig {
			f.c.networking = nil
			f.c.config.DualStack.Enabled = true
		} else {
			f.c.networking.IPFamilies = []core.IPFamily{core.IPFamilyIPv4, core.IPFamilyIPv6}
		}
		f.vpc.AssignGeneratedIPv6CidrBlock = true
	}
	f.setupIPAMPool = func(mode ipamCIDRMode) {
		f.c.config.Networks.VPC.Ipv6IpamPool = &aws.IPAMPool{ID: &f.ipv6IPAMPoolId}
		if mode == withCIDR {
			f.c.config.Networks.VPC.Ipv6IpamPool.CidrBlock = &f.ipv6Cidr
			f.vpc.Ipv6CidrBlock = &f.ipv6Cidr
		} else {
			f.c.config.Networks.VPC.Ipv6IpamPool.CidrBlock = nil
			f.vpc.Ipv6NetmaskLength = ptr.To[int32](defaultIPv6NetmaskSize)
		}
		f.vpc.Ipv6IpamPoolId = &f.ipv6IPAMPoolId
		f.vpc.AssignGeneratedIPv6CidrBlock = false
	}
}
