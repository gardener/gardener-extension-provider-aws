// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- No cryptographic context.
	"errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"slices"
	"strings"
	"text/template"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/utils/flow"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

const (
	defaultTimeout         = 90 * time.Second
	defaultLongTimeout     = 3 * time.Minute
	allIPv4                = "0.0.0.0/0"
	allIPv6                = "::/0"
	nat64Prefix            = "64:ff9b::/96"
	defaultIPv6NetmaskSize = 56
)

// Reconcile creates and runs the flow to reconcile the AWS infrastructure.
func (c *FlowContext) Reconcile(ctx context.Context) error {
	c.BasicFlowContext = NewBasicFlowContext(c.log, c.state, c.persistState)
	g := c.buildReconcileGraph()
	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{Log: c.log}); err != nil {
		c.log.Error(err, "flow reconciliation failed")
		return errors.Join(flow.Causes(err), c.persistState(ctx))
	}

	status := c.computeInfrastructureStatus()
	state := c.computeInfrastructureState()
	egressCIDRs := c.getEgressCIDRs()
	vpcIPv6CidrBlock := c.state.Get(IdentifierVpcIPv6CidrBlock)
	serviceCidr := c.state.Get(IdentifierServiceCIDR)
	return PatchProviderStatusAndState(ctx, c.runtimeClient, c.infra, c.networking, status, state, egressCIDRs, vpcIPv6CidrBlock, serviceCidr)
}

func (c *FlowContext) buildReconcileGraph() *flow.Graph {
	createVPC := c.config.Networks.VPC.ID == nil
	g := flow.NewGraph("AWS infrastructure reconciliation")

	ensureDhcpOptions := c.AddTask(g, "ensure DHCP options for VPC",
		c.ensureDhcpOptions,
		DoIf(createVPC), Timeout(defaultTimeout))

	ensureVpc := c.AddTask(g, "ensure VPC",
		c.ensureVpc,
		Timeout(defaultTimeout), Dependencies(ensureDhcpOptions))

	ensureVpcIPv6CidrBloc := c.AddTask(g, "ensure IPv6 CIDR Block",
		c.ensureVpcIPv6CidrBlock,
		Timeout(defaultTimeout), Dependencies(ensureVpc))

	ensureDefaultSecurityGroup := c.AddTask(g, "ensure default security group",
		c.ensureDefaultSecurityGroup,
		DoIf(createVPC), Timeout(defaultTimeout), Dependencies(ensureVpc))

	ensureInternetGateway := c.AddTask(g, "ensure internet gateway",
		c.ensureInternetGateway,
		DoIf(createVPC), Timeout(defaultTimeout), Dependencies(ensureVpc))

	ensureEgressOnlyInternetGateway := c.AddTask(g, "ensure egress only gateway ",
		c.ensureEgressOnlyInternetGateway,
		DoIf(createVPC), Timeout(defaultTimeout), Dependencies(ensureVpc))

	_ = c.AddTask(g, "ensure gateway endpoints",
		c.ensureGatewayEndpoints,
		Timeout(defaultTimeout), Dependencies(ensureVpc, ensureDefaultSecurityGroup, ensureInternetGateway))

	ensureMainRouteTable := c.AddTask(g, "ensure main route table",
		c.ensureMainRouteTable,
		Timeout(defaultTimeout), Dependencies(ensureVpc, ensureVpcIPv6CidrBloc, ensureDefaultSecurityGroup, ensureInternetGateway, ensureEgressOnlyInternetGateway))

	ensureNodesSecurityGroup := c.AddTask(g, "ensure nodes security group",
		c.ensureNodesSecurityGroup,
		Timeout(defaultTimeout), Dependencies(ensureVpc))

	ensureZones := c.AddTask(g, "ensure zones resources",
		c.ensureZones,
		Timeout(defaultLongTimeout), Dependencies(ensureVpc, ensureNodesSecurityGroup, ensureVpcIPv6CidrBloc, ensureMainRouteTable))

	_ = c.AddTask(g, "ensure efs file system",
		c.ensureEfs,
		DoIf(c.isCsiEfsEnabled()), Timeout(defaultTimeout), Dependencies(ensureZones))

	_ = c.AddTask(g, "ensure subnet cidr reservation",
		c.ensureSubnetCidrReservation,
		Timeout(defaultLongTimeout), Dependencies(ensureZones))

	_ = c.AddTask(g, "ensure egress CIDRs",
		c.ensureEgressCIDRs,
		Timeout(defaultLongTimeout), Dependencies(ensureZones))

	ensureIAMRole := c.AddTask(g, "ensure IAM role",
		c.ensureIAMRole,
		Timeout(defaultTimeout))

	_ = c.AddTask(g, "ensure IAM instance profile",
		c.ensureIAMInstanceProfile,
		Timeout(defaultTimeout), Dependencies(ensureIAMRole))

	_ = c.AddTask(g, "ensure IAM role policy",
		c.ensureIAMRolePolicy,
		Timeout(defaultTimeout), Dependencies(ensureIAMRole))

	_ = c.AddTask(g, "ensure key pair",
		c.ensureKeyPair,
		Timeout(defaultTimeout))

	return g
}

func (c *FlowContext) getDesiredDhcpOptions() *awsclient.DhcpOptions {
	dhcpDomainName := "ec2.internal"

	// This handles a special case for a rule predefined by AWS.
	// See https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-overview-DSN-queries-to-vpc.html
	if c.infraSpec.Region != "us-east-1" {
		dhcpDomainName = fmt.Sprintf("%s.compute.internal", c.infraSpec.Region)
	}

	return &awsclient.DhcpOptions{
		Tags: c.commonTags,
		DhcpConfigurations: map[string][]string{
			"domain-name":         {dhcpDomainName},
			"domain-name-servers": {"AmazonProvidedDNS"},
		},
	}
}

func (c *FlowContext) ensureDhcpOptions(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := c.getDesiredDhcpOptions()
	current, err := FindExisting(ctx, c.state.Get(IdentifierDHCPOptions), c.commonTags,
		c.client.GetVpcDhcpOptions, c.client.FindVpcDhcpOptionsByTags)
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierDHCPOptions, current.DhcpOptionsId)
		if _, err := c.updater.UpdateEC2Tags(ctx, current.DhcpOptionsId, c.commonTags, current.Tags); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateVpcDhcpOptions(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierDHCPOptions, created.DhcpOptionsId)
	}

	return nil
}

func (c *FlowContext) ensureVpc(ctx context.Context) error {
	if c.config.Networks.VPC.ID != nil {
		return c.ensureExistingVpc(ctx)
	}
	return c.ensureManagedVpc(ctx)
}

func (c *FlowContext) getIpFamilies() []v1beta1.IPFamily {
	if c.networking != nil {
		return c.networking.IPFamilies
	}
	return []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}
}

func (c *FlowContext) ensureManagedVpc(ctx context.Context) error {
	log := LogFromContext(ctx)
	log.Info("using managed VPC")
	// Default to shared tenancy unless dedicated tenancy is explicitly enabled.
	// AWS API does this as well, so all VPCs created before have instanceTenancy = "default".
	instanceTenancy := ec2types.TenancyDefault
	if c.config.EnableDedicatedTenancyForVPC != nil && *c.config.EnableDedicatedTenancyForVPC {
		instanceTenancy = ec2types.TenancyDedicated
	}
	desired := &awsclient.VPC{
		Tags:               c.commonTags,
		EnableDnsSupport:   true,
		EnableDnsHostnames: true,
		DhcpOptionsId:      c.state.Get(IdentifierDHCPOptions),
		InstanceTenancy:    instanceTenancy,
	}

	if (c.config.DualStack != nil && c.config.DualStack.Enabled) || containsIPv6(c.getIpFamilies()) {
		if c.config.Networks.VPC.Ipv6IpamPool != nil && c.config.Networks.VPC.Ipv6IpamPool.ID != nil {
			desired.AssignGeneratedIPv6CidrBlock = false
			desired.Ipv6IpamPoolId = c.config.Networks.VPC.Ipv6IpamPool.ID
			desired.Ipv6NetmaskLength = ptr.To(int32(defaultIPv6NetmaskSize))
		} else {
			desired.AssignGeneratedIPv6CidrBlock = true
		}
	}

	if c.config.Networks.VPC.CIDR == nil {
		return fmt.Errorf("missing VPC CIDR")
	}

	// Currently it is not possible to create a VPC without an IPv4 CIDR block
	// IPv4 range must also be specified for IPv6 only
	desired.CidrBlock = *c.config.Networks.VPC.CIDR

	current, err := FindExisting(ctx, c.state.Get(IdentifierVPC), c.commonTags,
		c.client.GetVpc, c.client.FindVpcsByTags)
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(IdentifierVPC, current.VpcId)
		c.state.Set(IdentifierVpcIPv6CidrBlock, current.IPv6CidrBlock)
		_, err := c.updater.UpdateVpc(ctx, desired, current)
		if err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateVpc(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierVPC, created.VpcId)
		_, err = c.updater.UpdateVpc(ctx, desired, created)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *FlowContext) ensureVpcIPv6CidrBlock(ctx context.Context) error {
	if (c.config.DualStack != nil && c.config.DualStack.Enabled) || containsIPv6(c.getIpFamilies()) {
		vpcID := *c.state.Get(IdentifierVPC) // guaranteed to be set because of ensureVPC dependency
		ipv6CidrBlock, err := c.client.WaitForIPv6Cidr(ctx, vpcID)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierVpcIPv6CidrBlock, ipv6CidrBlock)
	}
	return nil
}

func (c *FlowContext) ensureExistingVpc(ctx context.Context) error {
	vpcID := *c.config.Networks.VPC.ID
	log := LogFromContext(ctx)
	log.Info("using configured VPC", "vpc", vpcID)
	current, err := c.client.GetVpc(ctx, vpcID)
	if err != nil {
		return err
	}
	if current == nil {
		return fmt.Errorf("VPC %s has not been found", vpcID)
	}
	c.state.Set(IdentifierVPC, vpcID)
	if err := c.validateVpc(ctx, current); err != nil {
		return err
	}
	gw, err := c.client.FindInternetGatewayByVPC(ctx, vpcID)
	if err != nil {
		return fmt.Errorf("internet Gateway not found for VPC %s", vpcID)
	}
	c.state.Set(IdentifierInternetGateway, gw.InternetGatewayId)

	if containsIPv6(c.getIpFamilies()) {
		eogw, err := c.client.FindEgressOnlyInternetGatewayByVPC(ctx, vpcID)
		if err != nil || eogw == nil {
			return fmt.Errorf("Egress-Only Internet Gateway not found for VPC %s", vpcID)
		}
		c.state.Set(IdentifierEgressOnlyInternetGateway, eogw.EgressOnlyInternetGatewayId)
	}
	return nil
}

func (c *FlowContext) validateVpc(ctx context.Context, item *awsclient.VPC) error {
	if !item.EnableDnsHostnames {
		return fmt.Errorf("VPC attribute enableDnsHostnames must be set")
	}
	if !item.EnableDnsSupport {
		return fmt.Errorf("VPC attribute enableDnsSupport must be set")
	}
	if item.DhcpOptionsId == nil {
		return fmt.Errorf("missing DhcpOptions for VPC")
	}
	options, err := c.client.GetVpcDhcpOptions(ctx, *item.DhcpOptionsId)
	if err != nil {
		return err
	}
	if options == nil {
		return fmt.Errorf("DhcpOptions for VPC not found: %s", *item.DhcpOptionsId)
	}
	desired := c.getDesiredDhcpOptions()
	for k, v := range desired.DhcpConfigurations {
		if !reflect.DeepEqual(options.DhcpConfigurations[k], v) {
			return fmt.Errorf("missing DhcpConfiguration '%s'='%s' (actual: %s)",
				k, strings.Join(v, ","), strings.Join(options.DhcpConfigurations[k], ","))
		}
	}
	if (containsIPv6(c.getIpFamilies()) || (c.config.DualStack != nil && c.config.DualStack.Enabled)) && item.IPv6CidrBlock == "" {
		return fmt.Errorf("VPC has no ipv6 CIDR")
	}
	return nil
}

func (c *FlowContext) ensureDefaultSecurityGroup(ctx context.Context) error {
	current, err := c.client.FindDefaultSecurityGroupByVpcId(ctx, *c.state.Get(IdentifierVPC))
	if err != nil {
		return err
	}
	if current == nil {
		return fmt.Errorf("default security group not found")
	}

	c.state.Set(IdentifierDefaultSecurityGroup, current.GroupId)
	desired := current.Clone()
	desired.Rules = nil
	if _, err := c.updater.UpdateSecurityGroup(ctx, desired, current); err != nil {
		return err
	}
	return nil
}

func (c *FlowContext) ensureInternetGateway(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := &awsclient.InternetGateway{
		Tags:  c.commonTags,
		VpcId: c.state.Get(IdentifierVPC),
	}
	current, err := FindExisting(ctx, c.state.Get(IdentifierInternetGateway), c.commonTags,
		c.client.GetInternetGateway, c.client.FindInternetGatewaysByTags,
		func(item *awsclient.InternetGateway) bool {
			return c.isVpcMatchingState(item.VpcId)
		})
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierInternetGateway, current.InternetGatewayId)
		if err := c.client.AttachInternetGateway(ctx, *c.state.Get(IdentifierVPC), current.InternetGatewayId); err != nil {
			return err
		}
		if _, err := c.updater.UpdateEC2Tags(ctx, current.InternetGatewayId, c.commonTags, current.Tags); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateInternetGateway(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierInternetGateway, created.InternetGatewayId)
		if err := c.client.AttachInternetGateway(ctx, *c.state.Get(IdentifierVPC), created.InternetGatewayId); err != nil {
			return err
		}
	}

	return nil
}

func (c *FlowContext) ensureGatewayEndpoints(ctx context.Context) error {
	log := LogFromContext(ctx)
	child := c.state.GetChild(ChildIdVPCEndpoints)

	var desired []*awsclient.VpcEndpoint
	for _, endpoint := range c.config.Networks.VPC.GatewayEndpoints {
		desired = append(desired, &awsclient.VpcEndpoint{
			Tags:          c.commonTagsWithSuffix(fmt.Sprintf("gw-%s", endpoint)),
			VpcId:         c.state.Get(IdentifierVPC),
			ServiceName:   c.vpcEndpointServiceNamePrefix() + endpoint,
			IpAddressType: string(toEc2IpAddressType(c.getIpFamilies())),
		})
	}
	current, err := c.collectExistingVPCEndpoints(ctx)
	if err != nil {
		return err
	}

	toBeDeleted, toBeCreated, toBeChecked := diffByID(desired, current, c.extractVpcEndpointName)

	// Delete removed endpoints and their associations
	for _, item := range toBeDeleted {
		vpcEndpointName := c.extractVpcEndpointName(item)
		for _, zoneKey := range child.GetChildrenKeys() {
			zoneChild := child.GetChild(zoneKey)
			if routeTableId := zoneChild.Get(IdentifierZoneRouteTable); routeTableId != nil {
				if err := c.client.DeleteVpcEndpointRouteTableAssociation(ctx, *routeTableId, item.VpcEndpointId); err != nil {
					return err
				}
			}
		}
		if err := c.client.DeleteVpcEndpoint(ctx, item.VpcEndpointId); err != nil {
			return err
		}
		child.SetPtr(vpcEndpointName, nil)
	}

	// Create new endpoints
	for _, item := range toBeCreated {
		log.Info("creating...", "serviceName", item.ServiceName)
		created, err := c.client.CreateVpcEndpoint(ctx, item)
		if err != nil {
			return err
		}
		child.Set(c.extractVpcEndpointName(item), created.VpcEndpointId)
	}

	for _, pair := range toBeChecked {
		child.Set(c.extractVpcEndpointName(pair.current), pair.current.VpcEndpointId)
		// Ensure tags on existing endpoints
		if _, err := c.updater.UpdateEC2Tags(ctx, pair.current.VpcEndpointId, pair.desired.Tags, pair.current.Tags); err != nil {
			return err
		}
		// Ensure IpAddressType on existing endpoints
		if pair.current.IpAddressType != pair.desired.IpAddressType {
			log.Info("updating ip address type...", "serviceName", pair.current.ServiceName)
			err = c.client.UpdateVpcEndpointIpAddressType(ctx, pair.current.VpcEndpointId, pair.desired.IpAddressType)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *FlowContext) collectExistingVPCEndpoints(ctx context.Context) ([]*awsclient.VpcEndpoint, error) {
	child := c.state.GetChild(ChildIdVPCEndpoints)
	var ids []string
	for _, id := range child.AsMap() {
		ids = append(ids, id)
	}
	var current []*awsclient.VpcEndpoint
	if len(ids) > 0 {
		found, err := c.client.GetVpcEndpoints(ctx, ids)
		if err != nil {
			return nil, err
		}
		current = found
	}
	filters := awsclient.WithFilters().WithVpcId(*c.state.Get(IdentifierVPC)).WithTags(c.clusterTags()).Build()
	foundByTags, err := c.client.FindVpcEndpoints(ctx, filters)
	if err != nil {
		return nil, err
	}
outer:
	for _, item := range foundByTags {
		for _, currentItem := range current {
			if item.VpcEndpointId == currentItem.VpcEndpointId {
				continue outer
			}
		}
		current = append(current, item)
	}
	return current, nil
}

func (c *FlowContext) ensureMainRouteTable(ctx context.Context) error {
	log := LogFromContext(ctx)

	desired := &awsclient.RouteTable{
		Tags:  c.commonTags,
		VpcId: c.state.Get(IdentifierVPC),
		Routes: []*awsclient.Route{
			{
				DestinationCidrBlock: ptr.To(allIPv4),
				GatewayId:            c.state.Get(IdentifierInternetGateway),
			},
		},
	}
	if c.state.Get(IdentifierVpcIPv6CidrBlock) != nil {
		desired.Routes = append(desired.Routes, &awsclient.Route{
			DestinationIpv6CidrBlock: ptr.To(allIPv6),
			GatewayId:                c.state.Get(IdentifierInternetGateway),
		})
	}
	current, err := FindExisting(ctx, c.state.Get(IdentifierMainRouteTable), c.commonTags,
		c.client.GetRouteTable, c.client.FindRouteTablesByTags,
		func(item *awsclient.RouteTable) bool {
			return c.isVpcMatchingState(item.VpcId)
		})
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierMainRouteTable, current.RouteTableId)
		c.state.SetObject(ObjectMainRouteTable, current)
		log.Info("updating route table...")
		if _, err := c.updater.UpdateRouteTable(ctx, log, desired, current); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateRouteTable(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierMainRouteTable, created.RouteTableId)
		c.state.SetObject(ObjectMainRouteTable, created)
		log.Info("updating route table...")
		if _, err := c.updater.UpdateRouteTable(ctx, log, desired, created); err != nil {
			return err
		}
	}

	return nil
}

func (c *FlowContext) ensureNodesSecurityGroup(ctx context.Context) error {
	log := LogFromContext(ctx)
	groupName := fmt.Sprintf("%s-nodes", c.namespace)

	desired := &awsclient.SecurityGroup{
		Tags:        c.commonTagsWithSuffix("nodes"),
		GroupName:   groupName,
		VpcId:       c.state.Get(IdentifierVPC),
		Description: ptr.To("Security group for nodes"),
		Rules: []*awsclient.SecurityGroupRule{
			{
				Type:     awsclient.SecurityGroupRuleTypeIngress,
				Protocol: "-1",
				Self:     true,
			},
			{
				Type:     awsclient.SecurityGroupRuleTypeIngress,
				FromPort: ptr.To[int32](30000),
				ToPort:   ptr.To[int32](32767),
				Protocol: "tcp",
				CidrBlocks: func() []string {
					if containsIPv4(c.getIpFamilies()) {
						return []string{allIPv4}
					}
					return nil
				}(),
				CidrBlocksv6: func() []string {
					if containsIPv6(c.getIpFamilies()) {
						return []string{allIPv6}
					}
					return nil
				}(),
			},
			{
				Type:     awsclient.SecurityGroupRuleTypeIngress,
				FromPort: ptr.To[int32](30000),
				ToPort:   ptr.To[int32](32767),
				Protocol: "udp",
				CidrBlocks: func() []string {
					if containsIPv4(c.getIpFamilies()) {
						return []string{allIPv4}
					}
					return nil
				}(),
				CidrBlocksv6: func() []string {
					if containsIPv6(c.getIpFamilies()) {
						return []string{allIPv6}
					}
					return nil
				}(),
			},
			{
				Type:     awsclient.SecurityGroupRuleTypeEgress,
				Protocol: "-1",
				CidrBlocks: func() []string {
					if containsIPv4(c.getIpFamilies()) {
						return []string{allIPv4}
					}
					return nil
				}(),
				CidrBlocksv6: func() []string {
					if containsIPv6(c.getIpFamilies()) {
						return []string{allIPv6}
					}
					return nil
				}(),
			},
		},
	}

	// TODO: @hebelsan - remove processedZones after migration of shoots with duplicated zone name entries
	processedZones := sets.New[string]()
	for index, zone := range c.config.Networks.Zones {
		if processedZones.Has(zone.Name) {
			continue
		}
		processedZones.Insert(zone.Name)

		ruleNodesInternalTCP := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](30000),
			ToPort:   ptr.To[int32](32767),
			Protocol: "tcp",
		}

		ruleNodesInternalUDP := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](30000),
			ToPort:   ptr.To[int32](32767),
			Protocol: "udp",
		}

		ruleNodesPublicTCP := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](30000),
			ToPort:   ptr.To[int32](32767),
			Protocol: "tcp",
		}

		ruleNodesPublicUDP := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](30000),
			ToPort:   ptr.To[int32](32767),
			Protocol: "udp",
		}

		ruleEfsInboundNFS := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](2049),
			ToPort:   ptr.To[int32](2049),
			Protocol: "tcp",
		}

		if containsIPv4(c.getIpFamilies()) {
			ruleNodesInternalTCP.CidrBlocks = []string{zone.Internal}
			ruleNodesInternalUDP.CidrBlocks = []string{zone.Internal}
			ruleEfsInboundNFS.CidrBlocks = []string{zone.Internal}
			ruleNodesPublicTCP.CidrBlocks = []string{zone.Public}
			ruleNodesPublicUDP.CidrBlocks = []string{zone.Public}
		}

		if containsIPv6(c.getIpFamilies()) {
			ipv6CidrBlock := c.state.Get(IdentifierVpcIPv6CidrBlock)
			if ipv6CidrBlock != nil {
				subnetPrefixLength := 64
				internalSubnetCidrIPv6, err := cidrSubnet(*ipv6CidrBlock, subnetPrefixLength, 2+3*index)
				if err != nil {
					return err
				}
				publicSubnetCidrIPv6, err := cidrSubnet(*ipv6CidrBlock, subnetPrefixLength, 3+3*index)
				if err != nil {
					return err
				}
				ruleNodesInternalTCP.CidrBlocksv6 = []string{internalSubnetCidrIPv6}
				ruleNodesInternalUDP.CidrBlocksv6 = []string{internalSubnetCidrIPv6}
				ruleEfsInboundNFS.CidrBlocksv6 = []string{internalSubnetCidrIPv6}
				ruleNodesPublicTCP.CidrBlocksv6 = []string{publicSubnetCidrIPv6}
				ruleNodesPublicUDP.CidrBlocksv6 = []string{publicSubnetCidrIPv6}
			}
		}
		desired.Rules = append(desired.Rules, ruleNodesInternalTCP, ruleNodesInternalUDP, ruleNodesPublicTCP, ruleNodesPublicUDP)
		if c.isCsiEfsEnabled() {
			desired.Rules = append(desired.Rules, ruleEfsInboundNFS)
		}
	}
	current, err := FindExisting(ctx, c.state.Get(IdentifierNodesSecurityGroup), c.commonTagsWithSuffix("nodes"),
		c.client.GetSecurityGroup, c.client.FindSecurityGroupsByTags,
		func(item *awsclient.SecurityGroup) bool {
			return item.GroupName == groupName && c.isVpcMatchingState(item.VpcId)
		})
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierNodesSecurityGroup, current.GroupId)
		if _, err := c.updater.UpdateSecurityGroup(ctx, desired, current); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateSecurityGroup(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierNodesSecurityGroup, created.GroupId)
		current, err = c.client.GetSecurityGroup(ctx, created.GroupId)
		if err != nil {
			return err
		}
		if _, err := c.updater.UpdateSecurityGroup(ctx, desired, current); err != nil {
			return err
		}
	}

	return nil
}

func (c *FlowContext) ensureEgressCIDRs(ctx context.Context) error {
	var egressIPs []string
	tags := awsclient.Tags{
		c.tagKeyCluster(): TagValueCluster,
	}
	filters := awsclient.WithFilters().WithTags(tags).WithVpcId(*c.state.Get(IdentifierVPC)).Build()
	nats, err := c.client.FindNATGateways(ctx, filters)
	if err != nil {
		return err
	}
	for _, nat := range nats {
		if nat.State != string(ec2types.NatGatewayStateAvailable) {
			continue
		}
		egressIPs = append(egressIPs, fmt.Sprintf("%s/32", nat.PublicIP))
	}
	c.state.Set(IdentifierEgressCIDRs, strings.Join(egressIPs, ","))
	return nil
}

func (c *FlowContext) ensureZones(ctx context.Context) error {
	log := LogFromContext(ctx)
	var desired []*awsclient.Subnet

	// TODO: @hebelsan - remove processedZones after migration of shoots with duplicated zone name entries
	processedZones := sets.New[string]()
	for index, zone := range c.config.Networks.Zones {
		if processedZones.Has(zone.Name) {
			continue
		}
		processedZones.Insert(zone.Name)

		ipv6CidrBlock := c.state.Get(IdentifierVpcIPv6CidrBlock)
		subnetPrefixLength := 64
		var subnetCIDRs []string
		if ipv6CidrBlock != nil {
			for i := 0; i < 3; i++ {
				subnetCIDR, err := cidrSubnet(*ipv6CidrBlock, subnetPrefixLength, i+3*index)
				if err != nil {
					return err
				}
				subnetCIDRs = append(subnetCIDRs, subnetCIDR)
			}
		}
		helper := c.zoneSuffixHelpers(zone.Name)
		tagsWorkers := c.commonTagsWithSuffix(helper.GetSuffixSubnetWorkers())
		tagsPublic := c.commonTagsWithSuffix(helper.GetSuffixSubnetPublic())
		tagsPublic[TagKeyRolePublicELB] = TagValueELB
		tagsPrivate := c.commonTagsWithSuffix(helper.GetSuffixSubnetPrivate())
		tagsPrivate[TagKeyRolePrivateELB] = TagValueELB
		workersCIDR := zone.Workers
		if !containsIPv4(c.getIpFamilies()) {
			workersCIDR = ""
		}
		desired = append(desired,
			&awsclient.Subnet{
				Tags:                                    tagsWorkers,
				VpcId:                                   c.state.Get(IdentifierVPC),
				AvailabilityZone:                        zone.Name,
				AssignIpv6AddressOnCreation:             ptr.To(containsIPv6(c.getIpFamilies())),
				CidrBlock:                               workersCIDR,
				Ipv6Native:                              ptr.To(!containsIPv4(c.getIpFamilies())),
				EnableResourceNameDnsAAAARecordOnLaunch: ptr.To(!containsIPv4(c.getIpFamilies())),
				EnableDns64:                             ptr.To(!containsIPv4(c.getIpFamilies())),
			},
			// Load balancers can only be deployed to subnets that have an IPv4 CIDR.
			// Therefore, internal and public subnets must not be IPv6 native.
			&awsclient.Subnet{
				Tags:                        tagsPrivate,
				VpcId:                       c.state.Get(IdentifierVPC),
				AvailabilityZone:            zone.Name,
				AssignIpv6AddressOnCreation: ptr.To(containsIPv6(c.getIpFamilies())),
				CidrBlock:                   zone.Internal,
			},
			&awsclient.Subnet{
				Tags:                        tagsPublic,
				VpcId:                       c.state.Get(IdentifierVPC),
				AvailabilityZone:            zone.Name,
				AssignIpv6AddressOnCreation: ptr.To(containsIPv6(c.getIpFamilies())),
				CidrBlock:                   zone.Public,
			},
		)

		for i := 0; i < 3; i++ {
			if len(subnetCIDRs) == 3 && subnetCIDRs[i] != "" {
				desired[i+3*index].Ipv6CidrBlocks = []string{subnetCIDRs[i]}
			}
		}
	}
	// update flow state if subnet suffixes have been added
	if err := c.PersistState(ctx); err != nil {
		return err
	}
	current, err := c.collectExistingSubnets(ctx)
	if err != nil {
		return err
	}

	log.Info("Found existing subnets", "subnetIDs", mmap(current, func(t *awsclient.Subnet) string {
		return t.SubnetId
	}))
	toBeDeleted, toBeCreated, toBeChecked := diffByID(desired, current, func(item *awsclient.Subnet) string {
		if item.Ipv6CidrBlocks != nil && item.CidrBlock == "" {
			return item.AvailabilityZone + "-" + item.Ipv6CidrBlocks[0]
		}
		return item.AvailabilityZone + "-" + item.CidrBlock
	})

	g := flow.NewGraph("AWS infrastructure reconciliation: zones")

	if err := c.addZoneDeletionTasksBySubnets(g, toBeDeleted); err != nil {
		return err
	}

	dependencies := newZoneDependencies()
	for _, item := range toBeCreated {
		taskID, err := c.addSubnetReconcileTasks(g, item, nil)
		if err != nil {
			return err
		}
		dependencies.Append(item.AvailabilityZone, taskID)
	}
	for _, pair := range toBeChecked {
		taskID, err := c.addSubnetReconcileTasks(g, pair.desired, pair.current)
		if err != nil {
			return err
		}
		dependencies.Append(pair.desired.AvailabilityZone, taskID)
	}

	// TODO: @hebelsan - remove processedZones after migration of shoots with duplicated zone name entries
	processedZones = sets.New[string]()
	for _, item := range c.config.Networks.Zones {
		if processedZones.Has(item.Name) {
			continue
		}
		processedZones.Insert(item.Name)

		zone := item
		c.addZoneReconcileTasks(g, &zone, dependencies.Get(zone.Name))
	}
	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{Log: c.log}); err != nil {
		return flow.Causes(err)
	}
	return nil
}

func (c *FlowContext) addZoneDeletionTasksBySubnets(g *flow.Graph, toBeDeleted []*awsclient.Subnet) error {
	toBeDeletedZones := sets.NewString()
	for _, item := range toBeDeleted {
		toBeDeletedZones.Insert(getZoneName(item))
	}
	dependencies := newZoneDependencies()
	for zoneName := range toBeDeletedZones {
		taskID := c.addZoneDeletionTasks(g, zoneName)
		dependencies.Append(zoneName, taskID)
	}
	for _, item := range toBeDeleted {
		if err := c.addSubnetDeletionTasks(g, item, dependencies.Get(item.AvailabilityZone)); err != nil {
			return err
		}
	}
	return nil
}

func (c *FlowContext) collectExistingSubnets(ctx context.Context) ([]*awsclient.Subnet, error) {
	child := c.state.GetChild(ChildIdZones)
	var ids []string
	for _, zoneKey := range child.GetChildrenKeys() {
		zoneChild := child.GetChild(zoneKey)
		if id := zoneChild.Get(IdentifierZoneSubnetWorkers); id != nil {
			ids = append(ids, *id)
		}
		if id := zoneChild.Get(IdentifierZoneSubnetPublic); id != nil {
			ids = append(ids, *id)
		}
		if id := zoneChild.Get(IdentifierZoneSubnetPrivate); id != nil {
			ids = append(ids, *id)
		}
	}

	var current []*awsclient.Subnet
	if len(ids) > 0 {
		found, err := c.client.GetSubnets(ctx, ids)
		if err != nil {
			return nil, err
		}
		current = found
	}
	foundSubnets, err := c.client.FindSubnets(ctx, awsclient.WithFilters().WithVpcId(*c.state.Get(IdentifierVPC)).WithTags(c.clusterTags()).Build())
	if err != nil {
		return nil, err
	}
	for _, item := range foundSubnets {
		func() {
			for _, currentItem := range current {
				if item.SubnetId == currentItem.SubnetId {
					return
				}
			}
			current = append(current, item)
		}()
	}
	return current, nil
}

func (c *FlowContext) addSubnetReconcileTasks(g *flow.Graph, desired, current *awsclient.Subnet) (flow.TaskIDer, error) {
	zoneName, subnetKey, err := c.getSubnetKey(desired)
	if err != nil {
		return nil, err
	}
	suffix := fmt.Sprintf("%s-%s", zoneName, subnetKey)
	if ptr.Deref(desired.AssignIpv6AddressOnCreation, true) {
		return c.AddTask(g, "ensure IPv6 subnet "+suffix,
			c.ensureSubnetIPv6(subnetKey, desired, current),
			Timeout(defaultTimeout)), nil
	}
	return c.AddTask(g, "ensure subnet "+suffix,
		c.ensureSubnet(subnetKey, desired, current),
		Timeout(defaultTimeout)), nil
}

func (c *FlowContext) addZoneReconcileTasks(g *flow.Graph, zone *aws.Zone, dependencies []flow.TaskIDer) {
	ensureRecreateNATGateway := c.AddTask(g, "ensure NAT gateway recreation "+zone.Name,
		c.ensureRecreateNATGateway(zone),
		Timeout(defaultTimeout), Dependencies(dependencies...))

	ensureElasticIP := c.AddTask(g, "ensure NAT gateway elastic IP "+zone.Name,
		c.ensureElasticIP(zone),
		Timeout(defaultTimeout), Dependencies(dependencies...), Dependencies(ensureRecreateNATGateway))

	ensureNATGateway := c.AddTask(g, "ensure NAT gateway "+zone.Name,
		c.ensureNATGateway(zone),
		Timeout(defaultLongTimeout), Dependencies(dependencies...), Dependencies(ensureElasticIP))

	ensureRoutingTable := c.AddTask(g, "ensure route table "+zone.Name,
		c.ensurePrivateRoutingTable(zone.Name),
		Timeout(defaultTimeout), Dependencies(dependencies...), Dependencies(ensureNATGateway))

	_ = c.AddTask(g, "ensure route table associations "+zone.Name,
		c.ensureRoutingTableAssociations(zone.Name),
		Timeout(defaultTimeout), Dependencies(dependencies...), Dependencies(ensureRoutingTable))

	_ = c.AddTask(g, "ensure VPC endpoints route table associations "+zone.Name,
		c.ensureVPCEndpointsRoutingTableAssociations(zone.Name),
		Timeout(defaultTimeout), Dependencies(dependencies...), Dependencies(ensureRoutingTable))
}

func (c *FlowContext) addZoneDeletionTasks(g *flow.Graph, zoneName string) flow.TaskIDer {
	deleteRoutingTableAssocs := c.AddTask(g, "delete route table associations "+zoneName,
		c.deleteRoutingTableAssociations(zoneName),
		Timeout(defaultTimeout))

	deleteRoutingTable := c.AddTask(g, "delete route table "+zoneName,
		c.deletePrivateRoutingTable(zoneName),
		Timeout(defaultTimeout), Dependencies(deleteRoutingTableAssocs))

	deleteNATGateway := c.AddTask(g, "delete NAT gateway "+zoneName,
		c.deleteNATGateway(zoneName),
		Timeout(defaultLongTimeout), Dependencies(deleteRoutingTable))

	_ = c.AddTask(g, "delete NAT gateway elastic IP "+zoneName,
		c.deleteElasticIP(zoneName),
		Timeout(defaultTimeout), Dependencies(deleteNATGateway))

	return deleteNATGateway
}

func (c *FlowContext) addSubnetDeletionTasks(g *flow.Graph, item *awsclient.Subnet, dependencies []flow.TaskIDer) error {
	zoneName, subnetKey, err := c.getSubnetKey(item)
	if err != nil {
		return err
	}
	suffix := fmt.Sprintf("%s-%s", zoneName, subnetKey)
	_ = c.AddTask(g, "delete subnet resource "+suffix,
		c.deleteSubnet(subnetKey, item),
		Timeout(defaultTimeout), Dependencies(dependencies...))
	return nil
}

func (c *FlowContext) deleteSubnet(subnetKey string, item *awsclient.Subnet) flow.TaskFn {
	zoneChild := c.getSubnetZoneChildByItem(item)
	return func(ctx context.Context) error {
		if zoneChild.Get(subnetKey) == nil {
			return nil
		}
		log := LogFromContext(ctx)
		log.Info("deleting...", "SubnetID", item.SubnetId)
		waiter := informOnWaiting(log, 10*time.Second, "still deleting...", "SubnetID", item.SubnetId)
		err := c.client.DeleteSubnet(ctx, item.SubnetId)
		waiter.Done(err)
		if err != nil {
			return err
		}
		zoneChild.Delete(subnetKey)
		return nil
	}
}

func (c *FlowContext) ensureSubnet(subnetKey string, desired, current *awsclient.Subnet) flow.TaskFn {
	zoneChild := c.getSubnetZoneChildByItem(desired)
	if current == nil {
		return func(ctx context.Context) error {
			log := LogFromContext(ctx)
			log.Info("creating...")
			created, err := c.client.CreateSubnet(ctx, desired, defaultTimeout)
			if err != nil {
				return err
			}
			zoneChild.Set(subnetKey, created.SubnetId)
			return nil
		}
	}
	return func(ctx context.Context) error {
		zoneChild.Set(subnetKey, current.SubnetId)
		modified, err := c.updater.UpdateSubnet(ctx, desired, current)
		if err != nil {
			return err
		}
		if modified {
			log := LogFromContext(ctx)
			log.Info("updated")
		}
		return nil
	}
}

func (c *FlowContext) ensureSubnetIPv6(subnetKey string, desired, current *awsclient.Subnet) flow.TaskFn {
	zoneChild := c.getSubnetZoneChildByItem(desired)
	if current == nil {
		return func(ctx context.Context) error {
			log := LogFromContext(ctx)
			log.Info("creating...")
			var lastErr error
			for attempts := 0; attempts < 256; attempts++ {
				created, err := c.client.CreateSubnet(ctx, desired, defaultTimeout)
				if err == nil {
					zoneChild.Set(subnetKey, created.SubnetId)
					return nil
				}
				// Check for InvalidSubnet.Conflict error
				apiErrCode := awsclient.GetAWSAPIErrorCode(err)
				if apiErrCode == "InvalidSubnet.Conflict" {
					log.Info("CIDR conflict, trying next CIDR block")
					newCIDRs, nextErr := calcNextIPv6CidrBlock(desired.Ipv6CidrBlocks[0])
					if nextErr != nil {
						return nextErr
					}
					desired.Ipv6CidrBlocks = []string{newCIDRs}
					lastErr = err
					continue
				}
				// Any other error, return immediately
				return err
			}
			// If we exhausted all attempts, return the last error
			if lastErr != nil {
				return lastErr
			}
			return fmt.Errorf("failed to create subnet after multiple attempts")
		}
	}
	return func(ctx context.Context) error {
		zoneChild.Set(subnetKey, current.SubnetId)
		modified, err := c.updater.UpdateSubnet(ctx, desired, current)
		if err != nil {
			return err
		}
		if modified {
			log := LogFromContext(ctx)
			log.Info("updated")
		}
		return nil
	}
}

func (c *FlowContext) ensureSubnetCidrReservation(ctx context.Context) error {
	if !containsIPv6(c.getIpFamilies()) {
		return nil
	}

	subnets, err := c.collectExistingSubnets(ctx)
	if err != nil {
		return err
	}

	for _, subnet := range subnets {
		_, key, err := c.getSubnetKey(subnet)
		if err != nil {
			return err
		}

		if key == IdentifierZoneSubnetWorkers {
			cidr, err := cidrSubnet(subnet.Ipv6CidrBlocks[0], 108, 1)
			if err != nil {
				return err
			}

			currentCidrs, err := c.client.GetIPv6CIDRReservations(ctx, subnet)
			if err != nil {
				return err
			}

			if slices.Contains(currentCidrs, cidr) {
				c.state.Set(IdentifierServiceCIDR, cidr)
				return nil
			}
		}
	}

	// we didn't find a CIDR reservation on a subnet
	// create a new one at the first nodes subnet we find
	for _, subnet := range subnets {
		_, key, err := c.getSubnetKey(subnet)
		if err != nil {
			return err
		}

		if key == IdentifierZoneSubnetWorkers {
			cidr, err := cidrSubnet(subnet.Ipv6CidrBlocks[0], 108, 1)
			if err != nil {
				return err
			}

			cidr, err = c.client.CreateCIDRReservation(ctx, subnet, cidr, "explicit")
			if err != nil {
				return err
			}
			c.state.Set(IdentifierServiceCIDR, cidr)
			return nil
		}
	}
	return nil
}

func (c *FlowContext) ensureElasticIP(zone *aws.Zone) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		helper := c.zoneSuffixHelpers(zone.Name)
		child := c.getSubnetZoneChild(zone.Name)
		id := child.Get(IdentifierManagedZoneNATGWElasticIP)
		if zone.ElasticIPAllocationID != nil {
			// check if we need to clean up gardener managed IP, after user switched from managed to unmanaged
			if id != nil && *id != *zone.ElasticIPAllocationID {
				ip, err := c.client.GetElasticIP(ctx, *id)
				if err != nil {
					return err
				}
				// make sure that the EIP is not in use
				if ip != nil && ip.AssociationID == nil {
					log.Info("deleting unused managed elastic IP found in state", "id", *id)
					err = c.deleteElasticIpWithWait(ctx, ip)
					if err != nil {
						return err
					}
					child.Delete(IdentifierManagedZoneNATGWElasticIP)
				}
			}
			return nil
		}
		desired := &awsclient.ElasticIP{
			Tags: c.commonTagsWithSuffix(helper.GetSuffixElasticIP()),
			Vpc:  true,
		}
		current, err := FindExisting(ctx, id, desired.Tags, c.client.GetElasticIP, c.client.FindElasticIPsByTags)
		if err != nil {
			return err
		}

		if current != nil {
			child.Set(IdentifierManagedZoneNATGWElasticIP, current.AllocationId)
			if _, err := c.updater.UpdateEC2Tags(ctx, current.AllocationId, desired.Tags, current.Tags); err != nil {
				return err
			}
		} else {
			log.Info("creating...")
			created, err := c.client.CreateElasticIP(ctx, desired)
			if err != nil {
				return err
			}
			child.Set(IdentifierManagedZoneNATGWElasticIP, created.AllocationId)
		}

		return nil
	}
}

func (c *FlowContext) deleteElasticIP(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		child := c.getSubnetZoneChild(zoneName)
		if child.Get(IdentifierManagedZoneNATGWElasticIP) == nil {
			return nil
		}
		helper := c.zoneSuffixHelpers(zoneName)
		tags := c.commonTagsWithSuffix(helper.GetSuffixElasticIP())
		current, err := FindExisting(ctx, child.Get(IdentifierManagedZoneNATGWElasticIP), tags, c.client.GetElasticIP, c.client.FindElasticIPsByTags)
		if err != nil {
			return err
		}
		err = c.deleteElasticIpWithWait(ctx, current)
		if err != nil {
			return err
		}
		child.Delete(IdentifierManagedZoneNATGWElasticIP)
		return nil
	}
}

func (c *FlowContext) deleteElasticIpWithWait(ctx context.Context, elasticIP *awsclient.ElasticIP) error {
	if elasticIP != nil {
		log := LogFromContext(ctx)
		log.Info("deleting...", "AllocationId", elasticIP.AllocationId)
		waiter := informOnWaiting(log, 10*time.Second, "still deleting...", "AllocationId", elasticIP.AllocationId)
		err := c.client.DeleteElasticIP(ctx, elasticIP.AllocationId)
		waiter.Done(err)
		if err != nil {
			return err
		}
	}
	return nil
}

// ensureRecreateNATGateway checks if the EIPAllocationId has changed.
func (c *FlowContext) ensureRecreateNATGateway(zone *aws.Zone) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		child := c.getSubnetZoneChild(zone.Name)
		helper := c.zoneSuffixHelpers(zone.Name)
		desired := &awsclient.NATGateway{
			Tags:     c.commonTagsWithSuffix(helper.GetSuffixNATGateway()),
			SubnetId: *child.Get(IdentifierZoneSubnetPublic),
		}
		// no NAT was created yet
		if zone.ElasticIPAllocationID == nil && child.Get(IdentifierManagedZoneNATGWElasticIP) == nil {
			return nil
		}
		if zone.ElasticIPAllocationID != nil {
			desired.EIPAllocationId = *zone.ElasticIPAllocationID
		} else {
			desired.EIPAllocationId = *child.Get(IdentifierManagedZoneNATGWElasticIP)
		}
		current, err := FindExisting(ctx, child.Get(IdentifierZoneNATGateway), desired.Tags, c.client.GetNATGateway, c.client.FindNATGatewaysByTags,
			func(item *awsclient.NATGateway) bool {
				// a failed NAT will automatically be deleted by AWS
				return !isNATGatewayDeletingOrFailed(item) && c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}

		if current != nil && current.EIPAllocationId != desired.EIPAllocationId {
			log.Info("deleting NAT because of EIPAllocationID change detected", "current EIPAllocationId",
				current.EIPAllocationId, "desired EIPAllocationId", desired.EIPAllocationId)
			err := c.deleteNATGateway(zone.Name)(ctx)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *FlowContext) ensureNATGateway(zone *aws.Zone) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		child := c.getSubnetZoneChild(zone.Name)
		helper := c.zoneSuffixHelpers(zone.Name)
		desired := &awsclient.NATGateway{
			Tags:     c.commonTagsWithSuffix(helper.GetSuffixNATGateway()),
			SubnetId: *child.Get(IdentifierZoneSubnetPublic),
		}
		if zone.ElasticIPAllocationID != nil {
			desired.EIPAllocationId = *zone.ElasticIPAllocationID
		} else {
			desired.EIPAllocationId = *child.Get(IdentifierManagedZoneNATGWElasticIP)
		}
		current, err := FindExisting(ctx, child.Get(IdentifierZoneNATGateway), desired.Tags, c.client.GetNATGateway, c.client.FindNATGatewaysByTags,
			func(item *awsclient.NATGateway) bool {
				return !isNATGatewayDeletingOrFailed(item) && c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}

		if current != nil {
			child.Set(IdentifierZoneNATGateway, current.NATGatewayId)
			if _, err := c.updater.UpdateEC2Tags(ctx, current.NATGatewayId, desired.Tags, current.Tags); err != nil {
				return err
			}
			waiter := informOnWaiting(log, 10*time.Second, "waiting for NATGateway to become available...")
			err = c.client.WaitForNATGatewayAvailable(ctx, current.NATGatewayId)
			waiter.Done(err)
			if err != nil {
				return err
			}
		} else {
			child.Set(IdentifierZoneNATGateway, "")
			log.Info("creating...")
			waiter := informOnWaiting(log, 10*time.Second, "still creating...")
			created, err := c.client.CreateNATGateway(ctx, desired)
			if created != nil {
				waiter.UpdateMessage("waiting until available...")
				if perr := c.PersistState(ctx); perr != nil {
					log.Info("persisting state failed", "error", perr)
				}
				child.Set(IdentifierZoneNATGateway, created.NATGatewayId)
				err = c.client.WaitForNATGatewayAvailable(ctx, created.NATGatewayId)
			}
			waiter.Done(err)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *FlowContext) deleteNATGateway(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		child := c.getSubnetZoneChild(zoneName)
		if child.Get(IdentifierZoneNATGateway) == nil {
			return nil
		}
		log := LogFromContext(ctx)
		helper := c.zoneSuffixHelpers(zoneName)
		tags := c.commonTagsWithSuffix(helper.GetSuffixNATGateway())
		current, err := FindExisting(ctx, child.Get(IdentifierZoneNATGateway), tags, c.client.GetNATGateway, c.client.FindNATGatewaysByTags,
			func(item *awsclient.NATGateway) bool {
				// a failed NAT will automatically be deleted by AWS
				return !isNATGatewayDeletingOrFailed(item) && c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}
		if current != nil {
			log.Info("deleting...", "NATGatewayId", current.NATGatewayId)
			waiter := informOnWaiting(log, 10*time.Second, "still deleting...", "NATGatewayId", current.NATGatewayId)
			err := c.client.DeleteNATGateway(ctx, current.NATGatewayId)
			waiter.Done(err)
			if err != nil {
				return err
			}
		}
		child.Delete(IdentifierZoneNATGateway)
		return nil
	}
}

func (c *FlowContext) ensureEgressOnlyInternetGateway(ctx context.Context) error {
	if !containsIPv6(c.getIpFamilies()) {
		return nil
	}

	log := LogFromContext(ctx)
	desired := &awsclient.EgressOnlyInternetGateway{
		Tags:  c.commonTags,
		VpcId: c.state.Get(IdentifierVPC),
	}
	current, err := FindExisting(ctx, c.state.Get(IdentifierEgressOnlyInternetGateway), c.commonTags,
		c.client.GetEgressOnlyInternetGateway, c.client.FindEgressOnlyInternetGatewaysByTags,
		func(item *awsclient.EgressOnlyInternetGateway) bool {
			return c.isVpcMatchingState(item.VpcId)
		})
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(IdentifierEgressOnlyInternetGateway, current.EgressOnlyInternetGatewayId)
		if _, err := c.updater.UpdateEC2Tags(ctx, current.EgressOnlyInternetGatewayId, c.commonTags, current.Tags); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateEgressOnlyInternetGateway(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierEgressOnlyInternetGateway, created.EgressOnlyInternetGatewayId)
	}
	return nil
}

func (c *FlowContext) ensurePrivateRoutingTable(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		child := c.getSubnetZoneChild(zoneName)
		id := child.Get(IdentifierZoneRouteTable)

		var routes []*awsclient.Route

		routes = append(routes, &awsclient.Route{
			DestinationCidrBlock: ptr.To(allIPv4),
			NatGatewayId:         child.Get(IdentifierZoneNATGateway),
		})

		if containsIPv6(c.getIpFamilies()) {
			routes = append(routes, &awsclient.Route{
				DestinationIpv6CidrBlock:    ptr.To(allIPv6),
				EgressOnlyInternetGatewayId: c.state.Get(IdentifierEgressOnlyInternetGateway),
			})
			routes = append(routes, &awsclient.Route{
				DestinationIpv6CidrBlock: ptr.To(nat64Prefix),
				NatGatewayId:             child.Get(IdentifierZoneNATGateway),
			})
		}

		desired := &awsclient.RouteTable{
			Tags:   c.commonTagsWithSuffix(fmt.Sprintf("private-%s", zoneName)),
			VpcId:  c.state.Get(IdentifierVPC),
			Routes: routes,
		}

		current, err := FindExisting(ctx, id, desired.Tags, c.client.GetRouteTable, c.client.FindRouteTablesByTags,
			func(item *awsclient.RouteTable) bool {
				return c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}

		if current != nil {
			child.Set(IdentifierZoneRouteTable, current.RouteTableId)
			child.SetObject(ObjectZoneRouteTable, current)
			if _, err := c.updater.UpdateRouteTable(ctx, log, desired, current); err != nil {
				return err
			}
		} else {
			log.Info("creating...", "zone", zoneName)
			created, err := c.client.CreateRouteTable(ctx, desired)
			if err != nil {
				return err
			}
			child.Set(IdentifierZoneRouteTable, created.RouteTableId)
			child.SetObject(ObjectZoneRouteTable, created)
			if _, err := c.updater.UpdateRouteTable(ctx, log, desired, created); err != nil {
				return err
			}
		}

		return nil
	}
}

func (c *FlowContext) deletePrivateRoutingTable(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		child := c.getSubnetZoneChild(zoneName)
		if child.Get(IdentifierZoneRouteTable) == nil {
			return nil
		}
		tags := c.commonTagsWithSuffix(fmt.Sprintf("private-%s", zoneName))
		current, err := FindExisting(ctx, child.Get(IdentifierZoneRouteTable), tags, c.client.GetRouteTable,
			c.client.FindRouteTablesByTags, func(item *awsclient.RouteTable) bool {
				return c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}
		if current != nil {
			log.Info("deleting...", "RouteTableId", current.RouteTableId)
			if err := c.client.DeleteRouteTable(ctx, current.RouteTableId); err != nil {
				return err
			}
		}
		child.Delete(IdentifierZoneRouteTable)
		return nil
	}
}

func (c *FlowContext) ensureRoutingTableAssociations(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		if err := c.ensureZoneRoutingTableAssociation(ctx, zoneName, false,
			IdentifierZoneSubnetPublic, IdentifierZoneSubnetPublicRouteTableAssoc); err != nil {
			return err
		}
		if err := c.ensureZoneRoutingTableAssociation(ctx, zoneName, true,
			IdentifierZoneSubnetPrivate, IdentifierZoneSubnetPrivateRouteTableAssoc); err != nil {
			return err
		}
		return c.ensureZoneRoutingTableAssociation(ctx, zoneName, true,
			IdentifierZoneSubnetWorkers, IdentifierZoneSubnetWorkersRouteTableAssoc)
	}
}

func (c *FlowContext) ensureZoneRoutingTableAssociation(ctx context.Context, zoneName string,
	zoneRouteTable bool, subnetKey, assocKey string) error {
	child := c.getSubnetZoneChild(zoneName)
	assocID := child.Get(assocKey)
	if assocID != nil {
		return nil
	}
	subnetID := child.Get(subnetKey)
	if subnetID == nil {
		return fmt.Errorf("missing subnet id")
	}
	var obj any
	if zoneRouteTable {
		obj = child.GetObject(ObjectZoneRouteTable)
	} else {
		obj = c.state.GetObject(ObjectMainRouteTable)
	}
	if obj == nil {
		return fmt.Errorf("missing route table object")
	}
	routeTable := obj.(*awsclient.RouteTable)
	for _, assoc := range routeTable.Associations {
		if reflect.DeepEqual(assoc.SubnetId, subnetID) {
			child.Set(assocKey, assoc.RouteTableAssociationId)
			return nil
		}
	}
	log := LogFromContext(ctx)
	log.Info("creating...")
	assocID, err := c.client.CreateRouteTableAssociation(ctx, routeTable.RouteTableId, *subnetID)
	if err != nil {
		return err
	}
	child.Set(assocKey, *assocID)
	return nil
}

func (c *FlowContext) ensureVPCEndpointsRoutingTableAssociations(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		for _, endpoint := range c.config.Networks.VPC.GatewayEndpoints {
			if err := c.ensureVPCEndpointZoneRoutingTableAssociation(ctx, zoneName, endpoint); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *FlowContext) ensureVPCEndpointZoneRoutingTableAssociation(ctx context.Context, zoneName, endpointName string) error {
	child := c.getSubnetZoneChild(zoneName)
	subnetID := child.Get(IdentifierZoneSubnetWorkers)
	if subnetID == nil {
		return fmt.Errorf("missing subnet id")
	}
	vpcEndpointID := c.state.GetChild(ChildIdVPCEndpoints).Get(endpointName)
	if vpcEndpointID == nil {
		return fmt.Errorf("missing VPC endpoint: %s", endpointName)
	}
	obj := child.GetObject(ObjectZoneRouteTable)
	if obj == nil {
		return fmt.Errorf("missing route table object")
	}
	routeTable := obj.(*awsclient.RouteTable)
	for _, route := range routeTable.Routes {
		if reflect.DeepEqual(route.GatewayId, vpcEndpointID) {
			return nil
		}
	}
	log := LogFromContext(ctx)
	log.Info("creating...", "endpoint", endpointName)

	return c.client.CreateVpcEndpointRouteTableAssociation(ctx, routeTable.RouteTableId, *vpcEndpointID)
}

func (c *FlowContext) deleteRoutingTableAssociations(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		if err := c.deleteZoneRoutingTableAssociation(ctx, zoneName, false,
			IdentifierZoneSubnetPublic, IdentifierZoneSubnetPublicRouteTableAssoc); err != nil {
			return err
		}
		if err := c.deleteZoneRoutingTableAssociation(ctx, zoneName, true,
			IdentifierZoneSubnetPrivate, IdentifierZoneSubnetPrivateRouteTableAssoc); err != nil {
			return err
		}
		return c.deleteZoneRoutingTableAssociation(ctx, zoneName, true,
			IdentifierZoneSubnetWorkers, IdentifierZoneSubnetWorkersRouteTableAssoc)
	}
}

func (c *FlowContext) deleteZoneRoutingTableAssociation(ctx context.Context, zoneName string,
	zoneRouteTable bool, subnetKey, assocKey string) error {
	child := c.getSubnetZoneChild(zoneName)
	subnetID := child.Get(subnetKey)
	assocID := child.Get(assocKey)

	if assocID == nil && subnetID != nil {
		// unclear situation: load route table to search for association
		var routeTableID *string
		if zoneRouteTable {
			routeTableID = child.Get(IdentifierZoneRouteTable)
		} else {
			routeTableID = c.state.Get(IdentifierMainRouteTable)
		}
		if routeTableID != nil {
			routeTable, err := c.client.GetRouteTable(ctx, *routeTableID)
			if err != nil {
				return err
			}
			// if not found routeTable might be nil
			if routeTable != nil {
				for _, assoc := range routeTable.Associations {
					if reflect.DeepEqual(subnetID, assoc.SubnetId) {
						assocID = &assoc.RouteTableAssociationId
						break
					}
				}
			}
		}
	}

	log := LogFromContext(ctx)
	if assocID == nil {
		log.Info("No association ID found, nothing to delete", "SubnetID", subnetID)
		return nil
	}
	log.Info("deleting...", "RouteTableAssociationId", *assocID)
	if err := c.client.DeleteRouteTableAssociation(ctx, *assocID); err != nil {
		return err
	}
	child.Delete(assocKey)
	return nil
}

func (c *FlowContext) ensureIAMRole(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := &awsclient.IAMRole{
		RoleName: fmt.Sprintf("%s-nodes", c.namespace),
		Path:     "/",
		AssumeRolePolicyDocument: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`,
	}
	current, err := c.client.GetIAMRole(ctx, desired.RoleName)
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(NameIAMRole, current.RoleName)
		c.state.Set(ARNIAMRole, current.ARN)
		if _, err := c.updater.UpdateIAMRole(ctx, desired, current); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateIAMRole(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(NameIAMRole, created.RoleName)
		c.state.Set(ARNIAMRole, created.ARN)
	}

	return nil
}

func (c *FlowContext) ensureIAMInstanceProfile(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := &awsclient.IAMInstanceProfile{
		InstanceProfileName: fmt.Sprintf("%s-nodes", c.namespace),
		Path:                "/",
		RoleName:            fmt.Sprintf("%s-nodes", c.namespace),
	}
	current, err := c.client.GetIAMInstanceProfile(ctx, desired.InstanceProfileName)
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(NameIAMInstanceProfile, current.InstanceProfileName)
		if _, err := c.updater.UpdateIAMInstanceProfile(ctx, desired, current); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateIAMInstanceProfile(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(NameIAMInstanceProfile, created.InstanceProfileName)
		if _, err := c.updater.UpdateIAMInstanceProfile(ctx, desired, created); err != nil {
			return err
		}
	}

	return nil
}

const iamRolePolicyTemplate = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Resource": [
        "*"
      ]
    }{{ if .enableEfsAccess }},
	{
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:CreateAccessPoint",
        "elasticfilesystem:DeleteAccessPoint",
        "elasticfilesystem:TagResource",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": [
        "*"
      ]
	}{{ end }}{{ if .enableECRAccess }},
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:BatchGetImage"
      ],
      "Resource": [
        "*"
      ]
    }{{ end }}
  ]
}`

func (c *FlowContext) ensureIAMRolePolicy(ctx context.Context) error {
	log := LogFromContext(ctx)
	t, err := template.New("policyDocument").Parse(iamRolePolicyTemplate)
	if err != nil {
		return fmt.Errorf("parsing policyDocument template failed: %s", err)
	}
	var buffer bytes.Buffer
	templateData := map[string]any{
		"enableECRAccess": ptr.Deref(c.config.EnableECRAccess, true),
		"enableEfsAccess": ptr.Deref(c.config.ElasticFileSystem, aws.ElasticFileSystemConfig{}).Enabled,
	}
	if err := t.Execute(&buffer, templateData); err != nil {
		return fmt.Errorf("executing policyDocument template failed: %s", err)
	}

	name := fmt.Sprintf("%s-nodes", c.namespace)
	desired := &awsclient.IAMRolePolicy{
		PolicyName:     name,
		RoleName:       name,
		PolicyDocument: buffer.String(),
	}
	current, err := c.client.GetIAMRolePolicy(ctx, desired.PolicyName, desired.RoleName)
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(NameIAMRolePolicy, name)
		if current.PolicyDocument != desired.PolicyDocument {
			if err := c.client.PutIAMRolePolicy(ctx, desired); err != nil {
				return err
			}
		}
	} else {
		log.Info("creating...")
		if err := c.client.PutIAMRolePolicy(ctx, desired); err != nil {
			return err
		}
		c.state.Set(NameIAMRolePolicy, name)
	}

	return nil
}

func (c *FlowContext) ensureKeyPair(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := &awsclient.KeyPairInfo{
		Tags:    c.commonTags,
		KeyName: fmt.Sprintf("%s-ssh-publickey", c.namespace),
	}
	current, err := c.client.GetKeyPair(ctx, desired.KeyName)
	if err != nil {
		return err
	}

	if len(c.infraSpec.SSHPublicKey) == 0 {
		return c.deleteKeyPair(ctx)
	}

	specFingerprint := fmt.Sprintf("%x", md5.Sum(c.infraSpec.SSHPublicKey)) // #nosec G401 -- No cryptographic context.
	if current != nil {
		// check for foreign key replacement
		if fingerprint := c.state.Get(KeyPairFingerprint); fingerprint == nil || *fingerprint != current.KeyFingerprint {
			log.Info("deleting as modified by unknown")
			if err := c.client.DeleteKeyPair(ctx, current.KeyName); err != nil {
				return err
			}
			current = nil
		}
	}
	if current != nil {
		// check for key replacement in spec
		if fingerprint := c.state.Get(KeyPairSpecFingerprint); fingerprint == nil || *fingerprint != specFingerprint {
			log.Info("deleting as replaced in spec")
			if err := c.client.DeleteKeyPair(ctx, current.KeyName); err != nil {
				return err
			}
			current = nil
		}
	}

	if current != nil {
		c.state.Set(NameKeyPair, desired.KeyName)
	} else {
		log.Info("creating")
		info, err := c.client.ImportKeyPair(ctx, desired.KeyName, c.infraSpec.SSHPublicKey, c.commonTags)
		if err != nil {
			return err
		}
		c.state.Set(NameKeyPair, info.KeyName)
		c.state.Set(KeyPairFingerprint, info.KeyFingerprint)
		c.state.Set(KeyPairSpecFingerprint, specFingerprint)
	}

	return nil
}

func (c *FlowContext) ensureEfs(ctx context.Context) error {
	err := c.ensureEfsCreateFileSystem(ctx)
	if err != nil {
		return err
	}

	return c.ensureEfsMountTargets(ctx)
}

func (c *FlowContext) ensureEfsCreateFileSystem(ctx context.Context) error {
	log := LogFromContext(ctx)

	current, err := FindExisting(ctx, c.state.Get(IdentifierManagedEfsID), c.commonTags.AddManagedTag(),
		c.client.GetFileSystems, c.client.FindFileSystemsByTags)
	if err != nil {
		return fmt.Errorf("failed to find managed EFS file system: %w", err)
	}

	// check for user provided EFS file system
	if c.config.ElasticFileSystem.ID != nil && current != nil {
		if err := c.deleteEfs(ctx); err != nil {
			return fmt.Errorf("failed to delete managed EFS file system: %w", err)
		}
		c.state.Delete(IdentifierManagedEfsID)
	}
	if c.config.ElasticFileSystem.ID != nil {
		return nil
	}

	// check if we already created an EFS file system
	if current != nil {
		c.state.Set(IdentifierManagedEfsID, *current.FileSystemId)
		return nil
	}

	inputCreate := &efs.CreateFileSystemInput{
		Tags:          c.commonTags.AddManagedTag().ToEfsTags(),
		CreationToken: ptr.To(c.shootUUID),
		Encrypted:     ptr.To(true),
	}
	efsCreate, err := c.client.CreateFileSystem(ctx, inputCreate)
	if err != nil {
		return err
	}

	if efsCreate == nil || efsCreate.FileSystemId == nil {
		return fmt.Errorf("the created file system id is <nil>")
	}

	c.state.Set(IdentifierManagedEfsID, *efsCreate.FileSystemId)

	log.Info("created file system", "id", *efsCreate.FileSystemId)

	return nil
}

func (c *FlowContext) ensureEfsMountTargets(ctx context.Context) error {
	log := LogFromContext(ctx)

	var efsID *string
	switch {
	case c.config.ElasticFileSystem.ID != nil:
		efsID = c.config.ElasticFileSystem.ID
	case c.state.Get(IdentifierManagedEfsID) != nil:
		efsID = c.state.Get(IdentifierManagedEfsID)
	default:
		return fmt.Errorf("trying to ensure efs mount targets, but efs id is not set")
	}

	securityGroupID := c.state.Get(IdentifierNodesSecurityGroup)
	if securityGroupID == nil {
		return fmt.Errorf("security group not found in state")
	}

	mountTargetsToCreate := make(map[string]*efs.CreateMountTargetInput)
	childMountTargets := c.state.GetChild(ChildEfsMountTargets)
	existingMountTargetKeys := childMountTargets.Keys()
	childZones := c.state.GetChild(ChildIdZones)

	for _, zoneKey := range childZones.GetChildrenKeys() {
		zoneChild := childZones.GetChild(zoneKey)
		// every zone must have a subnet for workers, we use this subnet for the mount target
		subnetID := zoneChild.Get(IdentifierZoneSubnetWorkers)
		if subnetID == nil {
			return fmt.Errorf("subnet not found in state")
		}

		mountKey := fmt.Sprintf("%s_%s_%s", *efsID, *subnetID, *securityGroupID)
		mountInput := &efs.CreateMountTargetInput{
			FileSystemId:   efsID,
			SubnetId:       subnetID,
			SecurityGroups: []string{*securityGroupID},
		}
		mountTargetsToCreate[mountKey] = mountInput

		if slices.Contains(existingMountTargetKeys, mountKey) {
			continue
		}

		// check if mount target already exists but was not in state
		mountTargetOutput, err := c.client.DescribeMountTargetsEfs(ctx, &efs.DescribeMountTargetsInput{
			FileSystemId: efsID,
		})
		if err != nil {
			return fmt.Errorf("failed to describe mount targets for EFS %s: %w", *efsID, err)
		}
		if mountTargetOutput != nil && len(mountTargetOutput.MountTargets) > 0 {
			containsSubnet, mountTargetID := mountTargetsContainSubnet(mountTargetOutput.MountTargets, *subnetID)
			if containsSubnet {
				log.Info("found existing EFS mount target", "MountTargetId", mountTargetID, "SubnetId", *subnetID)
				childMountTargets.Set(mountKey, mountTargetID)
				continue
			}
		}

		log.Info("creating EFS mount target", "SubnetId", *mountInput.SubnetId)
		output, err := c.client.CreateMountTargetEfs(ctx, mountInput)
		if err != nil {
			return err
		}
		if output.MountTargetId == nil {
			return fmt.Errorf("got empty mount target id in response")
		}
		log.Info("created EFS mount target", "SubnetId", *mountInput.SubnetId)

		childMountTargets.Set(mountKey, *output.MountTargetId)
	}

	// delete unused mount targets
	for _, existingMountTargetKey := range existingMountTargetKeys {
		if _, ok := mountTargetsToCreate[existingMountTargetKey]; ok {
			continue
		}

		// this mount target is not in the list of mount targets to create, so we delete it
		mountTargetID := childMountTargets.Get(existingMountTargetKey)
		if mountTargetID == nil {
			return fmt.Errorf("mount target id not found in state for key %s", existingMountTargetKey)
		}
		err := c.client.DeleteMountTargetEfs(ctx, &efs.DeleteMountTargetInput{
			MountTargetId: mountTargetID,
		})
		if err != nil {
			return fmt.Errorf("failed to delete mount target id %s: %w", *mountTargetID, err)
		}
		childMountTargets.Delete(existingMountTargetKey)
	}

	return nil
}

func (c *FlowContext) getSubnetZoneChildByItem(item *awsclient.Subnet) Whiteboard {
	return c.getSubnetZoneChild(getZoneName(item))
}

func (c *FlowContext) getSubnetZoneChild(zoneName string) Whiteboard {
	return c.state.GetChild(ChildIdZones).GetChild(zoneName)
}

func (c *FlowContext) getSubnetKey(item *awsclient.Subnet) (string, string, error) {
	zone := c.getZone(item)
	// With IPv6 we don't have configuration for zone.Workers and zone.Internal.
	// In that case, we get the subnetKey comparing the name tag.
	if zone == nil || !containsIPv4(c.getIpFamilies()) {
		// zone may have been deleted from spec, need to find subnetKey on other ways
		zoneName := item.AvailabilityZone
		if item.SubnetId != "" {
			zoneChild := c.getSubnetZoneChild(zoneName)
			for _, key := range []string{IdentifierZoneSubnetWorkers, IdentifierZoneSubnetPublic, IdentifierZoneSubnetPrivate} {
				if s := zoneChild.Get(key); s != nil && *s == item.SubnetId {
					return zoneName, key, nil
				}
			}
		}
		if item.Tags != nil && item.Tags[TagKeyName] != "" {
			value := item.Tags[TagKeyName]
			helper := c.zoneSuffixHelpers(zoneName)
			for _, key := range []string{IdentifierZoneSubnetWorkers, IdentifierZoneSubnetPublic, IdentifierZoneSubnetPrivate} {
				switch key {
				case IdentifierZoneSubnetWorkers:
					if value == fmt.Sprintf("%s-%s", c.namespace, helper.GetSuffixSubnetWorkers()) {
						return zoneName, key, nil
					}
				case IdentifierZoneSubnetPublic:
					if value == fmt.Sprintf("%s-%s", c.namespace, helper.GetSuffixSubnetPublic()) {
						return zoneName, key, nil
					}
				case IdentifierZoneSubnetPrivate:
					if value == fmt.Sprintf("%s-%s", c.namespace, helper.GetSuffixSubnetPrivate()) {
						return zoneName, key, nil
					}
				}
			}
		}
		return "", "", fmt.Errorf("could not determine subnet key for subnet %s", item.SubnetId)
	}
	switch item.CidrBlock {
	case zone.Workers:
		return zone.Name, IdentifierZoneSubnetWorkers, nil
	case zone.Public:
		return zone.Name, IdentifierZoneSubnetPublic, nil
	case zone.Internal:
		return zone.Name, IdentifierZoneSubnetPrivate, nil
	}
	return "", "", fmt.Errorf("could not determine subnet key for subnet %s", item.SubnetId)
}

func (c *FlowContext) getZone(item *awsclient.Subnet) *aws.Zone {
	zoneName := getZoneName(item)
	for _, zone := range c.config.Networks.Zones {
		if zone.Name == zoneName {
			return &zone
		}
	}
	return nil
}

// isVpcMatchingState checks if the vpcID in the state matches the provided vpcID.
func (c *FlowContext) isVpcMatchingState(vpcID *string) bool {
	// panic if VPC ID is not set in state - all panics in reconcile are recovered and returned as an error
	if c.state.Get(IdentifierVPC) == nil {
		panic("VPC ID not set in state")
	}
	// we do not adopt resources that have no VPC ID specified
	if vpcID == nil {
		return false
	}
	return *c.state.Get(IdentifierVPC) == *vpcID
}

func getZoneName(item *awsclient.Subnet) string {
	return item.AvailabilityZone
}

func cidrSubnet(baseCIDR string, newPrefixLength int, index int) (string, error) {
	_, ipNet, err := net.ParseCIDR(baseCIDR)
	if err != nil {
		return "", err
	}

	baseIP := ipNet.IP
	maskSize, addrSize := ipNet.Mask.Size()

	if newPrefixLength <= maskSize || newPrefixLength > addrSize {
		return "", fmt.Errorf("invalid new prefix length")
	}

	// #nosec: G115
	offset := big.NewInt(0).Mul(big.NewInt(int64(index)), big.NewInt(0).Lsh(big.NewInt(1), uint(addrSize-newPrefixLength)))
	subnetIP := net.IP(big.NewInt(0).Add(big.NewInt(0).SetBytes(baseIP), offset).Bytes())
	return fmt.Sprintf("%s/%d", subnetIP.String(), newPrefixLength), nil
}

// calcNextIPv6CidrBlock returns the next IPv6 /64 subnet CIDR block within the same /56 VPC range.
// It increments the 8th byte of the IP address (index 7) to generate the next subnet.
// This is used to avoid subnet conflicts when creating IPv6 subnets.
// Returns an error if the maximum index (255) is reached or the input CIDR is invalid.
func calcNextIPv6CidrBlock(currentSubnetCIDR string) (string, error) {
	ip, _, err := net.ParseCIDR(currentSubnetCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse CIDR: %v", err)
	}

	currentIndex := int(ip[7])

	if currentIndex >= 255 {
		return "", fmt.Errorf("already at maximum index (255) within /56 range")
	}

	nextIndex := currentIndex + 1

	nextIP := make(net.IP, 16)
	copy(nextIP, ip)
	// #nosec G602 -- IPv6 addresses are always 16 bytes, index 7 is safe
	nextIP[7] = byte(nextIndex)

	nextCIDR := fmt.Sprintf("%s/64", nextIP.String())

	return nextCIDR, nil
}
