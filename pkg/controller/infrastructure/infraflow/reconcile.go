// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/pkg/utils/flow"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/pointer"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

const (
	defaultTimeout     = 90 * time.Second
	defaultLongTimeout = 3 * time.Minute
)

// Reconcile creates and runs the flow to reconcile the AWS infrastructure.
func (c *FlowContext) Reconcile(ctx context.Context) error {
	g := c.buildReconcileGraph()
	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{Log: c.Log}); err != nil {
		return flow.Causes(err)
	}
	return nil
}

func (c *FlowContext) buildReconcileGraph() *flow.Graph {
	createVPC := c.config.Networks.VPC.ID == nil
	g := flow.NewGraph("AWS infrastructure reconcilation")

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

	_ = c.AddTask(g, "ensure gateway endpoints",
		c.ensureGatewayEndpoints,
		Timeout(defaultTimeout), Dependencies(ensureVpc, ensureDefaultSecurityGroup, ensureInternetGateway))

	ensureMainRouteTable := c.AddTask(g, "ensure main route table",
		c.ensureMainRouteTable,
		Timeout(defaultTimeout), Dependencies(ensureVpc, ensureVpcIPv6CidrBloc, ensureDefaultSecurityGroup, ensureInternetGateway))

	ensureNodesSecurityGroup := c.AddTask(g, "ensure nodes security group",
		c.ensureNodesSecurityGroup,
		Timeout(defaultTimeout), Dependencies(ensureVpc))

	ensureZones := c.AddTask(g, "ensure zones resources",
		c.ensureZones,
		Timeout(defaultLongTimeout), Dependencies(ensureVpc, ensureNodesSecurityGroup, ensureVpcIPv6CidrBloc, ensureMainRouteTable))

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
	log := c.LogFromContext(ctx)
	desired := c.getDesiredDhcpOptions()
	current, err := findExisting(ctx, c.state.Get(IdentifierDHCPOptions), c.commonTags,
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

func (c *FlowContext) ensureManagedVpc(ctx context.Context) error {
	log := c.LogFromContext(ctx)
	log.Info("using managed VPC")
	desired := &awsclient.VPC{
		Tags:                         c.commonTags,
		EnableDnsSupport:             true,
		EnableDnsHostnames:           true,
		AssignGeneratedIPv6CidrBlock: c.config.DualStack != nil && c.config.DualStack.Enabled,
		DhcpOptionsId:                c.state.Get(IdentifierDHCPOptions),
	}
	if c.config.Networks.VPC.CIDR == nil {
		return fmt.Errorf("missing VPC CIDR")
	}
	desired.CidrBlock = *c.config.Networks.VPC.CIDR
	current, err := findExisting(ctx, c.state.Get(IdentifierVPC), c.commonTags,
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
	if c.config.DualStack != nil && c.config.DualStack.Enabled {
		current, err := findExisting(ctx, c.state.Get(IdentifierVPC), c.commonTags,
			c.client.GetVpc, c.client.FindVpcsByTags)
		if err != nil {
			return err
		}
		ipv6CidrBlock, err := c.client.WaitForIPv6Cidr(ctx, current.VpcId)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierVpcIPv6CidrBlock, ipv6CidrBlock)
	}
	return nil
}

func (c *FlowContext) ensureExistingVpc(ctx context.Context) error {
	vpcID := *c.config.Networks.VPC.ID
	log := c.LogFromContext(ctx)
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
		return fmt.Errorf("Internet Gateway not found for VPC %s", vpcID)
	}
	c.state.Set(IdentifierInternetGateway, gw.InternetGatewayId)
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
	if c.config.DualStack != nil && c.config.DualStack.Enabled && item.IPv6CidrBlock == "" {
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
	log := c.LogFromContext(ctx)
	desired := &awsclient.InternetGateway{
		Tags:  c.commonTags,
		VpcId: c.state.Get(IdentifierVPC),
	}
	current, err := findExisting(ctx, c.state.Get(IdentifierInternetGateway), c.commonTags,
		c.client.GetInternetGateway, c.client.FindInternetGatewaysByTags)
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
	log := c.LogFromContext(ctx)
	child := c.state.GetChild(ChildIdVPCEndpoints)
	var desired []*awsclient.VpcEndpoint
	for _, endpoint := range c.config.Networks.VPC.GatewayEndpoints {
		desired = append(desired, &awsclient.VpcEndpoint{
			Tags:        c.commonTagsWithSuffix(fmt.Sprintf("gw-%s", endpoint)),
			VpcId:       c.state.Get(IdentifierVPC),
			ServiceName: c.vpcEndpointServiceNamePrefix() + endpoint,
		})
	}
	current, err := c.collectExistingVPCEndpoints(ctx)
	if err != nil {
		return err
	}

	toBeDeleted, toBeCreated, toBeChecked := diffByID(desired, current, c.extractVpcEndpointName)
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
	for _, item := range toBeCreated {
		log.Info("creating...", "serviceName", item.ServiceName)
		created, err := c.client.CreateVpcEndpoint(ctx, item)
		if err != nil {
			return err
		}
		child.Set(c.extractVpcEndpointName(item), created.VpcEndpointId)
		if _, err := c.updater.UpdateEC2Tags(ctx, created.VpcEndpointId, item.Tags, created.Tags); err != nil {
			return err
		}
	}
	for _, pair := range toBeChecked {
		child.Set(c.extractVpcEndpointName(pair.current), pair.current.VpcEndpointId)
		if _, err := c.updater.UpdateEC2Tags(ctx, pair.current.VpcEndpointId, pair.desired.Tags, pair.current.Tags); err != nil {
			return err
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
	foundByTags, err := c.client.FindVpcEndpointsByTags(ctx, c.clusterTags())
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
	log := c.LogFromContext(ctx)
	allIPv4 := "0.0.0.0/0"
	allIPv6 := "::/0"
	desired := &awsclient.RouteTable{
		Tags:  c.commonTags,
		VpcId: c.state.Get(IdentifierVPC),
		Routes: []*awsclient.Route{
			{
				DestinationCidrBlock: pointer.String(allIPv4),
				GatewayId:            c.state.Get(IdentifierInternetGateway),
			},
		},
	}
	if c.state.Get(IdentifierVpcIPv6CidrBlock) != nil {
		desired.Routes = append(desired.Routes, &awsclient.Route{
			DestinationIpv6CidrBlock: pointer.String(allIPv6),
			GatewayId:                c.state.Get(IdentifierInternetGateway),
		})
	}
	current, err := findExisting(ctx, c.state.Get(IdentifierMainRouteTable), c.commonTags,
		c.client.GetRouteTable, c.client.FindRouteTablesByTags)
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierMainRouteTable, current.RouteTableId)
		c.state.SetObject(ObjectMainRouteTable, current)
		log.Info("updating route table...")
		if _, err := c.updater.UpdateRouteTable(ctx, log, desired, current, allIPv4); err != nil {
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
	log := c.LogFromContext(ctx)
	groupName := fmt.Sprintf("%s-nodes", c.namespace)
	desired := &awsclient.SecurityGroup{
		Tags:        c.commonTagsWithSuffix("nodes"),
		GroupName:   groupName,
		VpcId:       c.state.Get(IdentifierVPC),
		Description: pointer.String("Security group for nodes"),
		Rules: []*awsclient.SecurityGroupRule{
			{
				Type:     awsclient.SecurityGroupRuleTypeIngress,
				Protocol: "-1",
				Self:     true,
			},
			{
				Type:       awsclient.SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "tcp",
				CidrBlocks: []string{"0.0.0.0/0"},
			},
			{
				Type:       awsclient.SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "udp",
				CidrBlocks: []string{"0.0.0.0/0"},
			},
			{
				Type:       awsclient.SecurityGroupRuleTypeEgress,
				Protocol:   "-1",
				CidrBlocks: []string{"0.0.0.0/0"},
			},
		},
	}
	for _, zone := range c.config.Networks.Zones {
		desired.Rules = append(desired.Rules,
			&awsclient.SecurityGroupRule{
				Type:       awsclient.SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "tcp",
				CidrBlocks: []string{zone.Internal},
			},
			&awsclient.SecurityGroupRule{
				Type:       awsclient.SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "udp",
				CidrBlocks: []string{zone.Internal},
			},
			&awsclient.SecurityGroupRule{
				Type:       awsclient.SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "tcp",
				CidrBlocks: []string{zone.Public},
			},
			&awsclient.SecurityGroupRule{
				Type:       awsclient.SecurityGroupRuleTypeIngress,
				FromPort:   30000,
				ToPort:     32767,
				Protocol:   "udp",
				CidrBlocks: []string{zone.Public},
			})
	}
	current, err := findExisting(ctx, c.state.Get(IdentifierNodesSecurityGroup), c.commonTagsWithSuffix("nodes"),
		c.client.GetSecurityGroup, c.client.FindSecurityGroupsByTags,
		func(item *awsclient.SecurityGroup) bool { return item.GroupName == groupName })
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
	nats, err := c.client.FindNATGatewaysByTags(ctx, tags)
	if err != nil {
		return err
	}
	for _, nat := range nats {
		egressIPs = append(egressIPs, fmt.Sprintf("%s/32", nat.PublicIP))
	}
	c.state.Set(IdentifierEgressCIDRs, strings.Join(egressIPs, ","))
	return nil
}

func (c *FlowContext) ensureZones(ctx context.Context) error {
	var desired []*awsclient.Subnet

	for index, zone := range c.config.Networks.Zones {
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
		desired = append(desired,
			&awsclient.Subnet{
				Tags:                        tagsWorkers,
				VpcId:                       c.state.Get(IdentifierVPC),
				CidrBlock:                   zone.Workers,
				AvailabilityZone:            zone.Name,
				AssignIpv6AddressOnCreation: pointer.Bool(false),
			},
			&awsclient.Subnet{
				Tags:                        tagsPublic,
				VpcId:                       c.state.Get(IdentifierVPC),
				CidrBlock:                   zone.Public,
				AvailabilityZone:            zone.Name,
				AssignIpv6AddressOnCreation: pointer.Bool(false),
			},
			&awsclient.Subnet{
				Tags:                        tagsPrivate,
				VpcId:                       c.state.Get(IdentifierVPC),
				CidrBlock:                   zone.Internal,
				AvailabilityZone:            zone.Name,
				AssignIpv6AddressOnCreation: pointer.Bool(false),
			})

		for i := 0; i < 3; i++ {
			if len(subnetCIDRs) == 3 && subnetCIDRs[i] != "" {
				desired[i].Ipv6CidrBlocks = []string{subnetCIDRs[i]}
			} else {
				desired[i].Ipv6CidrBlocks = nil
			}
		}

	}
	// update flow state if subnet suffixes have been added
	if err := c.PersistState(ctx, true); err != nil {
		return err
	}
	current, err := c.collectExistingSubnets(ctx)
	if err != nil {
		return err
	}
	toBeDeleted, toBeCreated, toBeChecked := diffByID(desired, current, func(item *awsclient.Subnet) string {
		return item.AvailabilityZone + "-" + item.CidrBlock
	})

	g := flow.NewGraph("AWS infrastructure reconcilation: zones")

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
	for _, item := range c.config.Networks.Zones {
		zone := item
		c.addZoneReconcileTasks(g, &zone, dependencies.Get(zone.Name))
	}
	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{Log: c.Log}); err != nil {
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
	foundByTags, err := c.client.FindSubnetsByTags(ctx, c.clusterTags())
	if err != nil {
		return nil, err
	}
outer:
	for _, item := range foundByTags {
		for _, currentItem := range current {
			if item.SubnetId == currentItem.SubnetId {
				continue outer
			}
		}
		current = append(current, item)
	}
	return current, nil
}

func (c *FlowContext) addSubnetReconcileTasks(g *flow.Graph, desired, current *awsclient.Subnet) (flow.TaskIDer, error) {
	zoneName, subnetKey, err := c.getSubnetKey(desired)
	if err != nil {
		return nil, err
	}
	suffix := fmt.Sprintf("%s-%s", zoneName, subnetKey)
	return c.AddTask(g, "ensure subnet "+suffix,
		c.ensureSubnet(subnetKey, desired, current),
		Timeout(defaultTimeout)), nil
}

func (c *FlowContext) addZoneReconcileTasks(g *flow.Graph, zone *aws.Zone, dependencies []flow.TaskIDer) {
	ensureElasticIP := c.AddTask(g, "ensure NAT gateway elastic IP "+zone.Name,
		c.ensureElasticIP(zone),
		Timeout(defaultTimeout), Dependencies(dependencies...))

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
		if zoneChild.IsAlreadyDeleted(subnetKey) {
			return nil
		}
		log := c.LogFromContext(ctx)
		log.Info("deleting...", "SubnetID", item.SubnetId)
		waiter := informOnWaiting(log, 10*time.Second, "still deleting...", "SubnetID", item.SubnetId)
		err := c.client.DeleteSubnet(ctx, item.SubnetId)
		waiter.Done(err)
		if err != nil {
			return err
		}
		zoneChild.SetAsDeleted(subnetKey)
		return nil
	}
}

func (c *FlowContext) ensureSubnet(subnetKey string, desired, current *awsclient.Subnet) flow.TaskFn {
	zoneChild := c.getSubnetZoneChildByItem(desired)
	if current == nil {
		return func(ctx context.Context) error {
			log := c.LogFromContext(ctx)
			log.Info("creating...")
			created, err := c.client.CreateSubnet(ctx, desired)
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
			log := c.LogFromContext(ctx)
			log.Info("updated")
		}
		return nil
	}
}

func (c *FlowContext) ensureElasticIP(zone *aws.Zone) flow.TaskFn {
	return func(ctx context.Context) error {
		if zone.ElasticIPAllocationID != nil {
			return nil
		}
		log := c.LogFromContext(ctx)
		helper := c.zoneSuffixHelpers(zone.Name)
		child := c.getSubnetZoneChild(zone.Name)
		id := child.Get(IdentifierZoneNATGWElasticIP)
		desired := &awsclient.ElasticIP{
			Tags: c.commonTagsWithSuffix(helper.GetSuffixElasticIP()),
			Vpc:  true,
		}
		current, err := findExisting(ctx, id, desired.Tags, c.client.GetElasticIP, c.client.FindElasticIPsByTags)
		if err != nil {
			return err
		}

		if current != nil {
			child.Set(IdentifierZoneNATGWElasticIP, current.AllocationId)
			if _, err := c.updater.UpdateEC2Tags(ctx, current.AllocationId, desired.Tags, current.Tags); err != nil {
				return err
			}
		} else {
			log.Info("creating...")
			created, err := c.client.CreateElasticIP(ctx, desired)
			if err != nil {
				return err
			}
			child.Set(IdentifierZoneNATGWElasticIP, created.AllocationId)
		}

		return nil
	}
}

func (c *FlowContext) deleteElasticIP(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		child := c.getSubnetZoneChild(zoneName)
		if child.IsAlreadyDeleted(IdentifierZoneNATGWElasticIP) {
			return nil
		}
		helper := c.zoneSuffixHelpers(zoneName)
		tags := c.commonTagsWithSuffix(helper.GetSuffixElasticIP())
		current, err := findExisting(ctx, child.Get(IdentifierZoneNATGWElasticIP), tags, c.client.GetElasticIP, c.client.FindElasticIPsByTags)
		if err != nil {
			return err
		}
		if current != nil {
			log := c.LogFromContext(ctx)
			log.Info("deleting...", "AllocationId", current.AllocationId)
			waiter := informOnWaiting(log, 10*time.Second, "still deleting...", "AllocationId", current.AllocationId)
			err = c.client.DeleteElasticIP(ctx, current.AllocationId)
			waiter.Done(err)
			if err != nil {
				return err
			}
		}
		child.SetAsDeleted(IdentifierZoneNATGWElasticIP)
		return nil
	}
}

func (c *FlowContext) ensureNATGateway(zone *aws.Zone) flow.TaskFn {
	return func(ctx context.Context) error {
		log := c.LogFromContext(ctx)
		child := c.getSubnetZoneChild(zone.Name)
		helper := c.zoneSuffixHelpers(zone.Name)
		desired := &awsclient.NATGateway{
			Tags:     c.commonTagsWithSuffix(helper.GetSuffixNATGateway()),
			SubnetId: *child.Get(IdentifierZoneSubnetPublic),
		}
		if zone.ElasticIPAllocationID != nil {
			desired.EIPAllocationId = *zone.ElasticIPAllocationID
		} else {
			desired.EIPAllocationId = *child.Get(IdentifierZoneNATGWElasticIP)
		}
		current, err := findExisting(ctx, child.Get(IdentifierZoneNATGateway), desired.Tags, c.client.GetNATGateway, c.client.FindNATGatewaysByTags,
			func(item *awsclient.NATGateway) bool {
				return !strings.EqualFold(item.State, ec2.StateDeleting) && !strings.EqualFold(item.State, ec2.StateFailed)
			})
		if err != nil {
			return err
		}

		if current != nil {
			child.Set(IdentifierZoneNATGateway, current.NATGatewayId)
			if _, err := c.updater.UpdateEC2Tags(ctx, current.NATGatewayId, desired.Tags, current.Tags); err != nil {
				return err
			}
		} else {
			child.Set(IdentifierZoneNATGateway, "")
			log.Info("creating...")
			waiter := informOnWaiting(log, 10*time.Second, "still creating...")
			created, err := c.client.CreateNATGateway(ctx, desired)
			if created != nil {
				waiter.UpdateMessage("waiting until available...")
				if perr := c.PersistState(ctx, true); perr != nil {
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
		if child.IsAlreadyDeleted(IdentifierZoneNATGateway) {
			return nil
		}
		log := c.LogFromContext(ctx)
		helper := c.zoneSuffixHelpers(zoneName)
		tags := c.commonTagsWithSuffix(helper.GetSuffixNATGateway())
		current, err := findExisting(ctx, child.Get(IdentifierZoneNATGateway), tags, c.client.GetNATGateway, c.client.FindNATGatewaysByTags,
			func(item *awsclient.NATGateway) bool {
				return !strings.EqualFold(item.State, ec2.StateDeleting) && !strings.EqualFold(item.State, ec2.StateFailed)
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
		child.SetAsDeleted(IdentifierZoneNATGateway)
		return nil
	}
}

func (c *FlowContext) ensurePrivateRoutingTable(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		log := c.LogFromContext(ctx)
		child := c.getSubnetZoneChild(zoneName)
		id := child.Get(IdentifierZoneRouteTable)
		cidrBlock := "0.0.0.0/0"
		desired := &awsclient.RouteTable{
			Tags:  c.commonTagsWithSuffix(fmt.Sprintf("private-%s", zoneName)),
			VpcId: c.state.Get(IdentifierVPC),
			Routes: []*awsclient.Route{
				{
					DestinationCidrBlock: pointer.String(cidrBlock),
					NatGatewayId:         child.Get(IdentifierZoneNATGateway),
				},
			},
		}
		current, err := findExisting(ctx, id, desired.Tags, c.client.GetRouteTable, c.client.FindRouteTablesByTags)
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
			if _, err := c.updater.UpdateRouteTable(ctx, log, desired, created, cidrBlock); err != nil {
				return err
			}
		}

		return nil
	}
}

func (c *FlowContext) deletePrivateRoutingTable(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		log := c.LogFromContext(ctx)
		child := c.getSubnetZoneChild(zoneName)
		if child.IsAlreadyDeleted(IdentifierZoneRouteTable) {
			return nil
		}
		tags := c.commonTagsWithSuffix(fmt.Sprintf("private-%s", zoneName))
		current, err := findExisting(ctx, child.Get(IdentifierZoneRouteTable), tags, c.client.GetRouteTable, c.client.FindRouteTablesByTags)
		if err != nil {
			return err
		}
		if current != nil {
			log.Info("deleting...", "RouteTableId", current.RouteTableId)
			if err := c.client.DeleteRouteTable(ctx, current.RouteTableId); err != nil {
				return err
			}
		}
		child.SetAsDeleted(IdentifierZoneRouteTable)
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
	log := c.LogFromContext(ctx)
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
	log := c.LogFromContext(ctx)
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
	if child.IsAlreadyDeleted(assocKey) {
		return nil
	}
	subnetID := child.Get(subnetKey)
	if subnetID == nil {
		return fmt.Errorf("missing subnet id")
	}
	assocID := child.Get(assocKey)
	if assocID == nil {
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
			for _, assoc := range routeTable.Associations {
				if reflect.DeepEqual(subnetID, assoc.SubnetId) {
					assocID = &assoc.RouteTableAssociationId
					break
				}
			}
		}
	}
	if assocID == nil {
		child.SetAsDeleted(assocKey)
		return nil
	}
	log := c.LogFromContext(ctx)
	log.Info("deleting...", "RouteTableAssociationId", *assocID)
	if err := c.client.DeleteRouteTableAssociation(ctx, *assocID); err != nil {
		return err
	}
	child.SetAsDeleted(assocKey)
	return nil
}

func (c *FlowContext) ensureIAMRole(ctx context.Context) error {
	log := c.LogFromContext(ctx)
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
	log := c.LogFromContext(ctx)
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
    }{{ if .enableECRAccess }},
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
	log := c.LogFromContext(ctx)
	enableECRAccess := true
	if v := c.config.EnableECRAccess; v != nil {
		enableECRAccess = *v
	}
	t, err := template.New("policyDocument").Parse(iamRolePolicyTemplate)
	if err != nil {
		return fmt.Errorf("parsing policyDocument template failed: %s", err)
	}
	var buffer bytes.Buffer
	if err := t.Execute(&buffer, map[string]any{"enableECRAccess": enableECRAccess}); err != nil {
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
	log := c.LogFromContext(ctx)
	desired := &awsclient.KeyPairInfo{
		Tags:    c.commonTags,
		KeyName: fmt.Sprintf("%s-ssh-publickey", c.namespace),
	}
	current, err := c.client.GetKeyPair(ctx, desired.KeyName)
	if err != nil {
		return err
	}

	specFingerprint := fmt.Sprintf("%x", md5.Sum(c.infraSpec.SSHPublicKey))
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

func (c *FlowContext) getSubnetZoneChildByItem(item *awsclient.Subnet) Whiteboard {
	return c.getSubnetZoneChild(getZoneName(item))
}

func (c *FlowContext) getSubnetZoneChild(zoneName string) Whiteboard {
	return c.state.GetChild(ChildIdZones).GetChild(zoneName)
}

func (c *FlowContext) getSubnetKey(item *awsclient.Subnet) (zoneName, subnetKey string, err error) {
	zone := c.getZone(item)
	if zone == nil {
		// zone may have been deleted from spec, need to find subnetKey on other ways
		zoneName = item.AvailabilityZone
		if item.SubnetId != "" {
			zoneChild := c.getSubnetZoneChild(zoneName)
			for _, key := range []string{IdentifierZoneSubnetWorkers, IdentifierZoneSubnetPublic, IdentifierZoneSubnetPrivate} {
				if s := zoneChild.Get(key); s != nil && *s == item.SubnetId {
					subnetKey = key
					return
				}
			}
		}
		if item.Tags != nil && item.Tags[TagKeyName] != "" {
			value := item.Tags[TagKeyName]
			helper := c.zoneSuffixHelpers(zone.Name)
			for _, key := range []string{IdentifierZoneSubnetWorkers, IdentifierZoneSubnetPublic, IdentifierZoneSubnetPrivate} {
				switch key {
				case IdentifierZoneSubnetWorkers:
					if value == helper.GetSuffixSubnetWorkers() {
						subnetKey = key
						return
					}
				case IdentifierZoneSubnetPublic:
					if value == helper.GetSuffixSubnetPublic() {
						subnetKey = key
						return
					}
				case IdentifierZoneSubnetPrivate:
					if value == helper.GetSuffixSubnetPrivate() {
						subnetKey = key
						return
					}
				}
			}
		}
		err = fmt.Errorf("subnetKey could not calculated from subnet item")
		return
	}
	zoneName = zone.Name
	switch item.CidrBlock {
	case zone.Workers:
		subnetKey = IdentifierZoneSubnetWorkers
	case zone.Public:
		subnetKey = IdentifierZoneSubnetPublic
	case zone.Internal:
		subnetKey = IdentifierZoneSubnetPrivate
	}
	return
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

	offset := big.NewInt(0).Mul(big.NewInt(int64(index)), big.NewInt(0).Lsh(big.NewInt(1), uint(addrSize-newPrefixLength)))
	subnetIP := net.IP(big.NewInt(0).Add(big.NewInt(0).SetBytes(baseIP), offset).Bytes())
	return fmt.Sprintf("%s/%d", subnetIP.String(), newPrefixLength), nil
}
