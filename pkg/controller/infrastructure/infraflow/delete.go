// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/utils/flow"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

// Delete creates and runs the flow to delete the AWS infrastructure.
func (c *FlowContext) Delete(ctx context.Context) error {
	if c.state.IsEmpty() {
		// nothing to do, e.g. if cluster was created with wrong credentials
		return nil
	}
	c.BasicFlowContext = NewBasicFlowContext(c.log, c.state, c.persistState)
	g := c.buildDeleteGraph()
	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{Log: c.log}); err != nil {
		return flow.Causes(err)
	}
	return nil
}

func (c *FlowContext) buildDeleteGraph() *flow.Graph {
	g := flow.NewGraph("AWS infrastructure destruction")

	deleteVPC := c.config.Networks.VPC.ID == nil

	destroyLoadBalancersAndSecurityGroups := c.AddTask(g, "Destroying Kubernetes load balancers and security groups",
		c.deleteKubernetesLoadBalancersAndSecurityGroups,
		DoIf(c.hasVPC() && c.state.Get(MarkerLoadBalancersAndSecurityGroupsDestroyed) == nil), Timeout(5*time.Minute))

	_ = c.AddTask(g, "delete key pair",
		c.deleteKeyPair,
		Timeout(defaultTimeout))

	deleteIAMRolePolicy := c.AddTask(g, "delete IAM role policy",
		c.deleteIAMRolePolicy,
		Timeout(defaultTimeout))

	deleteIAMInstanceProfile := c.AddTask(g, "delete IAM instance profile",
		c.deleteIAMInstanceProfile,
		Timeout(defaultTimeout), Dependencies(deleteIAMRolePolicy))

	_ = c.AddTask(g, "delete IAM role",
		c.deleteIAMRole,
		Timeout(defaultTimeout), Dependencies(deleteIAMInstanceProfile, deleteIAMRolePolicy))

	deleteZones := c.AddTask(g, "delete zones resources",
		c.deleteZones,
		DoIf(c.hasVPC()), Timeout(defaultLongTimeout))

	deleteNodesSecurityGroup := c.AddTask(g, "delete nodes security group",
		c.deleteNodesSecurityGroup,
		DoIf(c.hasVPC()), Timeout(defaultTimeout), Dependencies(deleteZones))

	deleteMainRouteTable := c.AddTask(g, "delete main route table",
		c.deleteMainRouteTable,
		DoIf(c.hasVPC()), Timeout(defaultTimeout), Dependencies(deleteZones))

	deleteGatewayEndpoints := c.AddTask(g, "delete gateway endpoints",
		c.deleteGatewayEndpoints,
		DoIf(c.hasVPC()), Timeout(defaultTimeout))

	deleteInternetGateway := c.AddTask(g, "delete internet gateway",
		c.deleteInternetGateway,
		DoIf(deleteVPC && c.hasVPC()), Timeout(defaultTimeout), Dependencies(deleteGatewayEndpoints, deleteMainRouteTable))

	deleteEgressOnlyInternetGateway := c.AddTask(g, "delete egress only internet gateway",
		c.deleteEgressOnlyInternetGateway,
		DoIf(deleteVPC && c.hasVPC()), Timeout(defaultTimeout), Dependencies(deleteZones))

	deleteDefaultSecurityGroup := c.AddTask(g, "delete default security group",
		c.deleteDefaultSecurityGroup,
		DoIf(deleteVPC && c.hasVPC()), Timeout(defaultTimeout), Dependencies(deleteGatewayEndpoints))

	deleteVpc := c.AddTask(g, "delete VPC",
		c.deleteVpc,
		DoIf(deleteVPC && c.hasVPC()), Timeout(defaultTimeout),
		Dependencies(deleteInternetGateway, deleteDefaultSecurityGroup, deleteNodesSecurityGroup, destroyLoadBalancersAndSecurityGroups, deleteEgressOnlyInternetGateway))

	_ = c.AddTask(g, "delete DHCP options for VPC",
		c.deleteDhcpOptions,
		DoIf(deleteVPC && c.state.Get(IdentifierDHCPOptions) != nil), Timeout(defaultTimeout),
		Dependencies(deleteVpc))

	return g
}

func (c *FlowContext) deleteKubernetesLoadBalancersAndSecurityGroups(ctx context.Context) error {
	if err := DestroyKubernetesLoadBalancersAndSecurityGroups(ctx, c.client, *c.state.Get(IdentifierVPC), c.namespace); err != nil {
		return util.DetermineError(fmt.Errorf("failed to destroy load balancers and security groups: %w", err), helper.KnownCodes)
	}

	c.state.Set(MarkerLoadBalancersAndSecurityGroupsDestroyed, "true")

	return nil
}

// DestroyKubernetesLoadBalancersAndSecurityGroups tries to delete orphaned load balancers and security groups.
func DestroyKubernetesLoadBalancersAndSecurityGroups(ctx context.Context, awsClient awsclient.Interface, vpcID, clusterName string) error {
	for _, v := range []struct {
		listFn   func(context.Context, string, string) ([]string, error)
		deleteFn func(context.Context, string) error
	}{
		{awsClient.ListKubernetesELBs, awsClient.DeleteELB},
		{awsClient.ListKubernetesELBsV2, awsClient.DeleteELBV2},
		{awsClient.ListKubernetesSecurityGroups, awsClient.DeleteSecurityGroup},
	} {
		results, err := v.listFn(ctx, vpcID, clusterName)
		if err != nil {
			return err
		}

		for _, result := range results {
			if err := v.deleteFn(ctx, result); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *FlowContext) deleteDefaultSecurityGroup(_ context.Context) error {
	// nothing to do, it is deleted automatically together with VPC
	c.state.Delete(IdentifierDefaultSecurityGroup)
	return nil
}

func (c *FlowContext) deleteInternetGateway(ctx context.Context) error {
	if c.state.Get(IdentifierInternetGateway) == nil {
		return nil
	}
	log := LogFromContext(ctx)
	current, err := FindExisting(ctx, c.state.Get(IdentifierInternetGateway), c.commonTags,
		c.client.GetInternetGateway, c.client.FindInternetGatewaysByTags)
	if err != nil {
		return err
	}
	if current != nil {
		log.Info("detaching...", "InternetGatewayId", current.InternetGatewayId)
		if err := c.client.DetachInternetGateway(ctx, *c.state.Get(IdentifierVPC), current.InternetGatewayId); awsclient.IgnoreAlreadyDetached(err) != nil {
			return err
		}
		log.Info("deleting...", "InternetGatewayId", current.InternetGatewayId)
		if err := c.client.DeleteInternetGateway(ctx, current.InternetGatewayId); err != nil {
			return err
		}
		c.state.Delete(IdentifierInternetGateway)
	}
	return nil
}

func (c *FlowContext) deleteEgressOnlyInternetGateway(ctx context.Context) error {
	if c.state.Get(IdentifierEgressOnlyInternetGateway) == nil {
		return nil
	}
	log := LogFromContext(ctx)
	current, err := FindExisting(ctx, c.state.Get(IdentifierEgressOnlyInternetGateway), c.commonTags,
		c.client.GetEgressOnlyInternetGateway, c.client.FindEgressOnlyInternetGatewaysByTags)
	if err != nil {
		return err
	}
	if current != nil {
		log.Info("deleting...", "EgressOnlyInternetGatewayId", current.EgressOnlyInternetGatewayId)
		if err := c.client.DeleteEgressOnlyInternetGateway(ctx, current.EgressOnlyInternetGatewayId); err != nil {
			return err
		}
		c.state.Delete(IdentifierEgressOnlyInternetGateway)
	}
	return nil
}

func (c *FlowContext) deleteGatewayEndpoints(ctx context.Context) error {
	log := LogFromContext(ctx)
	child := c.state.GetChild(ChildIdVPCEndpoints)
	current, err := c.collectExistingVPCEndpoints(ctx)
	if err != nil {
		return err
	}

	for _, item := range current {
		log.Info("deleting...", "ServiceName", item.ServiceName)
		if err := c.client.DeleteVpcEndpoint(ctx, item.VpcEndpointId); err != nil {
			return err
		}
		name := c.extractVpcEndpointName(item)
		child.Delete(name)
	}
	// update state of endpoints in state, but not found
	for _, key := range child.Keys() {
		child.Delete(key)
	}
	return nil
}

func (c *FlowContext) deleteVpc(ctx context.Context) error {
	if c.state.Get(IdentifierVPC) == nil {
		return nil
	}
	log := LogFromContext(ctx)
	current, err := FindExisting(ctx, c.state.Get(IdentifierVPC), c.commonTags,
		c.client.GetVpc, c.client.FindVpcsByTags)
	if err != nil {
		return err
	}
	if current != nil {
		log.Info("deleting...", "VpcId", current.VpcId)
		if err := c.client.DeleteVpc(ctx, current.VpcId); err != nil {
			return err
		}
	}
	c.state.Delete(IdentifierVPC)
	return nil
}

func (c *FlowContext) deleteDhcpOptions(ctx context.Context) error {
	if c.state.Get(IdentifierDHCPOptions) == nil {
		return nil
	}
	log := LogFromContext(ctx)
	current, err := FindExisting(ctx, c.state.Get(IdentifierDHCPOptions), c.commonTags,
		c.client.GetVpcDhcpOptions, c.client.FindVpcDhcpOptionsByTags)
	if err != nil {
		return err
	}
	if current != nil {
		log.Info("deleting...", "DhcpOptionsId", current.DhcpOptionsId)
		if err := c.client.DeleteVpcDhcpOptions(ctx, current.DhcpOptionsId); err != nil {
			return err
		}
		c.state.Delete(IdentifierDHCPOptions)
	}
	return nil
}

func (c *FlowContext) deleteMainRouteTable(ctx context.Context) error {
	if c.state.Get(IdentifierMainRouteTable) == nil {
		return nil
	}

	log := LogFromContext(ctx)
	current, err := FindExisting(ctx, c.state.Get(IdentifierMainRouteTable), c.commonTags,
		c.client.GetRouteTable, c.client.FindRouteTablesByTags)
	if err != nil {
		return err
	}
	if current != nil {
		log.Info("deleting...", "RouteTableId", current.RouteTableId)
		if err := c.client.DeleteRouteTable(ctx, current.RouteTableId); err != nil {
			return err
		}
	}
	c.state.Delete(IdentifierMainRouteTable)
	return nil
}

func (c *FlowContext) deleteNodesSecurityGroup(ctx context.Context) error {
	if c.state.Get(IdentifierNodesSecurityGroup) == nil {
		return nil
	}
	log := LogFromContext(ctx)
	groupName := fmt.Sprintf("%s-nodes", c.namespace)
	current, err := FindExisting(ctx, c.state.Get(IdentifierNodesSecurityGroup), c.commonTagsWithSuffix("nodes"),
		c.client.GetSecurityGroup, c.client.FindSecurityGroupsByTags,
		func(item *awsclient.SecurityGroup) bool { return item.GroupName == groupName })
	if err != nil {
		return err
	}
	if current != nil {
		log.Info("deleting...", "GroupId", current.GroupId)
		if err := c.client.DeleteSecurityGroup(ctx, current.GroupId); err != nil {
			return err
		}
	}
	c.state.Delete(IdentifierNodesSecurityGroup)
	return nil
}

func (c *FlowContext) deleteZones(ctx context.Context) error {
	current, err := c.collectExistingSubnets(ctx)
	if err != nil {
		return err
	}
	g := flow.NewGraph("AWS infrastructure destruction: zones")
	if err := c.addZoneDeletionTasksBySubnets(g, current); err != nil {
		return err
	}
	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{Log: c.log}); err != nil {
		return flow.Causes(err)
	}
	return nil
}

func (c *FlowContext) deleteIAMRole(ctx context.Context) error {
	if c.state.Get(NameIAMRole) == nil {
		return nil
	}

	log := LogFromContext(ctx)
	roleName := fmt.Sprintf("%s-nodes", c.namespace)
	log.Info("deleting...", "RoleName", roleName)
	if err := c.client.DeleteIAMRole(ctx, roleName); err != nil {
		return err
	}
	c.state.Delete(NameIAMRole)
	return nil
}

func (c *FlowContext) deleteIAMInstanceProfile(ctx context.Context) error {
	if c.state.Get(NameIAMInstanceProfile) == nil {
		return nil
	}
	log := LogFromContext(ctx)
	instanceProfileName := fmt.Sprintf("%s-nodes", c.namespace)
	log.Info("deleting...", "InstanceProfileName", instanceProfileName)
	if err := c.client.DeleteIAMInstanceProfile(ctx, instanceProfileName); err != nil {
		return err
	}
	c.state.Delete(NameIAMInstanceProfile)
	return nil
}

func (c *FlowContext) deleteIAMRolePolicy(ctx context.Context) error {
	if c.state.Get(NameIAMRolePolicy) == nil {
		return nil
	}
	log := LogFromContext(ctx)
	policyName := fmt.Sprintf("%s-nodes", c.namespace)
	roleName := fmt.Sprintf("%s-nodes", c.namespace)
	log.Info("removing from profile...")
	if err := c.client.RemoveRoleFromIAMInstanceProfile(ctx, policyName, roleName); err != nil {
		return err
	}
	log.Info("deleting...", "PolicyName", policyName, "RoleName", roleName)
	if err := c.client.DeleteIAMRolePolicy(ctx, policyName, roleName); err != nil {
		return err
	}
	c.state.Delete(NameIAMRolePolicy)
	return nil
}

func (c *FlowContext) deleteKeyPair(ctx context.Context) error {
	if c.state.Get(NameKeyPair) == nil {
		return nil
	}
	log := LogFromContext(ctx)
	keyName := fmt.Sprintf("%s-ssh-publickey", c.namespace)
	log.Info("deleting...", "KeyName", keyName)
	if err := c.client.DeleteKeyPair(ctx, keyName); err != nil {
		return err
	}
	c.state.Delete(NameKeyPair)
	return nil
}
