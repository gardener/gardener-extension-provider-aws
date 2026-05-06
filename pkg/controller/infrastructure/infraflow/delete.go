// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"
	"strings"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	"k8s.io/utils/ptr"

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

	deleteEfs := c.AddTask(g, "delete efs file system",
		c.deleteEfs,
		DoIf(c.isCsiEfsEnabled()), Timeout(defaultTimeout))

	deleteIAMInstanceProfile := c.AddTask(g, "delete IAM instance profile",
		c.deleteIAMInstanceProfile,
		Timeout(defaultTimeout), Dependencies(deleteIAMRolePolicy))

	_ = c.AddTask(g, "delete IAM role",
		c.deleteIAMRole,
		Timeout(defaultTimeout), Dependencies(deleteIAMInstanceProfile, deleteIAMRolePolicy))

	deleteTransitGatewayAttachment := c.AddTask(g, "delete transit gateway VPC attachment",
		c.deleteTransitGatewayAttachment,
		DoIf(c.hasVPC() && c.state.Get(IdentifierTransitGatewayAttachment) != nil), Timeout(defaultTimeout))

	deleteShootTransitGatewayAttachment := c.AddTask(g, "delete shoot-level transit gateway VPC attachment",
		c.deleteShootTransitGatewayAttachment,
		DoIf(c.hasVPC() && c.state.Get(IdentifierShootTransitGatewayAttachment) != nil), Timeout(defaultTimeout))

	deleteManagedGlobalVPCAttachments := c.AddTask(g, "delete managed globalVPC TGW attachments",
		c.deleteManagedGlobalVPCAttachments,
		DoIf(c.hasManagedGlobalVPCAttachments()), Timeout(defaultTimeout))

	// Zones must be deleted AFTER TGW attachments — TGW attachments create ENIs in worker
	// subnets that block subnet deletion with DependencyViolation errors.
	deleteZones := c.AddTask(g, "delete zones resources",
		c.deleteZones,
		DoIf(c.hasVPC()), Timeout(defaultLongTimeout), Dependencies(deleteEfs, deleteTransitGatewayAttachment, deleteShootTransitGatewayAttachment, deleteManagedGlobalVPCAttachments))

	// Delete managed TGW + route tables after all attachments are gone.
	_ = c.AddTask(g, "delete managed transit gateway resources",
		c.deleteManagedTransitGatewayResources,
		DoIf(c.state.Get(IdentifierTransitGatewayManaged) != nil), Timeout(defaultTimeout), Dependencies(deleteTransitGatewayAttachment, deleteShootTransitGatewayAttachment, deleteManagedGlobalVPCAttachments))

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
		Dependencies(deleteInternetGateway, deleteDefaultSecurityGroup, deleteNodesSecurityGroup, destroyLoadBalancersAndSecurityGroups, deleteEgressOnlyInternetGateway, deleteTransitGatewayAttachment, deleteShootTransitGatewayAttachment))

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

func (c *FlowContext) deleteTransitGatewayAttachment(ctx context.Context) error {
	log := LogFromContext(ctx)

	// Use discovery-based cleanup: finds what exists in AWS and cleans it,
	// regardless of state accuracy. See tgw_reconcile.go.
	return c.reconcileTGWDeleteState(ctx, log)
}

// deleteShootTransitGatewayAttachment deletes the shoot-level TGW VPC attachment.
// This is the shoot's own TGW (InfrastructureConfig.Networks.TransitGateway), independent
// of the seed-level TGW.
func (c *FlowContext) deleteShootTransitGatewayAttachment(ctx context.Context) error {
	attachmentID := c.state.Get(IdentifierShootTransitGatewayAttachment)
	if attachmentID == nil {
		return nil
	}
	log := LogFromContext(ctx)

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	current, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, *attachmentID)
	if err != nil {
		return err
	}
	if current != nil {
		// For shoot-level TGW, route table IDs come from the shoot config (referenced only).
		// Fall back gracefully if config is already removed — AWS handles orphaned
		// associations/propagations automatically when attachment is deleted.
		if c.isShootTGWEnabled() {
			shootTGW := c.config.Networks.TransitGateway
			if shootTGW.SpokeRouteTableID != nil {
				log.Info("disassociating shoot TGW attachment from spoke route table", "routeTableId", *shootTGW.SpokeRouteTableID)
				if err := tgwClient.DisassociateTransitGatewayRouteTable(ctx, *shootTGW.SpokeRouteTableID, *attachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "InvalidAssociation.NotFound" {
						return fmt.Errorf("failed to disassociate shoot TGW attachment: %w", err)
					}
				}
				// Also disable spoke propagation if it was enabled.
				if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, *shootTGW.SpokeRouteTableID, *attachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
						return fmt.Errorf("failed to disable shoot TGW spoke propagation: %w", err)
					}
				}
			}
			if shootTGW.HubRouteTableID != nil {
				log.Info("disabling shoot TGW propagation from hub route table", "routeTableId", *shootTGW.HubRouteTableID)
				if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, *shootTGW.HubRouteTableID, *attachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
						return fmt.Errorf("failed to disable shoot TGW propagation: %w", err)
					}
				}
			}
		} else {
			log.Info("shoot TGW config removed — deleting attachment directly (AWS auto-cleans associations/propagations)")
		}

		if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, *attachmentID); err != nil {
			return err
		}
	}
	c.state.Delete(IdentifierShootTransitGatewayAttachment)
	return nil
}

// deleteManagedGlobalVPCAttachments deletes TGW VPC attachments that were created
// by the extension for managed globalVPCs. Referenced attachments are never deleted.
func (c *FlowContext) deleteManagedGlobalVPCAttachments(ctx context.Context) error {
	log := LogFromContext(ctx)

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	for _, name := range c.listGlobalVPCAttachmentNames() {
		if !c.getGlobalVPCAttachmentManaged(name) {
			continue
		}
		attachmentID := c.getGlobalVPCAttachmentID(name)
		if attachmentID == nil {
			continue
		}

		existing, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, *attachmentID)
		if err != nil {
			return fmt.Errorf("failed to get managed globalVPC %q attachment %s: %w", name, *attachmentID, err)
		}
		if existing != nil {
			if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, *attachmentID); err != nil {
				return err
			}
		}
		c.deleteGlobalVPCAttachmentState(name)
	}
	return nil
}

// deleteManagedTransitGatewayResources deletes auto-created TGW route tables and TGW
// during infrastructure deletion. Only deletes resources marked as managed in state.
// Checks for remaining attachments before deleting the TGW (safety guard).
func (c *FlowContext) deleteManagedTransitGatewayResources(ctx context.Context) error {
	log := LogFromContext(ctx)
	tgwID := c.state.Get(IdentifierTransitGatewayID)
	if tgwID == nil {
		c.cleanupTGWState()
		return nil
	}

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	// Check deleteManagedOnDisable — if not set, skip TGW/RT deletion (preserve is safe default).
	if !c.shouldDeleteManagedOnDisable() {
		log.Info("deleteManagedOnDisable is false — keeping managed TGW and route tables", "tgwId", *tgwID)
		c.cleanupTGWState()
		return nil
	}

	// Check for remaining attachments on this TGW.
	remaining, err := tgwClient.ListTransitGatewayVPCAttachments(ctx, *tgwID)
	if err != nil {
		return fmt.Errorf("failed to list TGW attachments: %w", err)
	}
	if len(remaining) > 0 {
		log.Info("WARNING: TGW still has active VPC attachments — skipping deletion",
			"tgwId", *tgwID, "remainingAttachments", len(remaining))
		c.cleanupTGWState()
		return nil
	}

	// Delete managed route tables.
	spokeRT := c.state.Get(IdentifierTransitGatewaySpokeRouteTable)
	hubRT := c.state.Get(IdentifierTransitGatewayHubRouteTable)
	spokeManaged := c.state.Get(IdentifierTransitGatewaySpokeRouteTableManaged)
	hubManaged := c.state.Get(IdentifierTransitGatewayHubRouteTableManaged)

	if spokeRT != nil && spokeManaged != nil && *spokeManaged == "true" {
		log.Info("deleting managed spoke route table", "routeTableId", *spokeRT)
		if err := tgwClient.DeleteTransitGatewayRouteTable(ctx, *spokeRT); err != nil {
			return fmt.Errorf("failed to delete spoke route table: %w", err)
		}
	}
	if hubRT != nil && hubManaged != nil && *hubManaged == "true" {
		log.Info("deleting managed hub route table", "routeTableId", *hubRT)
		if err := tgwClient.DeleteTransitGatewayRouteTable(ctx, *hubRT); err != nil {
			return fmt.Errorf("failed to delete hub route table: %w", err)
		}
	}

	log.Info("deleting managed transit gateway", "tgwId", *tgwID)
	if err := tgwClient.DeleteTransitGateway(ctx, *tgwID); err != nil {
		return fmt.Errorf("failed to delete transit gateway: %w", err)
	}

	c.cleanupTGWState()
	log.Info("managed TGW cleanup complete")
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
		c.client.GetInternetGateway, c.client.FindInternetGatewaysByTags,
		func(item *awsclient.InternetGateway) bool {
			return c.isVpcMatchingState(item.VpcId)
		})
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
		c.client.GetEgressOnlyInternetGateway, c.client.FindEgressOnlyInternetGatewaysByTags,
		func(item *awsclient.EgressOnlyInternetGateway) bool {
			return c.isVpcMatchingState(item.VpcId)
		})
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
		c.client.GetRouteTable, c.client.FindRouteTablesByTags,
		func(item *awsclient.RouteTable) bool {
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
		func(item *awsclient.SecurityGroup) bool {
			return item.GroupName == groupName && c.isVpcMatchingState(item.VpcId)
		})
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

func (c *FlowContext) deleteEfs(ctx context.Context) error {
	log := LogFromContext(ctx)

	managedEfs, err := FindExisting(ctx, c.state.Get(IdentifierManagedEfsID), c.commonTags.AddManagedTag(),
		c.client.GetFileSystem, c.client.FindFileSystemsByTags)
	if err != nil {
		return fmt.Errorf("failed to find managed EFS file system: %w", err)
	}

	// delete mount targets that were created by this shoot
	var efsIDs []string
	if c.config.ElasticFileSystem.ID != nil {
		efsIDs = append(efsIDs, *c.config.ElasticFileSystem.ID)
	}
	if managedEfs != nil {
		efsIDs = append(efsIDs, managedEfs.FileSystemId)
	}
	for _, efsID := range efsIDs {
		if err := c.deleteEfsMountTargets(ctx, efsID); err != nil {
			return fmt.Errorf("failed to delete EFS mount targets: %w", err)
		}
	}
	// delete mounts from state
	for _, mountKeys := range c.state.GetChild(ChildEfsMountTargets).Keys() {
		c.state.Delete(mountKeys)
	}
	c.state.Delete(ChildEfsMountTargets)

	// delete the EFS file system only if it was created by Gardener.
	if managedEfs != nil {
		log.Info("deleting...", "efsFileSystem", managedEfs.FileSystemId)
		err := c.client.DeleteFileSystem(ctx, managedEfs.FileSystemId)
		if err != nil {
			return err
		}
		c.state.Delete(IdentifierManagedEfsID)
	}

	return nil
}

func (c *FlowContext) deleteEfsMountTargets(ctx context.Context, efsID string) error {
	log := LogFromContext(ctx)

	output, err := c.client.GetMountTargetsEfs(ctx, efsID)
	if err != nil {
		return fmt.Errorf("failed to describe mount targets for EFS %s: %w", efsID, err)
	}
	if output == nil || len(output.MountTargets) == 0 {
		log.Info("no mount targets found for EFS", "efsFileSystem", efsID)
		return nil
	}

	// delete mount targets that were created by this shoot
	for _, mountTarget := range output.MountTargets {
		mountTargetID := *mountTarget.MountTargetId
		if mountTarget.SubnetId == nil {
			continue
		}
		subnets, err := c.client.GetSubnets(ctx, []string{*mountTarget.SubnetId})
		if err != nil {
			return fmt.Errorf("failed to describe subnets for deleting EFS mounts %s: %w", efsID, err)
		}
		if len(subnets) != 1 {
			return fmt.Errorf("expected exactly one subnet for mount target %s, got %d", mountTargetID, len(subnets))
		}
		// check if mount target was created by this shoot
		if subnets[0].Tags == nil || subnets[0].Tags[c.tagKeyCluster()] != TagValueCluster {
			continue
		}
		log.Info("deleting...", "mountTargetId", mountTargetID)
		err = c.client.DeleteMountTargetEfs(ctx, mountTargetID)
		if err != nil {
			return fmt.Errorf("failed to delete mount target id %s: %w", mountTargetID, err)
		}
		log.Info("deleted", "mountTargetId", mountTargetID)
	}

	return nil
}

// cleanupChildShootRoutesFromRuntimeAndGlobalVPCs removes the child shoot's CIDR route
// from the runtime VPC and globalVPC route tables. These routes were added during reconcile
// (ensureRuntimeVPCAttachment Step 5b and ensureSeedVPCAttachment Step 6c) for return traffic.
func (c *FlowContext) cleanupChildShootRoutesFromRuntimeAndGlobalVPCs(ctx context.Context, log logr.Logger, shootCIDR string) {
	// Clean up runtime VPC routes (reverse of Steps 5b and 5c).
	runtimeVPCID := c.state.Get(IdentifierRuntimeVPCID)
	if runtimeVPCID != nil {
		runtimeClient, clientErr := c.getSeedVPCClient(ctx)
		if clientErr != nil {
			log.Info("warning: failed to get seed VPC client for runtime VPC route cleanup", "error", clientErr)
		} else {
			// 5b reverse: remove shoot CIDR route from runtime VPC.
			log.Info("cleaning up child shoot route from runtime VPC", "runtimeVpcId", *runtimeVPCID, "shootCIDR", shootCIDR)
			c.deleteRouteFromVPC(ctx, log, runtimeClient, *runtimeVPCID, shootCIDR, "runtime VPC")

			// 5c reverse: remove globalVPC CIDR routes from runtime VPC.
			// These are shared routes (all shoots add the same globalVPC CIDRs), so only
			// remove them if this is the LAST child shoot being deleted. Since we can't
			// easily determine that here, we skip per-shoot cleanup of globalVPC routes —
			// they are harmless stale routes (point to TGW that may be deleted, becoming
			// blackholes that AWS ignores). The managed TGW full cleanup handles this.
		}
	}

	// Clean up globalVPC routes (reverse of Step 6c).
	if c.seedConfig != nil && c.seedConfig.TransitGateway != nil {
		tgwClient, tgwErr := c.getTGWClient(ctx)
		if tgwErr != nil {
			log.Info("warning: failed to get TGW client for globalVPC route cleanup", "error", tgwErr)
			return
		}

		for i := range c.seedConfig.TransitGateway.GlobalVPCs {
			gvpc := &c.seedConfig.TransitGateway.GlobalVPCs[i]
			var gvpcVpcID string
			if gvpc.VpcID != nil && *gvpc.VpcID != "" {
				gvpcVpcID = *gvpc.VpcID
			} else if gvpc.AttachmentID != nil && *gvpc.AttachmentID != "" {
				att, attErr := tgwClient.GetTransitGatewayVPCAttachment(ctx, *gvpc.AttachmentID)
				if attErr != nil || att == nil {
					continue
				}
				gvpcVpcID = att.VpcId
			}
			if gvpcVpcID == "" {
				continue
			}

			gvpcClient, clientErr := c.getGlobalVPCClient(ctx, gvpc)
			if clientErr != nil {
				log.Info("warning: failed to get globalVPC client for route cleanup", "name", gvpc.Name, "error", clientErr)
				continue
			}
			log.Info("cleaning up child shoot route from globalVPC", "globalVPC", gvpc.Name, "vpcId", gvpcVpcID, "shootCIDR", shootCIDR)
			c.deleteRouteFromVPC(ctx, log, gvpcClient, gvpcVpcID, shootCIDR, fmt.Sprintf("globalVPC %s", gvpc.Name))
		}
	}
}

// deleteRouteFromVPC removes a specific CIDR route from all private route tables of a VPC.
func (c *FlowContext) deleteRouteFromVPC(ctx context.Context, log logr.Logger, awsClient awsclient.Interface, vpcID, cidr, description string) {
	rts, err := awsClient.FindRouteTablesByFilters(ctx, []ec2types.Filter{
		{Name: ptr.To("vpc-id"), Values: []string{vpcID}},
	})
	if err != nil {
		log.Error(err, "failed to find route tables for route cleanup", "vpcId", vpcID)
		return
	}
	for _, rt := range rts {
		if !strings.Contains(rt.Tags["Name"], "private") {
			continue
		}
		for _, r := range rt.Routes {
			if r.DestinationCidrBlock != nil && *r.DestinationCidrBlock == cidr && r.TransitGatewayId != nil {
				log.Info("removing child shoot route from "+description, "routeTableId", rt.RouteTableId, "cidr", cidr)
				if err := awsClient.DeleteRoute(ctx, rt.RouteTableId, &awsclient.Route{
					DestinationCidrBlock: r.DestinationCidrBlock,
				}); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "InvalidRoute.NotFound" {
						log.Error(err, "failed to delete route — continuing", "routeTableId", rt.RouteTableId)
					}
				}
				break
			}
		}
	}
}
