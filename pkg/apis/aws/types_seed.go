// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SeedProviderConfig is the provider-specific configuration for AWS seeds.
// Specified in Seed.spec.provider.providerConfig.
type SeedProviderConfig struct {
	metav1.TypeMeta

	// TransitGateway configures the platform TGW for all shoots on this seed.
	// When nil or Enabled=false, no TGW operations are performed.
	TransitGateway *TransitGateway

	// GlobalCustomRoutes are routes enforced on ALL shoot zone route tables
	// on this seed. These are generic routes (TGW, VPC peering, network interface
	// targets) and do NOT require a TGW — they work independently.
	// Per-shoot customRoutes cannot conflict with global routes —
	// conflicting shoot routes are rejected at validation.
	GlobalCustomRoutes []CustomRoute
}

// TransitGateway configures optional connectivity via an AWS Transit Gateway.
type TransitGateway struct {
	// Enabled explicitly enables TGW integration. Must be true for any
	// TGW operations to occur.
	Enabled bool

	// ID of an existing Transit Gateway (referenced). If set, provider-aws uses it as-is
	// and never deletes it. If nil, provider-aws auto-creates and manages a TGW.
	ID *string

	// CreateConfig optionally tunes parameters for auto-created TGWs (ASN, default
	// association/propagation). Ignored when ID is set (referenced).
	CreateConfig *TransitGatewayCreateConfig

	// HubRouteTableID is a referenced TGW route table used by the hub (seed VPC).
	// All shoot/seed VPC attachments propagate to this table so the hub can reach them.
	// If nil, provider-aws auto-creates and manages a hub route table.
	HubRouteTableID *string

	// SpokeRouteTableID is a referenced TGW route table used by spoke VPCs
	// (seed VPCs, shoot VPCs, globalVPCs). Shoot VPC attachments associate
	// with this table, enforcing isolation — shoots can only route to CIDRs
	// propagated to this table.
	// If nil, provider-aws auto-creates and manages a spoke route table.
	SpokeRouteTableID *string

	// DeleteManagedOnDisable controls what happens to auto-created (managed) TGW resources
	// when TGW is disabled (Enabled set to false).
	// When true: auto-created TGW and route tables are deleted (aggressive cleanup).
	// When false (default): only the VPC attachment is removed; TGW and route tables are preserved (safe).
	//
	// Has NO EFFECT on referenced resources (ID, HubRouteTableID, or SpokeRouteTableID set).
	// Referenced resources are protected by two independent mechanisms:
	// 1. The "managed" marker in infrastructure state is never set for referenced resources,
	//    so deleteManagedTransitGatewayResources skips them even if DeleteManagedOnDisable is true.
	// 2. The delete path only deletes resources explicitly marked as managed ("true" in state).
	//
	// Only readable when the config block exists (enabled: false). If the entire
	// transitGateway block is removed from config, behavior defaults to preserve (safe, same as false).
	DeleteManagedOnDisable bool

	// IsolationMode controls how shoot VPCs are isolated from each other.
	// Immutable once set — to change mode, disable TGW with enabled=false +
	// deleteManagedOnDisable=true, then re-enable with the new mode.
	//
	//   "hub-spoke" (default): Two route tables (hub + spoke). Seed VPC associates
	//     with hub RT, child shoots associate with spoke RT. Shoots can only see
	//     seed, not each other. Uses: HubRouteTableID, SpokeRouteTableID.
	//
	//   "shared": Single route table. All VPCs (seed + shoots) associate and
	//     propagate to the same RT — everyone sees everyone. Uses: RouteTableID.
	//     HubRouteTableID/SpokeRouteTableID are rejected by validation.
	//
	// Empty string is treated as "hub-spoke" for backward compatibility.
	IsolationMode string

	// RouteTableID is the single TGW route table for "shared" isolation mode.
	// All VPC attachments (seed, shoots, globalVPCs) associate and propagate to this RT.
	// If nil + managed TGW, provider-aws auto-creates one RT.
	// If nil + referenced TGW (ID set), validation requires this to be set.
	// Rejected by validation in "hub-spoke" mode (use HubRouteTableID/SpokeRouteTableID instead).
	RouteTableID *string

	// GlobalVPCs are utility/shared VPCs that all shoots on this seed should
	// be able to reach via the TGW. Each entry references a pre-existing TGW
	// VPC attachment. Provider-aws manages TGW route table association/propagation
	// and adds routes to shoot VPC route tables for the specified CIDRs.
	// Lives under TransitGateway because globalVPCs require a TGW to function.
	GlobalVPCs []GlobalVPC

	// SeedVPCCredentialsRef references a Secret for cross-account seed VPC operations.
	SeedVPCCredentialsRef *GlobalVPCCredentialsRef
	// TransitGatewayCredentialsRef references a Secret containing AWS credentials for
	// the account that owns the Transit Gateway. Required when the TGW is in a different
	// AWS account than the shoot. When nil, uses the shoot's default credentials.
	TransitGatewayCredentialsRef *GlobalVPCCredentialsRef
}

// TransitGatewayCreateConfig specifies parameters for TGW auto-creation.
type TransitGatewayCreateConfig struct {
	// AmazonSideAsn is the private ASN for the AWS side of the TGW.
	// Only relevant for BGP (VPN, Direct Connect, TGW peering).
	// Default: 64512.
	// Mutable: can be changed later if no BGP attachments are active.
	AmazonSideAsn *int64

	// EnableDefaultAssociation controls whether new attachments auto-associate
	// with the default TGW route table. Recommend false for explicit control.
	EnableDefaultAssociation bool

	// EnableDefaultPropagation controls whether new attachments auto-propagate
	// to the default TGW route table. Recommend false for explicit control.
	EnableDefaultPropagation bool

	// AutoAcceptSharedAttachments enables auto-accept for cross-account
	// attachments (via RAM).
	AutoAcceptSharedAttachments bool
}

// GlobalVPC defines a shared/utility VPC that should be accessible to all
// shoots on this seed via the TGW.
//
// Two modes are supported:
//
//	Referenced (AttachmentID set): The TGW VPC attachment already exists.
//	  Provider-aws only manages association, propagation, and shoot VPC routes.
//	  The attachment is never created or deleted by the extension.
//
//	Managed (VpcID + SubnetIDs set): Provider-aws creates and manages the TGW
//	  VPC attachment. On removal from config or seed deletion, the attachment
//	  is deleted. For cross-account VPCs, provide CredentialsRef with credentials
//	  that have permission to create attachments in the VPC's account.
//
// Exactly one of AttachmentID or VpcID must be set.
type GlobalVPC struct {
	// Name is a human-readable identifier for this VPC (e.g., "harbor-registry").
	Name string

	// AttachmentID is the pre-existing TGW VPC attachment ID (referenced mode).
	// Provider-aws does NOT create or delete it.
	// Mutually exclusive with VpcID.
	AttachmentID *string

	// VpcID is the ID of the utility VPC to attach to the TGW (managed mode).
	// When set, provider-aws creates the TGW VPC attachment and manages its
	// lifecycle (create on add, delete on removal).
	// Mutually exclusive with AttachmentID. Requires SubnetIDs.
	VpcID *string

	// SubnetIDs are private subnet IDs in the utility VPC, one per AZ.
	// TGW creates an ENI in each subnet. Required when VpcID is set.
	SubnetIDs []string

	// CredentialsRef references a Secret containing AWS credentials for the
	// account that owns the utility VPC. Only needed for cross-account
	// globalVPCs where the utility VPC is in a different account than the TGW.
	// If nil, the extension uses the shoot's default credentials (same account).
	// The secret must contain 'accessKeyID' and 'secretAccessKey' keys.
	CredentialsRef *GlobalVPCCredentialsRef

	// CIDRs are the CIDR blocks reachable through this VPC.
	// If omitted, provider-aws discovers them via DescribeVpcs.
	CIDRs []string
}

// GlobalVPCCredentialsRef references AWS credentials for cross-account operations.
// Three modes are supported:
//
//  1. Secret only (Name+Namespace): static keys from a k8s Secret. Used directly.
//  2. AssumeRole only (AssumeRoleARN without Name/Namespace): the shoot's own
//     credentials call sts:AssumeRole to get temporary creds in the target account.
//  3. Secret + AssumeRole (Name+Namespace AND AssumeRoleARN): keys from the Secret
//     are used as the base credentials to call sts:AssumeRole. This supports the
//     case where an intermediary account's keys must assume a role in the target.
type GlobalVPCCredentialsRef struct {
	// Name is the secret name containing AWS credentials used as base credentials.
	// In mode 1, these are used directly. In mode 3, these are used to call sts:AssumeRole.
	Name string
	// Namespace is the secret namespace.
	Namespace string
	// AssumeRoleARN is the ARN of an IAM role to assume for cross-account access.
	// In mode 2, the shoot's own credentials call sts:AssumeRole.
	// In mode 3, the credentials from the Secret (Name/Namespace) call sts:AssumeRole.
	AssumeRoleARN *string
	// ExternalID is an optional external ID for the AssumeRole call.
	// Recommended for cross-account access to prevent confused deputy attacks.
	ExternalID *string
}

// CustomRoute defines a route to be added to all zone (private) route tables.
// Exactly one destination and one target must be specified.
type CustomRoute struct {
	// DestinationCidrBlock is the destination CIDR for this route.
	DestinationCidrBlock *string

	// DestinationPrefixListId is the ID of a managed prefix list.
	// Alternative to DestinationCidrBlock for dynamic CIDR sets.
	DestinationPrefixListId *string

	// TransitGatewayId routes traffic to a Transit Gateway.
	TransitGatewayId *string

	// VpcPeeringConnectionId routes traffic to a VPC peering connection.
	VpcPeeringConnectionId *string

	// NetworkInterfaceId routes traffic to a network interface.
	NetworkInterfaceId *string
}
