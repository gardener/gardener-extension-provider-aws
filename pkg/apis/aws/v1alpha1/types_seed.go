// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SeedProviderConfig is the provider-specific configuration for AWS seeds.
// Specified in Seed.spec.provider.providerConfig.
type SeedProviderConfig struct {
	metav1.TypeMeta `json:",inline"`

	// TransitGateway configures the platform TGW for all shoots on this seed.
	// When nil or Enabled=false, no TGW operations are performed.
	// +optional
	TransitGateway *TransitGateway `json:"transitGateway,omitempty"`

	// GlobalCustomRoutes are routes enforced on ALL shoot zone route tables
	// on this seed. These are generic routes (TGW, VPC peering, network interface
	// targets) and do NOT require a TGW — they work independently.
	// Per-shoot customRoutes cannot conflict with global routes —
	// conflicting shoot routes are rejected at validation.
	// +optional
	GlobalCustomRoutes []CustomRoute `json:"globalCustomRoutes,omitempty"`
}

// TransitGateway configures optional connectivity via an AWS Transit Gateway.
type TransitGateway struct {
	// Enabled explicitly enables TGW integration. Must be true for any
	// TGW operations to occur.
	Enabled bool `json:"enabled"`

	// ID of an existing Transit Gateway (referenced). If set, provider-aws uses it as-is
	// and never deletes it. If nil, provider-aws auto-creates and manages a TGW.
	// +optional
	ID *string `json:"id,omitempty"`

	// CreateConfig optionally tunes parameters for auto-created TGWs (ASN, default
	// association/propagation). Ignored when ID is set (referenced).
	// +optional
	CreateConfig *TransitGatewayCreateConfig `json:"createConfig,omitempty"`

	// HubRouteTableID is a referenced TGW route table used by the hub (seed VPC).
	// All shoot/seed VPC attachments propagate to this table so the hub can reach them.
	// If nil, provider-aws auto-creates and manages a hub route table.
	// +optional
	HubRouteTableID *string `json:"hubRouteTableId,omitempty"`

	// SpokeRouteTableID is a referenced TGW route table used by spoke VPCs
	// (seed VPCs, shoot VPCs, globalVPCs). Shoot VPC attachments associate
	// with this table, enforcing isolation — shoots can only route to CIDRs
	// propagated to this table.
	// If nil, provider-aws auto-creates and manages a spoke route table.
	// +optional
	SpokeRouteTableID *string `json:"spokeRouteTableId,omitempty"`

	// DeleteManagedOnDisable controls what happens to auto-created (managed) TGW resources
	// when TGW is disabled (Enabled set to false).
	// When true: auto-created TGW and route tables are deleted (aggressive cleanup).
	// When false (default): only the VPC attachment is removed; TGW and route tables are preserved (safe).
	// Has NO EFFECT on referenced resources (ID, HubRouteTableID, or SpokeRouteTableID set) —
	// referenced resources are never deleted regardless of this setting.
	// Only readable when the config block exists (enabled: false). If the entire
	// transitGateway block is removed from config, behavior defaults to preserve (safe, same as false).
	// +optional
	DeleteManagedOnDisable bool `json:"deleteManagedOnDisable,omitempty"`

	// IsolationMode controls how shoot VPCs are isolated from each other.
	// "hub-spoke" (default): two route tables, shoots isolated from each other.
	// "shared": single route table, all VPCs see each other.
	// Immutable once set. To change: disable TGW first.
	// +optional
	IsolationMode string `json:"isolationMode,omitempty"`

	// RouteTableID is the single TGW route table for "shared" isolation mode.
	// Rejected in "hub-spoke" mode.
	// +optional
	RouteTableID *string `json:"routeTableId,omitempty"`

	// GlobalVPCs are utility/shared VPCs that all shoots on this seed should
	// be able to reach via the TGW. Each entry references a pre-existing TGW
	// VPC attachment. Provider-aws manages TGW route table association/propagation
	// and adds routes to shoot VPC route tables for the specified CIDRs.
	// Lives under TransitGateway because globalVPCs require a TGW to function.
	// +optional
	GlobalVPCs []GlobalVPC `json:"globalVPCs,omitempty"`

	// SeedVPCCredentialsRef references a Secret containing AWS credentials for
	// cross-account seed VPC operations. Only needed when the seed VPC (runtime VPC
	// for this seed) is in a different AWS account than the TGW.
	// When nil, the extension uses the shoot's default credentials (same account).
	// The secret must contain 'accessKeyID' and 'secretAccessKey' keys.
	// +optional
	SeedVPCCredentialsRef *GlobalVPCCredentialsRef `json:"seedVPCCredentialsRef,omitempty"`
	// TransitGatewayCredentialsRef references a Secret containing AWS credentials for
	// the account that owns the Transit Gateway. Required when the TGW is in a different
	// AWS account than the shoot. When nil, uses the shoot's default credentials.
	// The secret must contain 'accessKeyID' and 'secretAccessKey' keys.
	// +optional
	TransitGatewayCredentialsRef *GlobalVPCCredentialsRef `json:"transitGatewayCredentialsRef,omitempty"`
}

// TransitGatewayCreateConfig specifies parameters for TGW auto-creation.
type TransitGatewayCreateConfig struct {
	// AmazonSideAsn is the private ASN for the AWS side of the TGW.
	// Only relevant for BGP (VPN, Direct Connect, TGW peering).
	// Default: 64512.
	// Mutable: can be changed later if no BGP attachments are active.
	// Valid ranges: 64512-65534 (16-bit) or 4200000000-4294967294 (32-bit).
	// +optional
	AmazonSideAsn *int64 `json:"amazonSideAsn,omitempty"`

	// EnableDefaultAssociation controls whether new attachments auto-associate
	// with the default TGW route table. Recommend false for explicit control.
	EnableDefaultAssociation bool `json:"enableDefaultAssociation"`

	// EnableDefaultPropagation controls whether new attachments auto-propagate
	// to the default TGW route table. Recommend false for explicit control.
	EnableDefaultPropagation bool `json:"enableDefaultPropagation"`

	// AutoAcceptSharedAttachments enables auto-accept for cross-account
	// attachments (via RAM).
	AutoAcceptSharedAttachments bool `json:"autoAcceptSharedAttachments"`
}

// GlobalVPC defines a shared/utility VPC that should be accessible to all
// shoots on this seed via the TGW.
//
// Two modes:
//   - Referenced (attachmentId set): attachment already exists, extension only manages
//     association/propagation/routes.
//   - Managed (vpcId + subnetIds set): extension creates and manages the TGW VPC attachment.
//
// Exactly one of attachmentId or vpcId must be set.
type GlobalVPC struct {
	// Name is a human-readable identifier for this VPC (e.g., "harbor-registry").
	Name string `json:"name"`

	// AttachmentID is the pre-existing TGW VPC attachment ID (referenced mode).
	// Provider-aws does NOT create or delete it.
	// Mutually exclusive with vpcId.
	// +optional
	AttachmentID *string `json:"attachmentId,omitempty"`

	// VpcID is the ID of the utility VPC to attach to the TGW (managed mode).
	// When set, provider-aws creates the TGW VPC attachment and manages its
	// lifecycle (create on add, delete on removal).
	// Mutually exclusive with attachmentId. Requires subnetIds.
	// +optional
	VpcID *string `json:"vpcId,omitempty"`

	// SubnetIDs are private subnet IDs in the utility VPC, one per AZ.
	// TGW creates an ENI in each subnet. Required when vpcId is set.
	// +optional
	SubnetIDs []string `json:"subnetIds,omitempty"`

	// CredentialsRef references a Secret containing AWS credentials for the
	// account that owns the utility VPC. Only needed for cross-account
	// globalVPCs where the utility VPC is in a different account than the TGW.
	// If nil, the extension uses the shoot's default credentials (same account).
	// The secret must contain 'accessKeyID' and 'secretAccessKey' keys.
	// +optional
	CredentialsRef *GlobalVPCCredentialsRef `json:"credentialsRef,omitempty"`

	// CIDRs are the CIDR blocks reachable through this VPC.
	// If omitted, provider-aws discovers them via DescribeVpcs.
	// +optional
	CIDRs []string `json:"cidrs,omitempty"`
}

// GlobalVPCCredentialsRef references AWS credentials for cross-account operations.
// Three modes are supported:
//
//  1. Secret only (name+namespace): static keys from a k8s Secret. Used directly.
//  2. AssumeRole only (assumeRoleARN without name/namespace): the shoot's own
//     credentials call sts:AssumeRole to get temporary creds in the target account.
//  3. Secret + AssumeRole (name+namespace AND assumeRoleARN): keys from the Secret
//     are used as base credentials to call sts:AssumeRole. Supports intermediary
//     account keys assuming a role in the target account.
type GlobalVPCCredentialsRef struct {
	// Name is the secret name containing AWS credentials used as base credentials.
	// In mode 1, these are used directly. In mode 3, these call sts:AssumeRole.
	// +optional
	Name string `json:"name,omitempty"`
	// Namespace is the secret namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// AssumeRoleARN is the ARN of an IAM role to assume for cross-account access.
	// In mode 2 (no name/namespace), the shoot's own credentials call sts:AssumeRole.
	// In mode 3 (with name/namespace), the Secret's credentials call sts:AssumeRole.
	// +optional
	AssumeRoleARN *string `json:"assumeRoleARN,omitempty"`
	// ExternalID is an optional external ID for the AssumeRole call.
	// Recommended for cross-account access to prevent confused deputy attacks.
	// +optional
	ExternalID *string `json:"externalID,omitempty"`
}

// CustomRoute defines a route to be added to all zone (private) route tables.
// Exactly one destination and one target must be specified.
type CustomRoute struct {
	// DestinationCidrBlock is the destination CIDR for this route.
	// +optional
	DestinationCidrBlock *string `json:"destinationCidrBlock,omitempty"`

	// DestinationPrefixListId is the ID of a managed prefix list.
	// Alternative to DestinationCidrBlock for dynamic CIDR sets.
	// +optional
	DestinationPrefixListId *string `json:"destinationPrefixListId,omitempty"`

	// TransitGatewayId routes traffic to a Transit Gateway.
	// +optional
	TransitGatewayId *string `json:"transitGatewayId,omitempty"`

	// VpcPeeringConnectionId routes traffic to a VPC peering connection.
	// +optional
	VpcPeeringConnectionId *string `json:"vpcPeeringConnectionId,omitempty"`

	// NetworkInterfaceId routes traffic to a network interface.
	// +optional
	NetworkInterfaceId *string `json:"networkInterfaceId,omitempty"`
}
