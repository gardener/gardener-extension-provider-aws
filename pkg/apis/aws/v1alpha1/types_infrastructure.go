// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// InfrastructureConfig infrastructure configuration resource
type InfrastructureConfig struct {
	metav1.TypeMeta `json:",inline"`

	// EnableECRAccess specifies whether the IAM role policy for the worker nodes shall contain
	// permissions to access the ECR.
	// default: true
	// +optional
	EnableECRAccess *bool `json:"enableECRAccess,omitempty"`

	// DualStack specifies whether dual-stack or IPv4-only should be supported.
	DualStack *DualStack `json:"dualStack,omitempty"`

	// Networks is the AWS specific network configuration (VPC, subnets, etc.)
	Networks Networks `json:"networks"`

	// IgnoreTags allows to configure which resource tags on resources managed by Gardener should be ignored during
	// infrastructure reconciliation. By default, all tags that are added outside of Gardener's / terraform's
	// reconciliation will be removed during the next reconciliation. This field allows users and automation to add
	// custom tags on resources created and managed by Gardener without loosing them on the next reconciliation.
	// See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging#ignoring-changes-in-all-resources
	// for details of the underlying terraform implementation.
	// +optional
	IgnoreTags *IgnoreTags `json:"ignoreTags,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// InfrastructureStatus contains information about created infrastructure resources.
type InfrastructureStatus struct {
	metav1.TypeMeta `json:",inline"`
	// EC2 contains information about the created AWS EC2 resources.
	EC2 EC2 `json:"ec2"`
	// IAM contains information about the created AWS IAM resources.
	IAM IAM `json:"iam"`
	// VPC contains information about the created AWS VPC and some related resources.
	VPC VPCStatus `json:"vpc"`
}

// Networks holds information about the Kubernetes and infrastructure networks.
type Networks struct {
	// VPC indicates whether to use an existing VPC or create a new one.
	VPC VPC `json:"vpc"`
	// Zones belonging to the same region
	Zones []Zone `json:"zones"`
}

// IgnoreTags holds information about ignored resource tags.
type IgnoreTags struct {
	// Keys is a list of individual tag keys, that should be ignored during infrastructure reconciliation.
	// +optional
	Keys []string `json:"keys,omitempty"`
	// KeyPrefixes is a list of tag key prefixes, that should be ignored during infrastructure reconciliation.
	// +optional
	KeyPrefixes []string `json:"keyPrefixes,omitempty"`
}

// Zone describes the properties of a zone.
type Zone struct {
	// Name is the name for this zone.
	Name string `json:"name"`
	// Internal is the private subnet range to create (used for internal load balancers).
	Internal string `json:"internal"`
	// Public is the public subnet range to create (used for bastion and load balancers).
	Public string `json:"public"`
	// Workers is the workers subnet range to create (used for the VMs).
	Workers string `json:"workers"`
	// ElasticIPAllocationID contains the allocation ID of an Elastic IP that will be attached to the NAT gateway in
	// this zone (e.g., `eipalloc-123456`). If it's not provided then a new Elastic IP will be automatically created
	// and attached.
	// Important: If this field is changed then the already attached Elastic IP will be disassociated from the NAT gateway
	// (and potentially removed if it was created by this extension). Also, the NAT gateway will be deleted. This will
	// disrupt egress traffic for a while.
	// +optional
	ElasticIPAllocationID *string `json:"elasticIPAllocationID,omitempty"`
}

// EC2 contains information about the  AWS EC2 resources.
type EC2 struct {
	// KeyName is the name of the SSH key.
	KeyName string `json:"keyName"`
}

// IAM contains information about the AWS IAM resources.
type IAM struct {
	// InstanceProfiles is a list of AWS IAM instance profiles.
	InstanceProfiles []InstanceProfile `json:"instanceProfiles"`
	// Roles is a list of AWS IAM roles.
	Roles []Role `json:"roles"`
}

// VPC contains information about the AWS VPC and some related resources.
type VPC struct {
	// ID is the VPC id.
	// +optional
	ID *string `json:"id,omitempty"`
	// CIDR is the VPC CIDR.
	// +optional
	CIDR *string `json:"cidr,omitempty"`
	// GatewayEndpoints service names to configure as gateway endpoints in the VPC.
	// +optional
	GatewayEndpoints []string `json:"gatewayEndpoints,omitempty"`
}

// VPCStatus contains information about a generated VPC or resources inside an existing VPC.
type VPCStatus struct {
	// ID is the VPC id.
	ID string `json:"id"`
	// Subnets is a list of subnets that have been created.
	Subnets []Subnet `json:"subnets"`
	// SecurityGroups is a list of security groups that have been created.
	SecurityGroups []SecurityGroup `json:"securityGroups"`
}

const (
	// PurposeNodes is a constant describing that the respective resource is used for nodes.
	PurposeNodes string = "nodes"
	// PurposePublic is a constant describing that the respective resource is used for public load balancers.
	PurposePublic string = "public"
	// PurposeInternal is a constant describing that the respective resource is used for internal load balancers.
	PurposeInternal string = "internal"
)

// InstanceProfile is an AWS IAM instance profile.
type InstanceProfile struct {
	// Purpose is a logical description of the instance profile.
	Purpose string `json:"purpose"`
	// Name is the name for this instance profile.
	Name string `json:"name"`
}

// Role is an AWS IAM role.
type Role struct {
	// Purpose is a logical description of the role.
	Purpose string `json:"purpose"`
	// ARN is the AWS Resource Name for this role.
	ARN string `json:"arn"`
}

// Subnet is an AWS subnet related to a VPC.
type Subnet struct {
	// Purpose is a logical description of the subnet.
	Purpose string `json:"purpose"`
	// ID is the subnet id.
	ID string `json:"id"`
	// Zone is the availability zone into which the subnet has been created.
	Zone string `json:"zone"`
}

// SecurityGroup is an AWS security group related to a VPC.
type SecurityGroup struct {
	// Purpose is a logical description of the security group.
	Purpose string `json:"purpose"`
	// ID is the subnet id.
	ID string `json:"id"`
}

// DualStack specifies whether dual-stack or IPv4-only should be supported.
type DualStack struct {
	// Enabled specifies if dual-stack is enabled or not.
	Enabled bool `json:"enabled"`
}
