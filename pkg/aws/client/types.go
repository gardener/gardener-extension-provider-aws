// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// IPStack is an enumeration of IP stacks
type IPStack string

const (
	// IPStackIPv4 is the default IPv4 stack
	IPStackIPv4 IPStack = "ipv4"
	// IPStackIPDualStack is the IPv4/IPv6 dual-stack
	IPStackIPDualStack IPStack = "dual-stack"
	// IPStackIPv6 is the IPv6 stack
	IPStackIPv6 IPStack = "ipv6"

	// S3ObjectDeletionLifecyclePolicy is the name of the lifecycle policy that is added to bucket which expires current objects after their immutability period.
	S3ObjectDeletionLifecyclePolicy = "GC-forTaggedObjects"
	// S3DeleteMarkerDeletionLifecyclePolicy is the name of the lifecycle policy that is added to bucket which deletes delete-markers(if present).
	S3DeleteMarkerDeletionLifecyclePolicy = "GC-delete-markers-objects"
	// S3ObjectMarkedForDeletionTagKey is the tag "key" to be added on objects to be garbage-collected by provider's lifecycle policy.
	S3ObjectMarkedForDeletionTagKey = "gc-marked-for-deletion"

	// NoSuchBucket is the S3 api error code constant indicating that bucket doesn't exist.
	NoSuchBucket = "NoSuchBucket"
	// PermanentRedirect is the S3 api error code constant indicating that bucket exist in different region.
	PermanentRedirect = "PermanentRedirect"
	// BucketNotEmpty is the S3 api error code constant indicating that bucket isn't empty.
	BucketNotEmpty = "BucketNotEmpty"
)

// Interface is an interface which must be implemented by AWS clients.
type Interface interface {
	GetAccountID(ctx context.Context) (string, error)
	GetVPCInternetGateway(ctx context.Context, vpcID string) (string, error)
	GetVPCAttribute(ctx context.Context, vpcID string, attribute ec2types.VpcAttributeName) (bool, error)
	GetDHCPOptions(ctx context.Context, vpcID string) (map[string]string, error)
	GetElasticIPsAssociationIDForAllocationIDs(ctx context.Context, allocationIDs []string) (map[string]*string, error)
	GetNATGatewayAddressAllocations(ctx context.Context, shootNamespace string) (sets.Set[string], error)

	// S3 wrappers
	CreateBucket(ctx context.Context, bucket, region string, objectLockEnabled bool) error
	GetBucketVersioningStatus(ctx context.Context, bucket string) (*s3.GetBucketVersioningOutput, error)
	EnableBucketVersioning(ctx context.Context, bucket string) error
	GetObjectLockConfiguration(ctx context.Context, bucket string) (*s3.GetObjectLockConfigurationOutput, error)
	UpdateObjectLockConfiguration(ctx context.Context, bucket string, mode apisaws.ModeType, days int32) error
	RemoveObjectLockConfiguration(ctx context.Context, bucket string) error
	DeleteObjectsWithPrefix(ctx context.Context, bucket, prefix string) error
	DeleteBucketIfExists(ctx context.Context, bucket string) error

	// Route53 wrappers
	GetDNSHostedZones(ctx context.Context) (map[string]string, error)
	CreateOrUpdateDNSRecordSet(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64, stack IPStack) error
	DeleteDNSRecordSet(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64, stack IPStack) error

	// The following functions are only temporary needed due to https://github.com/gardener/gardener/issues/129.
	ListKubernetesELBs(ctx context.Context, vpcID, clusterName string) ([]string, error)
	ListKubernetesELBsV2(ctx context.Context, vpcID, clusterName string) ([]string, error)
	ListKubernetesSecurityGroups(ctx context.Context, vpcID, clusterName string) ([]string, error)
	DeleteELB(ctx context.Context, name string) error
	DeleteELBV2(ctx context.Context, arn string) error

	// VPCs
	CreateVpcDhcpOptions(ctx context.Context, options *DhcpOptions) (*DhcpOptions, error)
	GetVpcDhcpOptions(ctx context.Context, id string) (*DhcpOptions, error)
	FindVpcDhcpOptionsByTags(ctx context.Context, tags Tags) ([]*DhcpOptions, error)
	DeleteVpcDhcpOptions(ctx context.Context, id string) error
	CreateVpc(ctx context.Context, vpc *VPC) (*VPC, error)
	GetIPv6Cidr(ctx context.Context, vpcID string) (string, error)
	WaitForIPv6Cidr(ctx context.Context, vpcID string) (string, error)
	AddVpcDhcpOptionAssociation(vpcId string, dhcpOptionsId *string) error
	UpdateVpcAttribute(ctx context.Context, vpcId, attributeName string, value bool) error
	UpdateAmazonProvidedIPv6CidrBlock(ctx context.Context, desired *VPC, current *VPC) (bool, error)
	DeleteVpc(ctx context.Context, id string) error
	GetVpc(ctx context.Context, id string) (*VPC, error)
	FindVpcsByTags(ctx context.Context, tags Tags) ([]*VPC, error)

	// Security groups
	CreateSecurityGroup(ctx context.Context, sg *SecurityGroup) (*SecurityGroup, error)
	GetSecurityGroup(ctx context.Context, id string) (*SecurityGroup, error)
	FindSecurityGroupsByTags(ctx context.Context, tags Tags) ([]*SecurityGroup, error)
	FindDefaultSecurityGroupByVpcId(ctx context.Context, vpcId string) (*SecurityGroup, error)
	AuthorizeSecurityGroupRules(ctx context.Context, id string, rules []*SecurityGroupRule) error
	RevokeSecurityGroupRules(ctx context.Context, id string, rules []*SecurityGroupRule) error
	DeleteSecurityGroup(ctx context.Context, id string) error

	// Internet gateways
	CreateInternetGateway(ctx context.Context, gateway *InternetGateway) (*InternetGateway, error)
	GetInternetGateway(ctx context.Context, id string) (*InternetGateway, error)
	FindInternetGatewaysByTags(ctx context.Context, tags Tags) ([]*InternetGateway, error)
	FindInternetGatewayByVPC(ctx context.Context, vpcId string) (*InternetGateway, error)
	DeleteInternetGateway(ctx context.Context, id string) error
	AttachInternetGateway(ctx context.Context, vpcId, internetGatewayId string) error
	DetachInternetGateway(ctx context.Context, vpcId, internetGatewayId string) error

	// VPC Endpoints
	CreateVpcEndpoint(ctx context.Context, endpoint *VpcEndpoint) (*VpcEndpoint, error)
	GetVpcEndpoints(ctx context.Context, ids []string) ([]*VpcEndpoint, error)
	FindVpcEndpoints(ctx context.Context, filters []ec2types.Filter) ([]*VpcEndpoint, error)
	DeleteVpcEndpoint(ctx context.Context, id string) error

	// VPC Endpoints Route table associations
	CreateVpcEndpointRouteTableAssociation(ctx context.Context, routeTableId, vpcEndpointId string) error
	DeleteVpcEndpointRouteTableAssociation(ctx context.Context, routeTableId, vpcEndpointId string) error

	// Route tables
	CreateRouteTable(ctx context.Context, routeTable *RouteTable) (*RouteTable, error)
	GetRouteTable(ctx context.Context, id string) (*RouteTable, error)
	FindRouteTablesByTags(ctx context.Context, tags Tags) ([]*RouteTable, error)
	DeleteRouteTable(ctx context.Context, id string) error
	CreateRoute(ctx context.Context, routeTableId string, route *Route) error
	DeleteRoute(ctx context.Context, routeTableId string, route *Route) error

	// Subnets
	CreateSubnet(ctx context.Context, subnet *Subnet, maxWaitDur time.Duration) (*Subnet, error)
	GetSubnets(ctx context.Context, ids []string) ([]*Subnet, error)
	FindSubnets(ctx context.Context, filters []ec2types.Filter) ([]*Subnet, error)
	UpdateSubnetAttributes(ctx context.Context, desired, current *Subnet) (modified bool, err error)
	DeleteSubnet(ctx context.Context, id string) error

	// Subnet CIDR Reservation
	CreateCIDRReservation(ctx context.Context, subnet *Subnet, cidr string, reservationType string) (string, error)
	GetIPv6CIDRReservations(ctx context.Context, subnet *Subnet) ([]string, error)

	// Route table associations
	CreateRouteTableAssociation(ctx context.Context, routeTableId, subnetId string) (associationId *string, err error)
	DeleteRouteTableAssociation(ctx context.Context, associationId string) error

	// Elastic IP
	CreateElasticIP(ctx context.Context, eip *ElasticIP) (*ElasticIP, error)
	GetElasticIP(ctx context.Context, id string) (*ElasticIP, error)
	FindElasticIPsByTags(ctx context.Context, tags Tags) ([]*ElasticIP, error)
	DeleteElasticIP(ctx context.Context, id string) error

	// NAT gateway
	CreateNATGateway(ctx context.Context, gateway *NATGateway) (*NATGateway, error)
	WaitForNATGatewayAvailable(ctx context.Context, id string) error
	GetNATGateway(ctx context.Context, id string) (*NATGateway, error)
	FindNATGatewaysByTags(ctx context.Context, tags Tags) ([]*NATGateway, error)
	FindNATGateways(ctx context.Context, filters []ec2types.Filter) ([]*NATGateway, error)
	DeleteNATGateway(ctx context.Context, id string) error

	// Egress only internet gateway
	CreateEgressOnlyInternetGateway(ctx context.Context, gateway *EgressOnlyInternetGateway) (*EgressOnlyInternetGateway, error)
	GetEgressOnlyInternetGateway(ctx context.Context, id string) (*EgressOnlyInternetGateway, error)
	FindEgressOnlyInternetGatewaysByTags(ctx context.Context, tags Tags) ([]*EgressOnlyInternetGateway, error)
	FindEgressOnlyInternetGatewayByVPC(ctx context.Context, vpcId string) (*EgressOnlyInternetGateway, error)
	DeleteEgressOnlyInternetGateway(ctx context.Context, id string) error

	// Key pairs
	ImportKeyPair(ctx context.Context, keyName string, publicKey []byte, tags Tags) (*KeyPairInfo, error)
	GetKeyPair(ctx context.Context, keyName string) (*KeyPairInfo, error)
	DeleteKeyPair(ctx context.Context, keyName string) error

	// IAM Role
	CreateIAMRole(ctx context.Context, role *IAMRole) (*IAMRole, error)
	GetIAMRole(ctx context.Context, roleName string) (*IAMRole, error)
	DeleteIAMRole(ctx context.Context, roleName string) error
	UpdateAssumeRolePolicy(ctx context.Context, roleName, assumeRolePolicy string) error

	// IAM Instance Profile
	CreateIAMInstanceProfile(ctx context.Context, profile *IAMInstanceProfile) (*IAMInstanceProfile, error)
	GetIAMInstanceProfile(ctx context.Context, profileName string) (*IAMInstanceProfile, error)
	DeleteIAMInstanceProfile(ctx context.Context, profileName string) error
	AddRoleToIAMInstanceProfile(ctx context.Context, profileName, roleName string) error
	RemoveRoleFromIAMInstanceProfile(ctx context.Context, profileName, roleName string) error

	// IAM Role Policy
	PutIAMRolePolicy(ctx context.Context, policy *IAMRolePolicy) error
	GetIAMRolePolicy(ctx context.Context, policyName, roleName string) (*IAMRolePolicy, error)
	DeleteIAMRolePolicy(ctx context.Context, policyName, roleName string) error

	// EC2 tags
	CreateEC2Tags(ctx context.Context, resources []string, tags Tags) error
	DeleteEC2Tags(ctx context.Context, resources []string, tags Tags) error

	// Efs
	GetFileSystems(ctx context.Context, fileSystemID string) (*efstypes.FileSystemDescription, error)
	FindFileSystemsByTags(ctx context.Context, tags Tags) ([]*efstypes.FileSystemDescription, error)
	CreateFileSystem(ctx context.Context, input *efs.CreateFileSystemInput) (*efstypes.FileSystemDescription, error)
	DeleteFileSystem(ctx context.Context, input *efs.DeleteFileSystemInput) error
	DescribeMountTargetsEfs(ctx context.Context, input *efs.DescribeMountTargetsInput) (*efs.DescribeMountTargetsOutput, error)
	CreateMountTargetEfs(ctx context.Context, input *efs.CreateMountTargetInput) (*efs.CreateMountTargetOutput, error)
	DeleteMountTargetEfs(ctx context.Context, input *efs.DeleteMountTargetInput) error
}

// Factory creates instances of Interface.
type Factory interface {
	// NewClient creates a new instance of Interface for the given AWS credentials and region.
	NewClient(authConfig AuthConfig) (Interface, error)
}

// FactoryFunc is a function that implements Factory.
type FactoryFunc func(authConfig AuthConfig) (Interface, error)

// NewClient creates a new instance of Interface for the given AWS credentials and region.
func (f FactoryFunc) NewClient(authConfig AuthConfig) (Interface, error) {
	return f(authConfig)
}

// DhcpOptions contains the relevant fields of a EC2 DHCP options resource.
type DhcpOptions struct {
	Tags
	DhcpOptionsId      string
	DhcpConfigurations map[string][]string
}

// VPC contains the relevant fields of a EC2 VPC resource.
type VPC struct {
	Tags
	VpcId                        string
	CidrBlock                    string
	IPv6CidrBlock                string
	EnableDnsSupport             bool
	EnableDnsHostnames           bool
	AssignGeneratedIPv6CidrBlock bool
	DhcpOptionsId                *string
	InstanceTenancy              ec2types.Tenancy
	State                        *string
}

// SecurityGroup contains the relevant fields of a EC2 security group resource.
type SecurityGroup struct {
	Tags
	GroupId     string
	GroupName   string
	VpcId       *string
	Description *string
	Rules       []*SecurityGroupRule
}

// Clone creates a copy.
func (sg *SecurityGroup) Clone() *SecurityGroup {
	cp := *sg
	cp.Rules = slices.Clone(sg.Rules)
	cp.Tags = sg.Tags.Clone()
	return &cp
}

// SortedClone creates a copy with sorted rules.
func (sg *SecurityGroup) SortedClone() *SecurityGroup {
	cp := sg.Clone()
	sort.Slice(cp.Rules, func(i, j int) bool {
		ri := cp.Rules[i].SortedClone()
		rj := cp.Rules[j].SortedClone()
		return ri.LessThan(rj)
	})
	return cp
}

// EquivalentRulesTo returns true if the security rules are equivalent to the rules of another security group.
func (sg *SecurityGroup) EquivalentRulesTo(other *SecurityGroup) bool {
	if len(sg.Rules) != len(other.Rules) {
		return false
	}
	a := sg.SortedClone()
	b := other.SortedClone()
	for i := range a.Rules {
		ra := a.Rules[i]
		rb := b.Rules[i]
		if ra.LessThan(rb) || rb.LessThan(ra) {
			return false
		}
	}
	return true
}

// DiffRules calculates the different rules to another security group.
func (sg *SecurityGroup) DiffRules(other *SecurityGroup) (addedRules, removedRules []*SecurityGroupRule) {
	a := sg.SortedClone()
	b := other.SortedClone()
	an := len(a.Rules)
	bn := len(b.Rules)
	ai := 0
	bi := 0
	for ai < an || bi < bn {
		var ra, rb *SecurityGroupRule
		if ai < an {
			ra = a.Rules[ai]
		}
		if bi < bn {
			rb = b.Rules[bi]
		}
		if ra != nil {
			if rb == nil || ra.LessThan(rb) {
				addedRules = append(addedRules, ra)
				ai++
				continue
			}
		}
		if rb != nil {
			if ra == nil || rb.LessThan(ra) {
				removedRules = append(removedRules, rb)
				bi++
				continue
			}
		}
		if ra != nil && rb != nil {
			ai++
			bi++
		}
	}
	return
}

// SecurityGroupRuleType is type for security group rule types
type SecurityGroupRuleType string

const (
	// SecurityGroupRuleTypeIngress is the type for ingress rules
	SecurityGroupRuleTypeIngress SecurityGroupRuleType = "ingress"
	// SecurityGroupRuleTypeEgress is the type for egress rules
	SecurityGroupRuleTypeEgress SecurityGroupRuleType = "egress"
)

// SecurityGroupRule contains the relevant fields of a EC2 security group rule resource.
type SecurityGroupRule struct {
	Type         SecurityGroupRuleType
	FromPort     *int32
	ToPort       *int32
	Protocol     string
	CidrBlocks   []string
	CidrBlocksv6 []string
	Self         bool
	Foreign      *string
}

// Clone creates a copy.
func (sgr *SecurityGroupRule) Clone() *SecurityGroupRule {
	cp := *sgr
	cp.CidrBlocks = slices.Clone(sgr.CidrBlocks)
	cp.CidrBlocksv6 = slices.Clone(sgr.CidrBlocksv6)
	return &cp
}

// SortedClone creates a copy with sorted CidrBlocks array for comparing and sorting.
func (sgr *SecurityGroupRule) SortedClone() *SecurityGroupRule {
	cp := sgr.Clone()
	sort.Strings(cp.CidrBlocks)
	sort.Strings(cp.CidrBlocksv6)
	return cp
}

// LessThan compares to another securitry group role for ordering.
func (sgr *SecurityGroupRule) LessThan(other *SecurityGroupRule) bool {
	if sgr.Type < other.Type {
		return true
	}
	if sgr.Type > other.Type {
		return false
	}
	if sgr.Foreign != nil || other.Foreign != nil {
		if sgr.Foreign == nil {
			return true
		}
		if other.Foreign == nil {
			return false
		}
		if *sgr.Foreign < *other.Foreign {
			return true
		}
		if *sgr.Foreign > *other.Foreign {
			return false
		}
	}
	if sgr.Protocol < other.Protocol {
		return true
	}
	if sgr.Protocol > other.Protocol {
		return false
	}
	if sgr.FromPort != nil && other.FromPort != nil {
		if *sgr.FromPort < *other.FromPort {
			return true
		}
		if *sgr.FromPort > *other.FromPort {
			return false
		}
	}
	if sgr.ToPort != nil && other.ToPort != nil {
		if *sgr.ToPort < *other.ToPort {
			return true
		}
		if *sgr.ToPort > *other.ToPort {
			return false
		}
	}
	if sgr.Self != other.Self {
		return other.Self
	}
	if len(sgr.CidrBlocks) < len(other.CidrBlocks) {
		return true
	}
	if len(sgr.CidrBlocks) > len(other.CidrBlocks) {
		return false
	}
	for i := range sgr.CidrBlocks {
		if sgr.CidrBlocks[i] < other.CidrBlocks[i] {
			return true
		}
		if sgr.CidrBlocks[i] > other.CidrBlocks[i] {
			return false
		}
	}

	if len(sgr.CidrBlocksv6) < len(other.CidrBlocksv6) {
		return true
	}
	if len(sgr.CidrBlocksv6) > len(other.CidrBlocksv6) {
		return false
	}
	for i := range sgr.CidrBlocksv6 {
		if sgr.CidrBlocksv6[i] < other.CidrBlocksv6[i] {
			return true
		}
		if sgr.CidrBlocksv6[i] > other.CidrBlocksv6[i] {
			return false
		}
	}

	return false
}

// InternetGateway contains the relevant fields for an EC2 internet gateway resource.
type InternetGateway struct {
	Tags
	InternetGatewayId string
	VpcId             *string
}

// EgressOnlyInternetGateway contains the relevant fields for an EC2 internet gateway resource.
type EgressOnlyInternetGateway struct {
	Tags
	EgressOnlyInternetGatewayId string
	VpcId                       *string
}

// VpcEndpoint contains the relevant fields for an EC2 VPC endpoint resource.
type VpcEndpoint struct {
	Tags
	VpcEndpointId string
	VpcId         *string
	ServiceName   string
}

// RouteTable contains the relevant fields for an EC2 route table resource.
// Routes and Associations are filled for returned values, but ignored on creation.
type RouteTable struct {
	Tags
	RouteTableId string
	VpcId        *string
	Routes       []*Route
	Associations []*RouteTableAssociation
}

// Route contains the relevant fields for a route of an EC2 route table resource.
type Route struct {
	DestinationCidrBlock        *string
	DestinationIpv6CidrBlock    *string
	GatewayId                   *string
	NatGatewayId                *string
	EgressOnlyInternetGatewayId *string
	DestinationPrefixListId     *string
}

// DestinationId returns the destination id of the route.
func (r *Route) DestinationId() (string, error) {
	if v := ptr.Deref(r.DestinationCidrBlock, ""); v != "" {
		return v, nil
	} else if v := ptr.Deref(r.DestinationIpv6CidrBlock, ""); v != "" {
		return v, nil
	} else if v := ptr.Deref(r.DestinationPrefixListId, ""); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no route destination found")
}

// RouteTableAssociation contains the relevant fields for a route association of an EC2 route table resource.
type RouteTableAssociation struct {
	RouteTableAssociationId string
	Main                    bool
	GatewayId               *string
	SubnetId                *string
}

// Subnet contains the relevant fields for an EC2 subnet resource.
type Subnet struct {
	Tags
	SubnetId         string
	VpcId            *string
	CidrBlock        string
	AvailabilityZone string

	AssignIpv6AddressOnCreation             *bool
	CustomerOwnedIpv4Pool                   *string
	EnableDns64                             *bool
	EnableResourceNameDnsAAAARecordOnLaunch *bool
	EnableResourceNameDnsARecordOnLaunch    *bool
	Ipv6CidrBlocks                          []string
	Ipv6Native                              *bool
	MapPublicIpOnLaunch                     *bool
	MapCustomerOwnedIpOnLaunch              *bool
	OutpostArn                              *string
	PrivateDnsHostnameTypeOnLaunch          *string
}

// Clone creates a copy.
func (s *Subnet) Clone() *Subnet {
	cp := *s
	cp.Tags = s.Tags.Clone()
	return &cp
}

// ElasticIP contains the relevant fields for an EC2 elastic IP resource.
type ElasticIP struct {
	Tags
	AllocationId  string
	PublicIp      string
	Vpc           bool
	AssociationID *string
}

// NATGateway contains the relevant fields for an EC2 NAT gateway resource.
type NATGateway struct {
	Tags
	NATGatewayId    string
	EIPAllocationId string
	PublicIP        string
	SubnetId        string
	State           string
	VpcId           *string
}

// KeyPairInfo contains the relevant fields for an EC2 key pair.
type KeyPairInfo struct {
	Tags
	KeyName        string
	KeyFingerprint string
}

// IAMRole contains the relevant fields for an IAM role resource.
type IAMRole struct {
	RoleId                   string
	RoleName                 string
	Path                     string
	AssumeRolePolicyDocument string
	ARN                      string
}

// IAMInstanceProfile contains the relevant fields for an IAM instance profile resource.
type IAMInstanceProfile struct {
	InstanceProfileId   string
	InstanceProfileName string
	Path                string
	RoleName            string
}

// IAMRolePolicy contains the relevant fields for an IAM role policy resource.
type IAMRolePolicy struct {
	PolicyName     string
	RoleName       string
	PolicyDocument string
}

// GetAWSAPIErrorCode return error code of AWS api error.
func GetAWSAPIErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}

	// not an AWS API error
	return ""
}
