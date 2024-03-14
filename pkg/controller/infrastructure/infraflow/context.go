// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"fmt"
	"strings"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/sets"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

const (
	// TagKeyName is the name tag key
	TagKeyName = "Name"
	// TagKeyClusterTemplate is the template for the cluster tag key
	TagKeyClusterTemplate = "kubernetes.io/cluster/%s"
	// TagKeyRolePublicELB is the tag key for the public ELB
	TagKeyRolePublicELB = "kubernetes.io/role/elb"
	// TagKeyRolePrivateELB is the tag key for the internal ELB
	TagKeyRolePrivateELB = "kubernetes.io/role/internal-elb"
	// TagValueCluster is the tag value for the cluster tag
	TagValueCluster = "1"
	// TagValueELB is the tag value for the ELB tag keys
	TagValueELB = "1"

	// IdentifierVPC is the key for the VPC id
	IdentifierVPC = "VPC"
	// IdentifierDHCPOptions is the key for the id of the DHCPOptions resource
	IdentifierDHCPOptions = "DHCPOptions"
	// IdentifierDefaultSecurityGroup is the key for the id of the default security group
	IdentifierDefaultSecurityGroup = "DefaultSecurityGroup"
	// IdentifierInternetGateway is the key for the id of the internet gateway resource
	IdentifierInternetGateway = "InternetGateway"
	// IdentifierMainRouteTable is the key for the id of the main route table
	IdentifierMainRouteTable = "MainRouteTable"
	// IdentifierNodesSecurityGroup is the key for the id of the nodes security group
	IdentifierNodesSecurityGroup = "NodesSecurityGroup"
	// IdentifierZoneSubnetWorkers is the key for the id of the workers subnet
	IdentifierZoneSubnetWorkers = "SubnetWorkers"
	// IdentifierZoneSubnetPublic is the key for the id of the public utility subnet
	IdentifierZoneSubnetPublic = "SubnetPublicUtility"
	// IdentifierZoneSubnetPrivate is the key for the id of the private utility subnet
	IdentifierZoneSubnetPrivate = "SubnetPrivateUtility"
	// IdentifierZoneSuffix is the key for the suffix used for a zone
	IdentifierZoneSuffix = "Suffix"
	// IdentifierZoneNATGWElasticIP is the key for the id of the elastic IP resource used for the NAT gateway
	IdentifierZoneNATGWElasticIP = "NATGatewayElasticIP"
	// IdentifierZoneNATGateway is the key for the id of the NAT gateway resource
	IdentifierZoneNATGateway = "NATGateway"
	// IdentifierZoneRouteTable is the key for the id of route table of the zone
	IdentifierZoneRouteTable = "ZoneRouteTable"
	// IdentifierZoneSubnetPublicRouteTableAssoc is the key for the id of the public route table association resource
	IdentifierZoneSubnetPublicRouteTableAssoc = "SubnetPublicRouteTableAssoc"
	// IdentifierZoneSubnetPrivateRouteTableAssoc is the key for the id of the private c route table association resource
	IdentifierZoneSubnetPrivateRouteTableAssoc = "SubnetPrivateRouteTableAssoc"
	// IdentifierZoneSubnetWorkersRouteTableAssoc is key for the id of the workers route table association resource
	IdentifierZoneSubnetWorkersRouteTableAssoc = "SubnetWorkersRouteTableAssoc"
	// IdentifierVpcIPv6CidrBlock is the IPv6 CIDR block attached to the vpc
	IdentifierVpcIPv6CidrBlock = "VPCIPv6CidrBlock"
	// IdentifierEgressCIDRs is the key for the slice containing egress CIDRs strings.
	IdentifierEgressCIDRs = "EgressCIDRs"
	// NameIAMRole is the key for the name of the IAM role
	NameIAMRole = "IAMRoleName"
	// NameIAMInstanceProfile is the key for the name of the IAM instance profile
	NameIAMInstanceProfile = "IAMInstanceProfileName"
	// NameIAMRolePolicy is the key for the name of the IAM role policy
	NameIAMRolePolicy = "IAMRolePolicyName"
	// NameKeyPair is the key for the name of the EC2 key pair resource
	NameKeyPair = "KeyPair"
	// ARNIAMRole is the key for the ARN of the IAM role
	ARNIAMRole = "IAMRoleARN"
	// KeyPairFingerprint is the key to store the fingerprint of the key pair
	KeyPairFingerprint = "KeyPairFingerprint"
	// KeyPairSpecFingerprint is the key to store the fingerprint of the public key from the spec
	KeyPairSpecFingerprint = "KeyPairSpecFingerprint"

	// ChildIdVPCEndpoints is the child key for the VPC endpoints
	ChildIdVPCEndpoints = "VPCEndpoints"
	// ChildIdZones is the child key for the zones
	ChildIdZones = "Zones"

	// ObjectMainRouteTable is the object key used for caching the main route table object
	ObjectMainRouteTable = "MainRouteTable"
	// ObjectZoneRouteTable is the object key used for caching the zone route table object
	ObjectZoneRouteTable = "ZoneRouteTable"

	// MarkerMigratedFromTerraform is the key for marking the state for successful state migration from Terraformer
	MarkerMigratedFromTerraform = "MigratedFromTerraform"
	// MarkerTerraformCleanedUp is the key for marking the state for successful cleanup of Terraformer resources.
	MarkerTerraformCleanedUp = "TerraformCleanedUp"
	// MarkerLoadBalancersAndSecurityGroupsDestroyed is the key for marking the state that orphan load balancers
	// and security groups have already been destroyed
	MarkerLoadBalancersAndSecurityGroupsDestroyed = "LoadBalancersAndSecurityGroupsDestroyed"
)

// FlowContext contains the logic to reconcile or delete the AWS infrastructure.
type FlowContext struct {
	shared.BasicFlowContext
	state      shared.Whiteboard
	namespace  string
	infraSpec  extensionsv1alpha1.InfrastructureSpec
	config     *awsapi.InfrastructureConfig
	client     awsclient.Interface
	updater    awsclient.Updater
	commonTags awsclient.Tags
}

// NewFlowContext creates a new FlowContext object
func NewFlowContext(log logr.Logger, awsClient awsclient.Interface,
	infra *extensionsv1alpha1.Infrastructure, config *awsapi.InfrastructureConfig,
	oldState shared.FlatMap, persistor shared.FlowStatePersistor) (*FlowContext, error) {

	whiteboard := shared.NewWhiteboard()
	if oldState != nil {
		whiteboard.ImportFromFlatMap(oldState)
	}

	flowContext := &FlowContext{
		BasicFlowContext: *shared.NewBasicFlowContext(log, whiteboard, persistor),
		state:            whiteboard,
		namespace:        infra.Namespace,
		infraSpec:        infra.Spec,
		config:           config,
		client:           awsClient,
		updater:          awsclient.NewUpdater(awsClient, config.IgnoreTags),
	}
	flowContext.commonTags = awsclient.Tags{
		flowContext.tagKeyCluster(): TagValueCluster,
		TagKeyName:                  infra.Namespace,
	}
	if config.Networks.VPC.ID != nil {
		flowContext.state.SetPtr(IdentifierVPC, config.Networks.VPC.ID)
	}
	return flowContext, nil
}

// GetInfrastructureConfig returns the InfrastructureConfig object
func (c *FlowContext) GetInfrastructureConfig() *awsapi.InfrastructureConfig {
	return c.config
}

func (c *FlowContext) hasVPC() bool {
	return !c.state.IsAlreadyDeleted(IdentifierVPC)
}

func (c *FlowContext) commonTagsWithSuffix(suffix string) awsclient.Tags {
	tags := c.commonTags.Clone()
	tags[TagKeyName] = fmt.Sprintf("%s-%s", c.namespace, suffix)
	return tags
}

func (c *FlowContext) tagKeyCluster() string {
	return fmt.Sprintf(TagKeyClusterTemplate, c.namespace)
}

func (c *FlowContext) clusterTags() awsclient.Tags {
	tags := awsclient.Tags{}
	tags[c.tagKeyCluster()] = TagValueCluster
	return tags
}

func (c *FlowContext) vpcEndpointServiceNamePrefix() string {
	return fmt.Sprintf("com.amazonaws.%s.", c.infraSpec.Region)
}

func (c *FlowContext) extractVpcEndpointName(item *awsclient.VpcEndpoint) string {
	return strings.TrimPrefix(item.ServiceName, c.vpcEndpointServiceNamePrefix())
}

func (c *FlowContext) zoneSuffixHelpers(zoneName string) *ZoneSuffixHelper {
	zoneChild := c.getSubnetZoneChild(zoneName)
	if suffix := zoneChild.Get(IdentifierZoneSuffix); suffix != nil {
		return &ZoneSuffixHelper{suffix: *suffix}
	}
	zones := c.state.GetChild(ChildIdZones)
	existing := sets.New[string]()
	for _, key := range zones.GetChildrenKeys() {
		otherChild := zones.GetChild(key)
		if suffix := otherChild.Get(IdentifierZoneSuffix); suffix != nil {
			existing.Insert(*suffix)
		}
	}
	for i := 0; ; i++ {
		suffix := fmt.Sprintf("z%d", i)
		if !existing.Has(suffix) {
			zoneChild.Set(IdentifierZoneSuffix, suffix)
			return &ZoneSuffixHelper{suffix: suffix}
		}
	}
}

// ZoneSuffixHelper provides methods to create suffices for various resources
type ZoneSuffixHelper struct {
	suffix string
}

// GetSuffixSubnetWorkers builds the suffix for the workers subnet
func (h *ZoneSuffixHelper) GetSuffixSubnetWorkers() string {
	return fmt.Sprintf("nodes-%s", h.suffix)
}

// GetSuffixSubnetPublic builds the suffix for the public utility subnet
func (h *ZoneSuffixHelper) GetSuffixSubnetPublic() string {
	return fmt.Sprintf("public-utility-%s", h.suffix)
}

// GetSuffixSubnetPrivate builds the suffix for the private utility subnet
func (h *ZoneSuffixHelper) GetSuffixSubnetPrivate() string {
	return fmt.Sprintf("private-utility-%s", h.suffix)
}

// GetSuffixElasticIP builds the suffix for the elastic IP of the NAT gateway
func (h *ZoneSuffixHelper) GetSuffixElasticIP() string {
	return fmt.Sprintf("eip-natgw-%s", h.suffix)
}

// GetSuffixNATGateway builds the suffix for the NAT gateway
func (h *ZoneSuffixHelper) GetSuffixNATGateway() string {
	return fmt.Sprintf("natgw-%s", h.suffix)
}
