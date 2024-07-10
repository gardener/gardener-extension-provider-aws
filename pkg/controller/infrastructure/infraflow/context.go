// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"
	"strings"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
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

// Opts contain options to initiliaze a FlowContext
type Opts struct {
	Log            logr.Logger
	ClientFactory  awsclient.Interface
	Infrastructure *extensionsv1alpha1.Infrastructure
	State          *awsapi.InfrastructureState
	AwsClient      awsclient.Interface
	RuntimeClient  client.Client
	Config         *awsapi.InfrastructureConfig
	OldState       shared.FlatMap
}

// FlowContext contains the logic to reconcile or delete the AWS infrastructure.
type FlowContext struct {
	log           logr.Logger
	state         shared.Whiteboard
	namespace     string
	infra         *extensionsv1alpha1.Infrastructure
	infraSpec     extensionsv1alpha1.InfrastructureSpec
	config        *awsapi.InfrastructureConfig
	client        awsclient.Interface
	runtimeClient client.Client
	updater       awsclient.Updater
	commonTags    awsclient.Tags
	*shared.BasicFlowContext
}

// NewFlowContext creates a new FlowContext object
func NewFlowContext(opts Opts) (*FlowContext, error) {
	whiteboard := shared.NewWhiteboard()
	if opts.OldState != nil {
		whiteboard.ImportFromFlatMap(opts.OldState)
	}

	infraConfig, err := helper.InfrastructureConfigFromInfrastructure(opts.Infrastructure)
	if err != nil {
		return nil, err
	}

	flowContext := &FlowContext{
		log:       opts.Log,
		state:     whiteboard,
		namespace: opts.Infrastructure.Namespace,
		infraSpec: opts.Infrastructure.Spec,
		config:    infraConfig,
		updater:   awsclient.NewUpdater(opts.AwsClient, opts.Config.IgnoreTags),
		infra:     opts.Infrastructure,
		// TODO no need for two clients
		client:        opts.AwsClient,
		runtimeClient: opts.RuntimeClient,
	}
	flowContext.commonTags = awsclient.Tags{
		flowContext.tagKeyCluster(): TagValueCluster,
		TagKeyName:                  opts.Infrastructure.Namespace,
	}
	if opts.Config.Networks.VPC.ID != nil {
		flowContext.state.SetPtr(IdentifierVPC, opts.Config.Networks.VPC.ID)
	}
	return flowContext, nil
}

func (fctx *FlowContext) persistState(ctx context.Context) error {
	var egressCIDRs []string
	if v := fctx.state.Get(IdentifierEgressCIDRs); v != nil {
		egressCIDRs = strings.Split(*v, ",")
	}
	return PatchProviderStatusAndState(ctx, fctx.runtimeClient, fctx.infra, nil, fctx.computeInfrastructureState(), egressCIDRs)
}

func PatchProviderStatusAndState(
	ctx context.Context,
	runtimeClient client.Client,
	infra *extensionsv1alpha1.Infrastructure,
	status *awsv1alpha1.InfrastructureStatus,
	state *runtime.RawExtension,
	egressCIDRs []string,
) error {
	patch := client.MergeFrom(infra.DeepCopy())
	if status != nil {
		infra.Status.ProviderStatus = &runtime.RawExtension{Object: status}
	}

	if egressCIDRs != nil {
		infra.Status.EgressCIDRs = egressCIDRs
	}

	if state != nil {
		infra.Status.State = state
	}

	// do not make a patch request if nothing has changed.
	if data, err := patch.Data(infra); err != nil {
		return fmt.Errorf("failed getting patch data for infra %s: %w", infra.Name, err)
	} else if string(data) == `{}` {
		return nil
	}

	return runtimeClient.Status().Patch(ctx, infra, patch)
}

func (fctx *FlowContext) computeInfrastructureStatus() *awsv1alpha1.InfrastructureStatus {
	status := &awsv1alpha1.InfrastructureStatus{
		TypeMeta: metav1.TypeMeta{
			APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
			Kind:       "InfrastructureStatus",
		},
	}

	vpcID := ptr.Deref(fctx.state.Get(IdentifierVPC), "")
	groupID := ptr.Deref(fctx.state.Get(IdentifierNodesSecurityGroup), "")
	ec2KeyName := ptr.Deref(fctx.state.Get(NameKeyPair), "")
	iamInstanceProfileName := ptr.Deref(fctx.state.Get(NameIAMInstanceProfile), "")
	arnIamRole := ptr.Deref(fctx.state.Get(ARNIAMRole), "")

	if fctx.config.Networks.VPC.ID != nil {
		vpcID = *fctx.config.Networks.VPC.ID
	}

	if vpcID != "" {
		var subnets []awsv1alpha1.Subnet
		prefix := ChildIdZones + shared.Separator
		for k, v := range fctx.state.AsMap() {
			if !shared.IsValidValue(v) {
				continue
			}
			if strings.HasPrefix(k, prefix) {
				parts := strings.Split(k, shared.Separator)
				if len(parts) != 3 {
					continue
				}
				var purpose string
				switch parts[2] {
				case IdentifierZoneSubnetPublic:
					purpose = awsapi.PurposePublic
				case IdentifierZoneSubnetWorkers:
					purpose = awsapi.PurposeNodes
				default:
					continue
				}
				subnets = append(subnets, awsv1alpha1.Subnet{
					ID:      v,
					Purpose: purpose,
					Zone:    parts[1],
				})
			}
		}

		status.VPC = awsv1alpha1.VPCStatus{
			ID:      vpcID,
			Subnets: subnets,
		}
		if groupID != "" {
			status.VPC.SecurityGroups = []awsv1alpha1.SecurityGroup{
				{
					Purpose: awsapi.PurposeNodes,
					ID:      groupID,
				},
			}
		}
	}

	if ec2KeyName != "" {
		status.EC2.KeyName = ec2KeyName
	}

	if iamInstanceProfileName != "" {
		status.IAM.InstanceProfiles = []awsv1alpha1.InstanceProfile{
			{
				Purpose: awsapi.PurposeNodes,
				Name:    iamInstanceProfileName,
			},
		}
	}
	if arnIamRole != "" {
		status.IAM.Roles = []awsv1alpha1.Role{
			{
				Purpose: awsapi.PurposeNodes,
				ARN:     arnIamRole,
			},
		}
	}

	return status
}

func (fctx *FlowContext) computeInfrastructureState() *runtime.RawExtension {
	return &runtime.RawExtension{
		Object: &awsv1alpha1.InfrastructureState{
			TypeMeta: metav1.TypeMeta{
				APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
				Kind:       "InfrastructureState",
			},
			Data: fctx.state.ExportAsFlatMap(),
		},
	}
}

// GetInfrastructureConfig returns the InfrastructureConfig object
func (c *FlowContext) GetInfrastructureConfig() *awsapi.InfrastructureConfig {
	return c.config
}

func (c *FlowContext) hasVPC() bool {
	return c.state.Get(IdentifierVPC) != nil
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
