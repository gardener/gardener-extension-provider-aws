// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"fmt"
	"net"
	"slices"

	awsSDK "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	v1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	cidrvalidation "github.com/gardener/gardener/pkg/utils/validation/cidr"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	apiaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// configValidator implements ConfigValidator for aws infrastructure resources.
type configValidator struct {
	client           client.Client
	awsClientFactory awsclient.Factory
	logger           logr.Logger
}

// NewConfigValidator creates a new ConfigValidator.
func NewConfigValidator(mgr manager.Manager, awsClientFactory awsclient.Factory, logger logr.Logger) infrastructure.ConfigValidator {
	return &configValidator{
		client:           mgr.GetClient(),
		awsClientFactory: awsClientFactory,
		logger:           logger.WithName("aws-infrastructure-config-validator"),
	}
}

// Validate validates the provider config of the given infrastructure resource with the cloud provider.
func (c *configValidator) Validate(ctx context.Context, infra *extensionsv1alpha1.Infrastructure) field.ErrorList {
	allErrs := field.ErrorList{}

	logger := c.logger.WithValues("infrastructure", client.ObjectKeyFromObject(infra))

	// Get provider config from the infrastructure resource
	config, err := helper.InfrastructureConfigFromInfrastructure(infra)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(nil, err))
		return allErrs
	}

	// Create AWS client
	authConfig, err := aws.GetCredentialsFromSecretRef(ctx, c.client, infra.Spec.SecretRef, false, infra.Spec.Region)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(nil, fmt.Errorf("could not get AWS credentials: %+v", err)))
		return allErrs
	}

	// Determine whether IPv6 is required by reading the Shoot's ipFamilies from the Cluster resource.
	// This covers both the legacy dualStack.enabled flag and the modern ipFamilies-based dual-stack.
	requiresIPv6 := config.DualStack != nil && config.DualStack.Enabled
	cluster, err := extensions.GetCluster(ctx, c.client, infra.Namespace)
	if err != nil {
		logger.Error(err, "could not read Cluster resource, falling back to legacy DualStack detection")
	} else if cluster != nil && cluster.Shoot != nil && cluster.Shoot.Spec.Networking != nil {
		if slices.Contains(cluster.Shoot.Spec.Networking.IPFamilies, v1beta1.IPFamilyIPv6) {
			requiresIPv6 = true
		}
	}

	awsClient, err := c.awsClientFactory.NewClient(*authConfig)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(nil, fmt.Errorf("could not create AWS client: %+v", err)))
		return allErrs
	}

	// Validate infrastructure config
	if config.Networks.VPC.ID != nil {
		logger.Info("Validating infrastructure networks.vpc.id")
		allErrs = append(allErrs, c.validateVPC(ctx, field.NewPath("networks"),
			awsClient, *config, *config.Networks.VPC.ID, infra.Spec.Region, requiresIPv6)...)
	}

	// Extract node network CIDR for BYO subnet validation
	var nodesCIDRs []string
	if cluster != nil && cluster.Shoot != nil && cluster.Shoot.Spec.Networking != nil && cluster.Shoot.Spec.Networking.Nodes != nil {
		nodesCIDRs = []string{*cluster.Shoot.Spec.Networking.Nodes}
	}

	// Validate BYO subnet IDs exist and are in the correct VPC/AZ
	if config.Networks.VPC.ID != nil {
		allErrs = append(allErrs, c.validateBYOSubnets(ctx, awsClient, config, *config.Networks.VPC.ID, requiresIPv6, nodesCIDRs)...)
	}

	// Validate BYO security group exists and is in the correct VPC
	if config.Networks.NodesSecurityGroupID != nil && config.Networks.VPC.ID != nil {
		allErrs = append(allErrs, c.validateBYOSecurityGroup(ctx, awsClient, *config.Networks.NodesSecurityGroupID, *config.Networks.VPC.ID)...)
	}

	// The AWS Cloud Controller Manager (CCM) runs outside the shoot VPC (in the seed). It requires
	// a non-empty SubnetID in its cloud-provider-config to trigger "external master" mode
	// (see aws.go:623 in cloud-provider-aws). Without this, the CCM tries to call the EC2 instance
	// metadata service and crashes. The SubnetID is never actually used at runtime — LB subnets are
	// discovered via cluster tags — but it must be non-empty for initialization.
	// The CCM config uses a fallback cascade: public > internal > workers subnet.
	// In BYO mode (workersSubnetID set), the workers subnet is always available as a fallback,
	// so this check is only needed for managed mode where no public CIDR might be specified.
	isBYO := len(config.Networks.Zones) > 0 && config.Networks.Zones[0].WorkersSubnetID != nil
	if config.Networks.VPC.ID != nil && !isBYO {
		allErrs = append(allErrs, c.validatePublicSubnetAvailability(ctx, awsClient, config, *config.Networks.VPC.ID, infra.Namespace)...)
	}

	var (
		eips      []string
		eipToZone = make(map[string]string)
	)

	for _, zone := range config.Networks.Zones {
		if zone.ElasticIPAllocationID != nil {
			eips = append(eips, *zone.ElasticIPAllocationID)
			eipToZone[*zone.ElasticIPAllocationID] = zone.Name
		}
	}

	if len(eips) > 0 {
		allErrs = append(allErrs, c.validateEIPS(ctx, awsClient, infra.Namespace, eips, eipToZone, field.NewPath("networks", "zones[]", "elasticIPAllocationID"))...)
	}

	return allErrs
}

func (c *configValidator) validateVPC(
	ctx context.Context,
	fldPath *field.Path,
	awsClient awsclient.Interface,
	infraConfig apiaws.InfrastructureConfig,
	vpcID, region string,
	requiresIPv6 bool,
) field.ErrorList {
	allErrs := field.ErrorList{}

	vpcIdPath := fldPath.Child("vpc", "id")

	// Verify that the VPC exists and the enableDnsSupport and enableDnsHostnames VPC attributes are both true
	for _, attribute := range []ec2types.VpcAttributeName{ec2types.VpcAttributeNameEnableDnsSupport, ec2types.VpcAttributeNameEnableDnsHostnames} {
		value, err := awsClient.GetVPCAttribute(ctx, vpcID, attribute)
		if err != nil {
			if awsclient.IsNotFoundError(err) {
				allErrs = append(allErrs, field.NotFound(vpcIdPath, vpcID))
			} else {
				allErrs = append(allErrs, field.InternalError(vpcIdPath, fmt.Errorf("could not get VPC attribute %s for VPC %s: %w", attribute, vpcID, err)))
			}
			return allErrs
		}
		if !value {
			allErrs = append(allErrs, field.Invalid(vpcIdPath, vpcID, fmt.Sprintf("VPC attribute %s must be set to true", attribute)))
		}
	}

	if requiresIPv6 {
		_, err := awsClient.GetIPv6Cidr(ctx, vpcID)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(vpcIdPath, vpcID, fmt.Sprintf("VPC %s has no ipv6 CIDR", vpcID)))
			return allErrs
		}
	}

	// Determine if any zone uses Gardener-managed public subnets (requires IGW).
	// For fully BYO configurations, users manage their own connectivity.
	requiresIGW := false
	for _, zone := range infraConfig.Networks.Zones {
		if zone.Public != nil {
			requiresIGW = true
			break
		}
	}

	if requiresIGW {
		internetGatewayID, err := awsClient.GetVPCInternetGateway(ctx, vpcID)
		if err != nil {
			allErrs = append(allErrs, field.InternalError(vpcIdPath, fmt.Errorf("could not get internet gateway for VPC %s: %w", vpcID, err)))
			return allErrs
		}
		if internetGatewayID == "" {
			allErrs = append(allErrs, field.Invalid(vpcIdPath, vpcID, "no attached internet gateway found (required when Gardener manages public subnets)"))
		}
	}

	// Verify DHCP options
	dhcpOptions, err := awsClient.GetDHCPOptions(ctx, vpcID)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(vpcIdPath, fmt.Errorf("could not get DHCP options for VPC %s: %w", vpcID, err)))
		return allErrs
	}

	if domainName, ok := dhcpOptions["domain-name"]; !ok {
		allErrs = append(allErrs, field.Invalid(vpcIdPath, vpcID, "missing domain-name value in DHCP options used by the VPC"))
	} else if (region == "us-east-1" && domainName != "ec2.internal") || (region != "us-east-1" && domainName != region+".compute.internal") {
		allErrs = append(allErrs, field.Invalid(vpcIdPath, vpcID, fmt.Sprintf("invalid domain-name specified in DHCP options used by VPC: %s", domainName)))
	}

	// crosscheck subnet CIDRs are subset of VPC CIDR (only for Gardener-managed subnets)
	vpc, err := awsClient.GetVpc(ctx, vpcID)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(vpcIdPath, fmt.Errorf("could not get CIDR block for VPC %s: %w", vpcID, err)))
		return allErrs
	}

	cidrsToConsider := []string{vpc.CidrBlock}
	cidrsToConsider = append(cidrsToConsider, vpc.CidrBlockAssociationSet...)

	allErrs = append(allErrs, validateZoneSubnetCIDRs(fldPath, cidrsToConsider, infraConfig.Networks.Zones)...)

	return allErrs
}

// validateBYOSubnets validates that referenced BYO subnet IDs exist and are in the correct VPC/AZ.
// When requiresIPv6 is true, it also validates IPv6-readiness of all BYO subnets.
func (c *configValidator) validateBYOSubnets(ctx context.Context, awsClient awsclient.Interface, config *apiaws.InfrastructureConfig, vpcID string, requiresIPv6 bool, nodesCIDRs []string) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, zone := range config.Networks.Zones {
		zonePath := field.NewPath("networks", "zones").Index(i)

		if zone.WorkersSubnetID == nil {
			continue
		}

		// Validate worker subnet
		fldPath := zonePath.Child("workersSubnetID")
		workerSubnet, workerErrs := c.validateBYOSubnet(ctx, awsClient, zone.WorkersSubnetID, fldPath, vpcID, zone.Name)
		allErrs = append(allErrs, workerErrs...)
		if len(workerErrs) == 0 && workerSubnet != nil {
			if requiresIPv6 {
				allErrs = append(allErrs, validateSubnetIPv6Readiness(workerSubnet, fldPath, *zone.WorkersSubnetID, true)...)
			}
			// Validate that the shoot's node network range fits inside the worker subnet CIDR.
			allErrs = append(allErrs, validateNodesCIDRInSubnet(workerSubnet, fldPath, *zone.WorkersSubnetID, nodesCIDRs)...)
		}

		// Validate BYO public LB subnet
		if zone.PublicSubnetID != nil {
			pubPath := zonePath.Child("publicSubnetID")
			pubSubnet, pubErrs := c.validateBYOSubnet(ctx, awsClient, zone.PublicSubnetID, pubPath, vpcID, zone.Name)
			allErrs = append(allErrs, pubErrs...)
			if len(pubErrs) == 0 && pubSubnet != nil {
				if requiresIPv6 {
					allErrs = append(allErrs, validateSubnetIPv6Readiness(pubSubnet, pubPath, *zone.PublicSubnetID, false)...)
				}
				allErrs = append(allErrs, validateLBSubnetNotIPv6Native(pubSubnet, pubPath, *zone.PublicSubnetID)...)
			}
		}

		// Validate BYO internal LB subnet
		if zone.InternalSubnetID != nil {
			intPath := zonePath.Child("internalSubnetID")
			intSubnet, intErrs := c.validateBYOSubnet(ctx, awsClient, zone.InternalSubnetID, intPath, vpcID, zone.Name)
			allErrs = append(allErrs, intErrs...)
			if len(intErrs) == 0 && intSubnet != nil {
				if requiresIPv6 {
					allErrs = append(allErrs, validateSubnetIPv6Readiness(intSubnet, intPath, *zone.InternalSubnetID, false)...)
				}
				allErrs = append(allErrs, validateLBSubnetNotIPv6Native(intSubnet, intPath, *zone.InternalSubnetID)...)
			}
		}
	}

	return allErrs
}

// validateBYOSubnet validates existence, VPC, and AZ of a BYO subnet, returning the subnet for further checks.
func (c *configValidator) validateBYOSubnet(ctx context.Context, awsClient awsclient.Interface, subnetID *string, fldPath *field.Path, vpcID, expectedAZ string) (*awsclient.Subnet, field.ErrorList) {
	allErrs := field.ErrorList{}

	if subnetID == nil {
		return nil, allErrs
	}

	subnets, err := awsClient.GetSubnets(ctx, []string{*subnetID})
	if err != nil {
		allErrs = append(allErrs, field.InternalError(fldPath, fmt.Errorf("could not get subnet %s: %w", *subnetID, err)))
		return nil, allErrs
	}
	if len(subnets) == 0 {
		allErrs = append(allErrs, field.NotFound(fldPath, *subnetID))
		return nil, allErrs
	}
	subnet := subnets[0]
	if subnet.VpcId != nil && *subnet.VpcId != vpcID {
		allErrs = append(allErrs, field.Invalid(fldPath, *subnetID,
			fmt.Sprintf("subnet is in VPC %s, expected %s", *subnet.VpcId, vpcID)))
	}
	if subnet.AvailabilityZone != expectedAZ {
		allErrs = append(allErrs, field.Invalid(fldPath, *subnetID,
			fmt.Sprintf("subnet is in availability zone %s, expected %s", subnet.AvailabilityZone, expectedAZ)))
	}

	return subnet, allErrs
}

// validateSubnetIPv6Readiness checks that a BYO subnet is properly configured for IPv6.
func validateSubnetIPv6Readiness(subnet *awsclient.Subnet, fldPath *field.Path, subnetID string, isWorker bool) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(subnet.Ipv6CidrBlocks) == 0 {
		if isWorker {
			allErrs = append(allErrs, field.Invalid(fldPath, subnetID,
				"worker subnet has no IPv6 CIDR block but IPv6 is enabled; "+
					"the subnet must have an IPv6 CIDR block from the VPC's IPv6 pool"))
		} else {
			allErrs = append(allErrs, field.Invalid(fldPath, subnetID,
				"load balancer subnet has no IPv6 CIDR block but IPv6 is enabled; "+
					"LB subnets must have an IPv6 CIDR block for dual-stack load balancers"))
		}
		return allErrs
	}

	// Worker subnets must have AssignIpv6AddressOnCreation enabled so that
	// EC2 instances automatically receive an IPv6 address at launch.
	if isWorker && (subnet.AssignIpv6AddressOnCreation == nil || !*subnet.AssignIpv6AddressOnCreation) {
		allErrs = append(allErrs, field.Invalid(fldPath, subnetID,
			"worker subnet does not have AssignIpv6AddressOnCreation enabled; "+
				"worker subnets must auto-assign IPv6 addresses so nodes get IPv6 at launch"))
	}

	return allErrs
}

// validateLBSubnetNotIPv6Native checks that LB subnets have an IPv4 CIDR (AWS NLBs/ALBs require IPv4).
func validateLBSubnetNotIPv6Native(subnet *awsclient.Subnet, fldPath *field.Path, subnetID string) field.ErrorList {
	allErrs := field.ErrorList{}

	if subnet.CidrBlock == "" || (subnet.Ipv6Native != nil && *subnet.Ipv6Native) {
		allErrs = append(allErrs, field.Invalid(fldPath, subnetID,
			"load balancer subnets must have an IPv4 CIDR block; "+
				"AWS NLBs and ALBs cannot be deployed to IPv6-native subnets"))
	}

	return allErrs
}

// validateNodesCIDRInSubnet checks that each IPv4 node network CIDR is contained within the
// worker subnet's IPv4 CIDR block. This ensures nodes will receive IPs from within the subnet range.
func validateNodesCIDRInSubnet(subnet *awsclient.Subnet, fldPath *field.Path, subnetID string, nodesCIDRs []string) field.ErrorList {
	allErrs := field.ErrorList{}

	if subnet.CidrBlock == "" || len(nodesCIDRs) == 0 {
		return allErrs
	}

	_, subnetNet, err := net.ParseCIDR(subnet.CidrBlock)
	if err != nil {
		// Subnet CIDR is malformed — skip check, AWS would reject it anyway
		return allErrs
	}

	for _, nodesCIDR := range nodesCIDRs {
		nodesIP, nodesNet, err := net.ParseCIDR(nodesCIDR)
		if err != nil {
			continue
		}
		// Only check IPv4 node CIDRs against the IPv4 subnet CIDR
		if nodesIP.To4() == nil {
			continue
		}

		// The nodes CIDR must be fully contained within the subnet CIDR.
		// Check: subnet contains the first IP of nodes range AND the subnet prefix is shorter or equal.
		subnetOnes, _ := subnetNet.Mask.Size()
		nodesOnes, _ := nodesNet.Mask.Size()
		if !subnetNet.Contains(nodesIP) || nodesOnes < subnetOnes {
			allErrs = append(allErrs, field.Invalid(fldPath, subnetID,
				fmt.Sprintf("shoot nodes CIDR %s is not contained within worker subnet CIDR %s",
					nodesCIDR, subnet.CidrBlock)))
		}
	}

	return allErrs
}

// validateBYOSecurityGroup validates that a referenced security group exists and is in the correct VPC.
func (c *configValidator) validateBYOSecurityGroup(ctx context.Context, awsClient awsclient.Interface, sgID, vpcID string) field.ErrorList {
	allErrs := field.ErrorList{}
	fldPath := field.NewPath("networks", "nodesSecurityGroupID")

	sg, err := awsClient.GetSecurityGroup(ctx, sgID)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(fldPath, fmt.Errorf("could not get security group %s: %w", sgID, err)))
		return allErrs
	}
	if sg == nil {
		allErrs = append(allErrs, field.NotFound(fldPath, sgID))
		return allErrs
	}
	if sg.VpcId != nil && *sg.VpcId != vpcID {
		allErrs = append(allErrs, field.Invalid(fldPath, sgID,
			fmt.Sprintf("security group is in VPC %s, expected %s", *sg.VpcId, vpcID)))
	}

	return allErrs
}

// ValidateZoneSubnetCIDRs validates that the provided CIDRs (assumed to be from a single VPC) are
// set up in a way that it's conceivable that the shoot creation can succeed. It is checked
// that for each subnet there is at least one CIDR present that is a superset of the subnet's CIDR.
// In BYO mode (zone.WorkersSubnetID set), the Workers CIDR is skipped. Empty Public/Internal CIDRs
// are also skipped since they are optional.
func validateZoneSubnetCIDRs(fldPath *field.Path, cidrs []string, zones []apiaws.Zone) field.ErrorList {
	allErrs := field.ErrorList{}
	zonesPath := fldPath.Child("zones")

	vpcCIDRs := []cidrvalidation.CIDR{}
	for _, cidr := range cidrs {
		vpcCIDRs = append(vpcCIDRs, cidrvalidation.NewCIDR(cidr, fldPath.Child("vpc")))
	}

	isSubnetCIDRContainedInAnyCIDR := func(cidrsToCheck []cidrvalidation.CIDR, subnetCIDR cidrvalidation.CIDR) bool {
		return slices.ContainsFunc(cidrsToCheck, func(vpcCIDR cidrvalidation.CIDR) bool {
			return vpcCIDR.ValidateSubset(subnetCIDR).ToAggregate() == nil
		})
	}

	for i, zone := range zones {
		var subnetCIDRs []cidrvalidation.CIDR
		if zone.Workers != nil && zone.WorkersSubnetID == nil {
			subnetCIDRs = append(subnetCIDRs, cidrvalidation.NewCIDR(*zone.Workers, zonesPath.Index(i).Child("nodes")))
		}
		if zone.Public != nil {
			subnetCIDRs = append(subnetCIDRs, cidrvalidation.NewCIDR(*zone.Public, zonesPath.Index(i).Child("public")))
		}
		if zone.Internal != nil {
			subnetCIDRs = append(subnetCIDRs, cidrvalidation.NewCIDR(*zone.Internal, zonesPath.Index(i).Child("internal")))
		}
		for _, subnetCIDR := range subnetCIDRs {
			if !isSubnetCIDRContainedInAnyCIDR(vpcCIDRs, subnetCIDR) {
				allErrs = append(allErrs, field.Invalid(
					subnetCIDR.GetFieldPath(),
					subnetCIDR.GetCIDR(),
					fmt.Sprintf("subnet CIDR %q is not contained in any of the VPC's associated CIDR blocks", subnetCIDR.GetCIDR()),
				))
			}
		}
	}
	return allErrs
}

// validateEIP validates if the given elastic IP exists and can be associated by the Shoot's NAT gateway
// An EIP can be associated with the Shoot when
//   - it is not associated yet (new)
//   - it is already associated to any Gardener-created NAT Gateway of the Shoot cluster (identified by tag `kubernetes.io/cluster/<shoot-name>`)
func (c *configValidator) validateEIPS(ctx context.Context, awsClient awsclient.Interface, shootNamespace string, elasticIPAllocationIDs []string, elasticIPAllocationIDToZone map[string]string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	mapping, err := awsClient.GetElasticIPsAssociationIDForAllocationIDs(ctx, elasticIPAllocationIDs)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(fldPath, fmt.Errorf("failed to list Elastic IPs: %w", err)))
		return allErrs
	}

	var associatedEips []string
	for _, allocationID := range elasticIPAllocationIDs {
		associationId, ok := mapping[allocationID]
		if !ok {
			allErrs = append(allErrs, field.Invalid(fldPath, allocationID, fmt.Sprintf("elastic IP in zone %q cannot be used as it does not exist. Please make sure the elastic IPs configured in the Infrastructure configuration (field: `elasticIPAllocationID`) exist.", elasticIPAllocationIDToZone[allocationID])))
			continue
		}

		// EIP found, but not associated to any resource yet --> new.
		// no further checks needed as this Elastic IPs is freely available to be associated with the NAT Gateway of the Shoot
		if associationId == nil {
			continue
		}

		associatedEips = append(associatedEips, allocationID)
	}

	if len(associatedEips) == 0 {
		return allErrs
	}

	// check if the existing and already associated Elastic IPs are associated with NAT Gateways in the VPC of the Shoot
	allocationIDsNATGateway, err := awsClient.GetNATGatewayAddressAllocations(ctx, shootNamespace)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(fldPath, fmt.Errorf("failed to list existing address allocations for NAT Gateways: %w", err)))
		return allErrs
	}

	diff := sets.New[string](associatedEips...).Difference(allocationIDsNATGateway)
	if diff.Len() == 0 {
		return allErrs
	}

	for _, allocationID := range sets.List(diff) {
		allErrs = append(allErrs, field.Invalid(fldPath, allocationID, fmt.Sprintf("elastic IP in zone %q cannot be attached to the clusters NAT Gateway(s) as it is already associated. Please make sure the elastic IPs configured in the Infrastructure configuration (field: `elasticIPAllocationID`) are not already attached to another AWS resource.", elasticIPAllocationIDToZone[allocationID])))
	}

	return allErrs
}

// validatePublicSubnetAvailability checks that at least one public subnet is available for the CCM config.
// The AWS CCM runs outside the shoot VPC (in the seed) and needs a non-empty SubnetID in its
// cloud-provider-config to trigger "external master" mode (see aws.go:623 in cloud-provider-aws).
// Without it, the CCM tries to call the EC2 instance metadata service and crashes. The SubnetID is
// never used at runtime — LB subnets are discovered via cluster tags — but must be non-empty for init.
// A public subnet can come from either:
//   - A Gardener-managed public CIDR in the zone config, or
//   - An existing subnet in the VPC tagged with kubernetes.io/role/elb=1 and the cluster tag.
func (c *configValidator) validatePublicSubnetAvailability(ctx context.Context, awsClient awsclient.Interface, config *apiaws.InfrastructureConfig, vpcID, clusterName string) field.ErrorList {
	allErrs := field.ErrorList{}

	// If any zone has a public CIDR, Gardener will create a public subnet — nothing to check.
	for _, zone := range config.Networks.Zones {
		if zone.Public != nil {
			return allErrs
		}
	}

	// No Gardener-managed public subnets. Check if user-tagged public subnets exist in the VPC.
	// Use tag-key filter for the cluster tag (accepts any value: "1", "owned", "shared").
	clusterTag := fmt.Sprintf("kubernetes.io/cluster/%s", clusterName)
	filters := append(
		awsclient.WithFilters().
			WithVpcId(vpcID).
			WithTags(awsclient.Tags{"kubernetes.io/role/elb": "1"}).
			Build(),
		ec2types.Filter{
			Name:   awsSDK.String("tag-key"),
			Values: []string{clusterTag},
		},
	)

	subnets, err := awsClient.FindSubnets(ctx, filters)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(field.NewPath("networks", "zones"),
			fmt.Errorf("could not check for existing public subnets in VPC %s: %w", vpcID, err)))
		return allErrs
	}

	if len(subnets) == 0 {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("networks", "zones"),
			"no public subnet available for the AWS Cloud Controller Manager configuration; "+
				"either specify a public CIDR in at least one zone, use publicSubnetID in BYO mode, "+
				"or ensure an existing subnet in the VPC is tagged with kubernetes.io/role/elb=1 and "+clusterTag+"=1"))
	}

	return allErrs
}
