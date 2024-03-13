// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

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
	credentials, err := aws.GetCredentialsFromSecretRef(ctx, c.client, infra.Spec.SecretRef, false)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(nil, fmt.Errorf("could not get AWS credentials: %+v", err)))
		return allErrs
	}
	awsClient, err := c.awsClientFactory.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), infra.Spec.Region)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(nil, fmt.Errorf("could not create AWS client: %+v", err)))
		return allErrs
	}

	// Validate infrastructure config
	if config.Networks.VPC.ID != nil {
		logger.Info("Validating infrastructure networks.vpc.id")
		allErrs = append(allErrs, c.validateVPC(ctx, awsClient, *config.Networks.VPC.ID, infra.Spec.Region, field.NewPath("networks", "vpc", "id"), config.DualStack != nil && config.DualStack.Enabled)...)
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

func (c *configValidator) validateVPC(ctx context.Context, awsClient awsclient.Interface, vpcID, region string, fldPath *field.Path, dualStack bool) field.ErrorList {
	allErrs := field.ErrorList{}

	// Verify that the VPC exists and the enableDnsSupport and enableDnsHostnames VPC attributes are both true
	for _, attribute := range []string{"enableDnsSupport", "enableDnsHostnames"} {
		value, err := awsClient.GetVPCAttribute(ctx, vpcID, attribute)
		if err != nil {
			if awsclient.IsNotFoundError(err) {
				allErrs = append(allErrs, field.NotFound(fldPath, vpcID))
			} else {
				allErrs = append(allErrs, field.InternalError(fldPath, fmt.Errorf("could not get VPC attribute %s for VPC %s: %w", attribute, vpcID, err)))
			}
			return allErrs
		}
		if !value {
			allErrs = append(allErrs, field.Invalid(fldPath, vpcID, fmt.Sprintf("VPC attribute %s must be set to true", attribute)))
		}
	}

	if dualStack {
		_, err := awsClient.GetIPv6Cidr(ctx, vpcID)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath, vpcID, fmt.Sprintf("VPC %s has no ipv6 CIDR", vpcID)))
			return allErrs
		}
	}

	// Verify that there is an internet gateway attached to the VPC
	internetGatewayID, err := awsClient.GetVPCInternetGateway(ctx, vpcID)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(fldPath, fmt.Errorf("could not get internet gateway for VPC %s: %w", vpcID, err)))
		return allErrs
	}
	if internetGatewayID == "" {
		allErrs = append(allErrs, field.Invalid(fldPath, vpcID, "no attached internet gateway found"))
	}

	// Verify DHCP options
	dhcpOptions, err := awsClient.GetDHCPOptions(ctx, vpcID)
	if err != nil {
		allErrs = append(allErrs, field.InternalError(fldPath, fmt.Errorf("could not get DHCP options for VPC %s: %w", vpcID, err)))
		return allErrs
	}

	if domainName, ok := dhcpOptions["domain-name"]; !ok {
		allErrs = append(allErrs, field.Invalid(fldPath, vpcID, "missing domain-name value in DHCP options used by the VPC"))
	} else if (region == "us-east-1" && domainName != "ec2.internal") || (region != "us-east-1" && domainName != region+".compute.internal") {
		allErrs = append(allErrs, field.Invalid(fldPath, vpcID, fmt.Sprintf("invalid domain-name specified in DHCP options used by VPC: %s", domainName)))
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
