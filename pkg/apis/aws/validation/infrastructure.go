// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	cidrvalidation "github.com/gardener/gardener/pkg/utils/validation/cidr"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// valid values for networks.vpc.gatewayEndpoints
var gatewayEndpointPattern = regexp.MustCompile(`^\w+(\.\w+)*$`)

// ValidateInfrastructureConfigAgainstCloudProfile validates the given `InfrastructureConfig` against the given `CloudProfile`.
func ValidateInfrastructureConfigAgainstCloudProfile(oldInfra, infra *apisaws.InfrastructureConfig, shoot *core.Shoot, cloudProfile *gardencorev1beta1.CloudProfile, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	shootRegion := shoot.Spec.Region
	for _, region := range cloudProfile.Spec.Regions {
		if region.Name == shootRegion {
			allErrs = append(allErrs, validateInfrastructureConfigZones(oldInfra, infra, region.Zones, fldPath.Child("network"))...)
			break
		}
	}

	return allErrs
}

// validateInfrastructureConfigZones validates the given `InfrastructureConfig` against the given `Zones`.
func validateInfrastructureConfigZones(oldInfra, infra *apisaws.InfrastructureConfig, zones []gardencorev1beta1.AvailabilityZone, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	awsZones := sets.New[string]()
	for _, awsZone := range zones {
		awsZones.Insert(awsZone.Name)
	}

	usedZones := sets.New[string]()
	for i, zone := range infra.Networks.Zones {
		if oldInfra != nil && len(oldInfra.Networks.Zones) > i && oldInfra.Networks.Zones[i] == zone {
			usedZones.Insert(zone.Name)
			continue
		}

		if !awsZones.Has(zone.Name) {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("zones").Index(i).Child("name"), zone.Name, awsZones.UnsortedList()))
		}
		if usedZones.Has(zone.Name) {
			allErrs = append(allErrs, field.Duplicate(fldPath.Child("zones").Index(i).Child("name"), zone.Name))
		}
		usedZones.Insert(zone.Name)
	}

	return allErrs
}

// ValidateInfrastructureConfig validates a InfrastructureConfig object.
func ValidateInfrastructureConfig(infra *apisaws.InfrastructureConfig, nodesCIDR, podsCIDR, servicesCIDR *string) field.ErrorList {
	allErrs := field.ErrorList{}

	var (
		nodes    cidrvalidation.CIDR
		pods     cidrvalidation.CIDR
		services cidrvalidation.CIDR
	)

	networkingPath := field.NewPath("networking")
	if nodesCIDR != nil {
		nodes = cidrvalidation.NewCIDR(*nodesCIDR, networkingPath.Child("nodes"))
	}
	if podsCIDR != nil {
		pods = cidrvalidation.NewCIDR(*podsCIDR, networkingPath.Child("pods"))
	}
	if servicesCIDR != nil {
		services = cidrvalidation.NewCIDR(*servicesCIDR, networkingPath.Child("services"))
	}

	networksPath := field.NewPath("networks")
	if len(infra.Networks.Zones) == 0 {
		allErrs = append(allErrs, field.Required(networksPath.Child("zones"), "must specify at least the networks for one zone"))
	}

	if len(infra.Networks.VPC.GatewayEndpoints) > 0 {
		epsPath := networksPath.Child("vpc", "gatewayEndpoints")
		for i, svc := range infra.Networks.VPC.GatewayEndpoints {
			if !gatewayEndpointPattern.MatchString(svc) {
				allErrs = append(allErrs, field.Invalid(epsPath.Index(i), svc, "must be a valid domain name"))
			}
		}
	}

	var (
		cidrs                            = make([]cidrvalidation.CIDR, 0, len(infra.Networks.Zones)*3)
		workerCIDRs                      = make([]cidrvalidation.CIDR, 0, len(infra.Networks.Zones))
		referencedElasticIPAllocationIDs []string
	)

	for i, zone := range infra.Networks.Zones {
		zonePath := networksPath.Child("zones").Index(i)

		internalPath := zonePath.Child("internal")
		cidrs = append(cidrs, cidrvalidation.NewCIDR(zone.Internal, internalPath))
		allErrs = append(allErrs, cidrvalidation.ValidateCIDRIsCanonical(internalPath, zone.Internal)...)

		publicPath := zonePath.Child("public")
		cidrs = append(cidrs, cidrvalidation.NewCIDR(zone.Public, publicPath))
		allErrs = append(allErrs, cidrvalidation.ValidateCIDRIsCanonical(publicPath, zone.Public)...)

		workerPath := zonePath.Child("workers")
		cidrs = append(cidrs, cidrvalidation.NewCIDR(zone.Workers, workerPath))
		allErrs = append(allErrs, cidrvalidation.ValidateCIDRIsCanonical(workerPath, zone.Workers)...)
		workerCIDRs = append(workerCIDRs, cidrvalidation.NewCIDR(zone.Workers, workerPath))

		if zone.ElasticIPAllocationID != nil {
			for _, eIP := range referencedElasticIPAllocationIDs {
				if eIP == *zone.ElasticIPAllocationID {
					allErrs = append(allErrs, field.Duplicate(zonePath.Child("elasticIPAllocationID"), *zone.ElasticIPAllocationID))
					break
				}
			}
			referencedElasticIPAllocationIDs = append(referencedElasticIPAllocationIDs, *zone.ElasticIPAllocationID)

			if !strings.HasPrefix(*zone.ElasticIPAllocationID, "eipalloc-") {
				allErrs = append(allErrs, field.Invalid(zonePath.Child("elasticIPAllocationID"), *zone.ElasticIPAllocationID, "must start with eipalloc-"))
			}
		}
	}

	allErrs = append(allErrs, cidrvalidation.ValidateCIDRParse(cidrs...)...)

	if nodes != nil {
		allErrs = append(allErrs, nodes.ValidateSubset(workerCIDRs...)...)
	}

	if (infra.Networks.VPC.ID == nil && infra.Networks.VPC.CIDR == nil) || (infra.Networks.VPC.ID != nil && infra.Networks.VPC.CIDR != nil) {
		allErrs = append(allErrs, field.Invalid(networksPath.Child("vpc"), infra.Networks.VPC, "must specify either a vpc id or a cidr"))
	} else if infra.Networks.VPC.CIDR != nil && infra.Networks.VPC.ID == nil {
		cidrPath := networksPath.Child("vpc", "cidr")
		vpcCIDR := cidrvalidation.NewCIDR(*infra.Networks.VPC.CIDR, cidrPath)
		allErrs = append(allErrs, cidrvalidation.ValidateCIDRIsCanonical(cidrPath, *infra.Networks.VPC.CIDR)...)
		allErrs = append(allErrs, vpcCIDR.ValidateParse()...)
		allErrs = append(allErrs, vpcCIDR.ValidateSubset(nodes)...)
		allErrs = append(allErrs, vpcCIDR.ValidateSubset(cidrs...)...)
		allErrs = append(allErrs, vpcCIDR.ValidateNotOverlap(pods, services)...)
	}

	// make sure that VPC cidrs don't overlap with each other
	allErrs = append(allErrs, cidrvalidation.ValidateCIDROverlap(cidrs, false)...)
	if pods != nil {
		allErrs = append(allErrs, pods.ValidateNotOverlap(cidrs...)...)
	}
	if services != nil {
		allErrs = append(allErrs, services.ValidateNotOverlap(cidrs...)...)
	}

	allErrs = append(allErrs, ValidateIgnoreTags(field.NewPath("ignoreTags"), infra.IgnoreTags)...)

	return allErrs
}

// ValidateInfrastructureConfigUpdate validates a InfrastructureConfig object.
func ValidateInfrastructureConfigUpdate(oldConfig, newConfig *apisaws.InfrastructureConfig) field.ErrorList {
	allErrs := field.ErrorList{}

	vpcPath := field.NewPath("networks.vpc")
	oldVPC := oldConfig.Networks.VPC
	newVPC := newConfig.Networks.VPC
	allErrs = append(allErrs, apivalidation.ValidateImmutableField(newVPC.ID, oldVPC.ID, vpcPath.Child("id"))...)
	allErrs = append(allErrs, apivalidation.ValidateImmutableField(newVPC.CIDR, oldVPC.CIDR, vpcPath.Child("cidr"))...)

	var (
		oldZones = oldConfig.Networks.Zones
		newZones = newConfig.Networks.Zones
	)

	if len(oldZones) > len(newZones) {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("networks.zones"), "removing zones is not allowed"))
		return allErrs
	}

	for i, oldZone := range oldZones {
		idxPath := field.NewPath("networks.zones").Index(i)
		allErrs = append(allErrs, apivalidation.ValidateImmutableField(oldZone.Name, newConfig.Networks.Zones[i].Name, idxPath.Child("name"))...)
		allErrs = append(allErrs, apivalidation.ValidateImmutableField(oldZone.Public, newConfig.Networks.Zones[i].Public, idxPath.Child("public"))...)
		allErrs = append(allErrs, apivalidation.ValidateImmutableField(oldZone.Internal, newConfig.Networks.Zones[i].Internal, idxPath.Child("internal"))...)
		allErrs = append(allErrs, apivalidation.ValidateImmutableField(oldZone.Workers, newConfig.Networks.Zones[i].Workers, idxPath.Child("workers"))...)
	}
	if oldConfig.DualStack != nil && oldConfig.DualStack.Enabled && (newConfig.DualStack == nil || !newConfig.DualStack.Enabled) {
		dualStackPath := field.NewPath("dualStack.enabled")
		allErrs = append(allErrs, field.Forbidden(dualStackPath, "field can't be changed from \"true\" to \"false\""))
	}
	return allErrs
}

var (
	reservedTagKeys        = []string{"Name"}
	reservedTagKeyPrefixes = []string{
		"kubernetes.io",
		// not used yet. forbid it nevertheless, so we don't need to introduce any incompatible change, when we reserve it
		// sometime in the future
		"gardener.cloud",
	}
)

// ValidateIgnoreTags validates that a given IgnoreTags value doesn't ignore any reserved tag keys and prefixes.
func ValidateIgnoreTags(fldPath *field.Path, ignoreTags *apisaws.IgnoreTags) field.ErrorList {
	allErrs := field.ErrorList{}

	if ignoreTags == nil {
		return allErrs
	}

	keysPath := fldPath.Child("keys")
	for i, key := range ignoreTags.Keys {
		idxPath := keysPath.Index(i)
		if key == "" {
			allErrs = append(allErrs, field.Invalid(idxPath, key, "ignored key must not be empty"))
			continue
		}
		allErrs = append(allErrs, validateKeyIsReserved(idxPath, key)...)
		allErrs = append(allErrs, validateKeyHasReservedPrefix(idxPath, key)...)
	}

	prefixesPath := fldPath.Child("keyPrefixes")
	for i, prefix := range ignoreTags.KeyPrefixes {
		idxPath := prefixesPath.Index(i)
		if prefix == "" {
			allErrs = append(allErrs, field.Invalid(idxPath, prefix, "ignored key prefix must not be empty"))
			continue
		}
		allErrs = append(allErrs, validatePrefixIncludesReservedKey(idxPath, prefix)...)
		allErrs = append(allErrs, validatePrefixMatchesReservedPrefix(idxPath, prefix)...)
	}

	return allErrs
}

func validateKeyIsReserved(fldPath *field.Path, key string) field.ErrorList {
	allErrs := field.ErrorList{}
	for _, reserved := range reservedTagKeys {
		if key == reserved {
			allErrs = append(allErrs, field.Invalid(fldPath, key, fmt.Sprintf("must not ignore reserved key %q", reserved)))
			break
		}
	}
	return allErrs
}

func validateKeyHasReservedPrefix(fldPath *field.Path, key string) field.ErrorList {
	allErrs := field.ErrorList{}
	for _, reserved := range reservedTagKeyPrefixes {
		if strings.HasPrefix(key, reserved) {
			allErrs = append(allErrs, field.Invalid(fldPath, key, fmt.Sprintf("must not ignore key with reserved prefix %q", reserved)))
			break
		}
	}
	return allErrs
}

func validatePrefixIncludesReservedKey(fldPath *field.Path, prefix string) field.ErrorList {
	allErrs := field.ErrorList{}
	for _, reserved := range reservedTagKeys {
		if strings.HasPrefix(reserved, prefix) {
			allErrs = append(allErrs, field.Invalid(fldPath, prefix, fmt.Sprintf("must not include reserved key %q", reserved)))
			break
		}
	}
	return allErrs
}

func validatePrefixMatchesReservedPrefix(fldPath *field.Path, prefix string) field.ErrorList {
	allErrs := field.ErrorList{}
	for _, reserved := range reservedTagKeyPrefixes {
		if strings.HasPrefix(prefix, reserved) {
			allErrs = append(allErrs, field.Invalid(fldPath, prefix, fmt.Sprintf("must not include reserved key prefix %q", reserved)))
			break
		}
		if strings.HasPrefix(reserved, prefix) {
			allErrs = append(allErrs, field.Invalid(fldPath, prefix, fmt.Sprintf("must not have reserved key prefix %q", reserved)))
			break
		}
	}
	return allErrs
}
