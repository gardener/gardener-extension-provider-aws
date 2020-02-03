// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validation

import (
	"fmt"
	"regexp"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	cidrvalidation "github.com/gardener/gardener/pkg/utils/validation/cidr"

	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateInfrastructureConfigAgainstCloudProfile validates the given `InfrastructureConfig` against the given `CloudProfile`.
func ValidateInfrastructureConfigAgainstCloudProfile(infra *apisaws.InfrastructureConfig, shoot *core.Shoot, cloudProfile *gardencorev1beta1.CloudProfile, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	shootRegion := shoot.Spec.Region
	for _, region := range cloudProfile.Spec.Regions {
		if region.Name == shootRegion {
			allErrs = append(allErrs, validateInfrastructureConfigZones(infra, region.Zones, fldPath.Child("network"))...)
			break
		}
	}

	return allErrs
}

// validateInfrastructureConfigZones validates the given `InfrastructureConfig` against the given `Zones`.
func validateInfrastructureConfigZones(infra *apisaws.InfrastructureConfig, zones []gardencorev1beta1.AvailabilityZone, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	awsZones := sets.NewString()
	for _, awsZone := range zones {
		awsZones.Insert(awsZone.Name)
	}

	for i, zone := range infra.Networks.Zones {
		if !awsZones.Has(zone.Name) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("zones").Index(i).Child("name"), zone.Name, fmt.Sprintf("supported values: %v", awsZones.UnsortedList())))
		}
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

	if nodesCIDR != nil {
		nodes = cidrvalidation.NewCIDR(*nodesCIDR, nil)
	}
	if podsCIDR != nil {
		pods = cidrvalidation.NewCIDR(*podsCIDR, nil)
	}
	if servicesCIDR != nil {
		services = cidrvalidation.NewCIDR(*servicesCIDR, nil)
	}

	networksPath := field.NewPath("networks")
	if len(infra.Networks.Zones) == 0 {
		allErrs = append(allErrs, field.Required(networksPath.Child("zones"), "must specify at least the networks for one zone"))
	}

	if len(infra.Networks.VPC.GatewayEndpoints) > 0 {
		epsPath := networksPath.Child("vpc", "gatewayEndpoints")
		re := regexp.MustCompile(`^\w+$`)
		for i, svc := range infra.Networks.VPC.GatewayEndpoints {
			if !re.MatchString(svc) {
				allErrs = append(allErrs, field.Invalid(epsPath.Index(i), svc, "must be alphanumeric"))
			}
		}
	}

	var (
		cidrs       = make([]cidrvalidation.CIDR, 0, len(infra.Networks.Zones)*3)
		workerCIDRs = make([]cidrvalidation.CIDR, 0, len(infra.Networks.Zones))
	)

	validatedZones := sets.NewString()
	for i, zone := range infra.Networks.Zones {
		zonePath := networksPath.Child("zones").Index(i)
		if validatedZones.Has(zone.Name) {
			allErrs = append(allErrs, field.Invalid(zonePath.Child("name"), zone.Name, "each zone may only be specified once"))
		}

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

		validatedZones.Insert(zone.Name)
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
		allErrs = append(allErrs, vpcCIDR.ValidateNotSubset(pods, services)...)
	}

	// make sure that VPC cidrs don't overlap with each other
	allErrs = append(allErrs, cidrvalidation.ValidateCIDROverlap(cidrs, cidrs, false)...)
	allErrs = append(allErrs, cidrvalidation.ValidateCIDROverlap([]cidrvalidation.CIDR{pods, services}, cidrs, false)...)

	return allErrs
}

// ValidateInfrastructureConfigUpdate validates a InfrastructureConfig object.
func ValidateInfrastructureConfigUpdate(oldConfig, newConfig *apisaws.InfrastructureConfig) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, apivalidation.ValidateImmutableField(newConfig.Networks.VPC, oldConfig.Networks.VPC, field.NewPath("networks.vpc"))...)

	var (
		oldZones     = oldConfig.Networks.Zones
		newZones     = newConfig.Networks.Zones
		missingZones = sets.NewString()
	)

	for i, oldZone := range oldZones {
		missingZones.Insert(oldZone.Name)
		for j, newZone := range newZones {
			if newZone.Name == oldZone.Name {
				missingZones.Delete(newZone.Name)
				allErrs = append(allErrs, apivalidation.ValidateImmutableField(newConfig.Networks.Zones[j], oldConfig.Networks.Zones[j], field.NewPath("networks.zones").Index(i))...)
			}
		}
	}

	for zone := range missingZones {
		allErrs = append(allErrs, field.Invalid(field.NewPath("networks.zones"), zone, "zone is missing - removing a zone is not supported"))
	}

	return allErrs
}
