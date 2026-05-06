// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ReservedCIDR represents a CIDR that is already in use within the TGW routing domain.
type ReservedCIDR struct {
	CIDR   string // e.g. "10.100.0.0/16"
	Owner  string // e.g. "shoot my-shoot on seed my-seed"
	Reason string // e.g. "shoot VPC CIDR", "globalVPC management", "seed nodes"
}

// ValidateShootCIDROverlap checks that a shoot's VPC CIDR does not overlap with any
// reserved CIDRs in the TGW routing domain. Also checks shoot customRoutes destinations
// against globalVPC CIDRs and seed node CIDRs.
func ValidateShootCIDROverlap(
	fldPath *field.Path,
	shootNodesCIDR string,
	_ string,
	customRoutes []apisaws.CustomRoute,
	reserved []ReservedCIDR,
	seedConfig *apisaws.SeedProviderConfig,
) field.ErrorList {
	allErrs := field.ErrorList{}

	if shootNodesCIDR == "" || len(reserved) == 0 {
		return allErrs
	}

	// Check shoot nodes CIDR against all reserved CIDRs.
	for _, r := range reserved {
		if CIDRsOverlap(shootNodesCIDR, r.CIDR) {
			allErrs = append(allErrs, field.Forbidden(fldPath,
				fmt.Sprintf("VPC CIDR %s overlaps with %s (%s: %s). "+
					"All shoots on TGW-enabled seeds must use non-overlapping VPC CIDRs.",
					shootNodesCIDR, r.CIDR, r.Reason, r.Owner)))
		}
	}

	// Check shoot customRoutes destinations against all reserved CIDRs in the TGW routing domain.
	if seedConfig != nil && seedConfig.TransitGateway != nil && len(customRoutes) > 0 {
		for i, cr := range customRoutes {
			if cr.DestinationCidrBlock == nil {
				continue
			}
			dest := *cr.DestinationCidrBlock
			crPath := fldPath.Child("networks", "customRoutes").Index(i).Child("destinationCidrBlock")

			// Check against globalVPC CIDRs.
			for _, gvpc := range seedConfig.TransitGateway.GlobalVPCs {
				for _, gcidr := range gvpc.CIDRs {
					if CIDRsOverlap(dest, gcidr) {
						allErrs = append(allErrs, field.Forbidden(crPath,
							fmt.Sprintf("customRoute destination %s overlaps with globalVPC %q CIDR %s",
								dest, gvpc.Name, gcidr)))
					}
				}
			}

			// Check against all reserved CIDRs (seed nodes, runtime VPC, other shoots, globalCustomRoutes).
			for _, r := range reserved {
				if CIDRsOverlap(dest, r.CIDR) {
					allErrs = append(allErrs, field.Forbidden(crPath,
						fmt.Sprintf("customRoute destination %s overlaps with %s (%s: %s)",
							dest, r.CIDR, r.Reason, r.Owner)))
				}
			}
		}
	}

	return allErrs
}

// BuildReservedCIDRs builds the set of reserved CIDRs from the seed config and
// existing shoots on TGW-enabled seeds. The caller provides shoot names+CIDRs
// since listing shoots requires API access (done in the admission webhook, not here).
func BuildReservedCIDRs(
	seedName string,
	seedConfig *apisaws.SeedProviderConfig,
	seedNodesCIDR string,
	runtimeVPCCIDR string, // parent seed's nodes CIDR (runtime VPC)
	existingShoots map[string]string, // shootName -> nodesCIDR
	currentShootName string, // excluded from overlap check (self)
) []ReservedCIDR {
	var reserved []ReservedCIDR

	// Runtime VPC CIDR (parent seed that hosts the garden runtime).
	if runtimeVPCCIDR != "" {
		reserved = append(reserved, ReservedCIDR{
			CIDR:   runtimeVPCCIDR,
			Owner:  "runtime cluster",
			Reason: "runtime VPC",
		})
	}

	// Seed nodes CIDR.
	if seedNodesCIDR != "" {
		reserved = append(reserved, ReservedCIDR{
			CIDR:   seedNodesCIDR,
			Owner:  seedName,
			Reason: "seed nodes",
		})
	}

	// GlobalVPC CIDRs.
	if seedConfig != nil && seedConfig.TransitGateway != nil {
		for _, gvpc := range seedConfig.TransitGateway.GlobalVPCs {
			for _, cidr := range gvpc.CIDRs {
				reserved = append(reserved, ReservedCIDR{
					CIDR:   cidr,
					Owner:  fmt.Sprintf("globalVPC %q on seed %s", gvpc.Name, seedName),
					Reason: "globalVPC",
				})
			}
		}

		// GlobalCustomRoutes destinations.
		for _, gr := range seedConfig.GlobalCustomRoutes {
			if gr.DestinationCidrBlock != nil {
				reserved = append(reserved, ReservedCIDR{
					CIDR:   *gr.DestinationCidrBlock,
					Owner:  fmt.Sprintf("globalCustomRoute on seed %s", seedName),
					Reason: "globalCustomRoute destination",
				})
			}
		}
	}

	// Existing shoot VPC CIDRs on this seed.
	for name, cidr := range existingShoots {
		if name == currentShootName || cidr == "" {
			continue
		}
		reserved = append(reserved, ReservedCIDR{
			CIDR:   cidr,
			Owner:  fmt.Sprintf("shoot %q on seed %s", name, seedName),
			Reason: "shoot VPC CIDR",
		})
	}

	return reserved
}

// CIDRsOverlap returns true if two CIDR blocks overlap (one contains part of the other).
func CIDRsOverlap(a, b string) bool {
	_, netA, errA := net.ParseCIDR(a)
	_, netB, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return false
	}
	return netA.Contains(netB.IP) || netB.Contains(netA.IP)
}
