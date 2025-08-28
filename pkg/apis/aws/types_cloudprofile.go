// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"github.com/gardener/gardener/pkg/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CloudProfileConfig contains provider-specific configuration that is embedded into Gardener's `CloudProfile`
// resource.
type CloudProfileConfig struct {
	metav1.TypeMeta
	// MachineImages is the list of machine images that are understood by the controller. It maps
	// logical names and versions to provider-specific identifiers.
	MachineImages []MachineImages
}

// MachineImages is a mapping from logical names and versions to provider-specific identifiers.
type MachineImages struct {
	// Name is the logical name of the machine image.
	Name string
	// Versions contains versions and a provider-specific identifier.
	Versions []MachineImageVersion
}

// MachineImageVersion contains a version and a provider-specific identifier.
type MachineImageVersion struct {
	// Version is the version of the image.
	Version string
	// TODO @Roncossek add "// deprecated" once aws cloudprofiles are migrated to use CapabilitySets

	// Regions is a mapping to the correct AMI for the machine image in the supported regions.
	Regions []RegionAMIMapping
	// CapabilitySets is grouping of region AMIs by capabilities.
	CapabilitySets []CapabilitySet
}

// CapabilitySet groups all RegionAMIMappings for a specific et of capabilities.
type CapabilitySet struct {
	// Regions is a mapping to the correct AMI for the machine image in the supported regions.
	Regions []RegionAMIMapping
	// Capabilities that are supported by the AMIs in this set.
	Capabilities core.Capabilities
}

// GetCapabilities returns the Capabilities of a CapabilitySet
func (cs *CapabilitySet) GetCapabilities() core.Capabilities {
	return cs.Capabilities
}

// SetCapabilities sets the Capabilities on a CapabilitySet
func (cs *CapabilitySet) SetCapabilities(capabilities core.Capabilities) {
	cs.Capabilities = capabilities
}

// RegionAMIMapping is a mapping to the correct AMI for the machine image in the given region.
type RegionAMIMapping struct {
	// Name is the name of the region.
	Name string
	// AMI is the AMI for the machine image.
	AMI string
	// TODO @Roncossek add "// deprecated" once aws cloudprofiles are migrated to use CapabilitySets

	// Architecture is the CPU architecture of the machine image.
	Architecture *string
}
