// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CloudProfileConfig contains provider-specific configuration that is embedded into Gardener's `CloudProfile`
// resource.
type CloudProfileConfig struct {
	metav1.TypeMeta `json:",inline"`
	// MachineImages is the list of machine images that are understood by the controller. It maps
	// logical names and versions to provider-specific identifiers.
	MachineImages []MachineImages `json:"machineImages"`
}

// MachineImages is a mapping from logical names and versions to provider-specific identifiers.
type MachineImages struct {
	// Name is the logical name of the machine image.
	Name string `json:"name"`
	// Versions contains versions and a provider-specific identifier.
	Versions []MachineImageVersion `json:"versions"`
}

// MachineImageVersion contains a version and a provider-specific identifier.
type MachineImageVersion struct {
	// Version is the version of the image.
	Version string `json:"version"`
	// TODO @Roncossek add "// deprecated" once aws cloudprofiles are migrated to use CapabilityFlavors

	// Regions is a mapping to the correct AMI for the machine image in the supported regions.
	Regions []RegionAMIMapping `json:"regions"`
	// CapabilityFlavors is grouping of region AMIs by capabilities.
	CapabilityFlavors []MachineImageFlavor `json:"capabilityFlavors"`
}

// MachineImageFlavor groups all RegionAMIMappings for a specific et of capabilities.
type MachineImageFlavor struct {
	// Regions is a mapping to the correct AMI for the machine image in the supported regions.
	Regions []RegionAMIMapping `json:"regions"`
	// Capabilities that are supported by the AMIs in this set.
	Capabilities gardencorev1beta1.Capabilities `json:"capabilities,omitempty"`
}

// GetCapabilities returns the Capabilities of a MachineImageFlavor
func (cs *MachineImageFlavor) GetCapabilities() gardencorev1beta1.Capabilities {
	return cs.Capabilities
}

// RegionAMIMapping is a mapping to the correct AMI for the machine image in the given region.
type RegionAMIMapping struct {
	// Name is the name of the region.
	Name string `json:"name"`
	// AMI is the AMI for the machine image.
	AMI string `json:"ami"`
	// TODO @Roncossek add "// deprecated" once aws cloudprofiles are migrated to use CapabilityFlavors

	// Architecture is the CPU architecture of the machine image.
	// +optional
	Architecture *string `json:"architecture,omitempty"`
}
