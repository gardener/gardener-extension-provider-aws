// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

// This file contains helper functions for capabilities handling, e.g. conversion, comparison, validation.
// These functions can be used by different providers and should not contain any provider-specific logic.
// All functions in this file should be transitioned into the Gardener core repository over time once the
// implementation is stable.

import (
	"fmt"
	"maps"
	"slices"

	gardencoreapi "github.com/gardener/gardener/pkg/api"
	gardencore "github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ConvertV1beta1CapabilitiesDefinitions converts core.CapabilityDefinition objects to v1beta1.CapabilityDefinition objects.
func ConvertV1beta1CapabilitiesDefinitions(capabilitiesDefinitions []gardencore.CapabilityDefinition) ([]gardencorev1beta1.CapabilityDefinition, error) {
	var v1beta1CapabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition
	for _, capabilityDefinition := range capabilitiesDefinitions {
		var v1beta1CapabilityDefinition gardencorev1beta1.CapabilityDefinition
		err := gardencoreapi.Scheme.Convert(&capabilityDefinition, &v1beta1CapabilityDefinition, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to convert capability definition: %w", err)
		}
		v1beta1CapabilitiesDefinitions = append(v1beta1CapabilitiesDefinitions, v1beta1CapabilityDefinition)
	}
	return v1beta1CapabilitiesDefinitions, nil
}

// AreCapabilitiesEqual checks if two capabilities are semantically equal.
func AreCapabilitiesEqual(a, b gardencorev1beta1.Capabilities) bool {
	return areCapabilitiesSubsetOf(a, b) && areCapabilitiesSubsetOf(b, a)
}

// areCapabilitiesSubsetOf verifies if all keys and values in `source` exist in `target`.
func areCapabilitiesSubsetOf(source, target gardencorev1beta1.Capabilities) bool {
	for key, valuesSource := range source {
		valuesTarget, exists := target[key]
		if !exists {
			return false
		}
		for _, value := range valuesSource {
			if !slices.Contains(valuesTarget, value) {
				return false
			}
		}
	}
	return true
}

// ValidateCapabilities validates the capabilities of a machine type or machine image against the capabilitiesDefinition located in a cloud profile at spec.capabilities.
// It checks if the capabilities are supported by the cloud profile and if the architecture is defined correctly.
// It returns a list of field errors if any validation fails.
func ValidateCapabilities(capabilities gardencorev1beta1.Capabilities, capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	// create map from capabilitiesDefinitions
	capabilitiesDefinition := make(map[string][]string)
	for _, capabilityDefinition := range capabilitiesDefinitions {
		capabilitiesDefinition[capabilityDefinition.Name] = capabilityDefinition.Values
	}
	supportedCapabilityKeys := slices.Collect(maps.Keys(capabilitiesDefinition))

	// Check if all capabilities are supported by the cloud profile
	for capabilityKey, capability := range capabilities {
		supportedValues, keyExists := capabilitiesDefinition[capabilityKey]
		if !keyExists {
			allErrs = append(allErrs, field.NotSupported(fldPath, capabilityKey, supportedCapabilityKeys))
			continue
		}
		for i, value := range capability {
			if !slices.Contains(supportedValues, value) {
				allErrs = append(allErrs, field.NotSupported(fldPath.Child(capabilityKey).Index(i), value, supportedValues))
			}
		}
	}

	// Check additional requirements for architecture
	// - must be defined when multiple architectures are supported by the cloud profile
	supportedArchitectures := capabilitiesDefinition[v1beta1constants.ArchitectureName]
	architectures := capabilities[v1beta1constants.ArchitectureName]
	if len(supportedArchitectures) > 1 && len(architectures) != 1 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child(v1beta1constants.ArchitectureName), architectures, "must define exactly one architecture when multiple architectures are supported by the cloud profile"))
	}

	return allErrs
}

// AreCapabilitiesCompatible checks if two sets of capabilities are compatible.
// It applies defaults from the capability definitions to both sets before checking compatibility.
func AreCapabilitiesCompatible(capabilities1, capabilities2 gardencorev1beta1.Capabilities, capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition) bool {
	defaultedCapabilities1 := gardencorev1beta1helper.GetCapabilitiesWithAppliedDefaults(capabilities1, capabilitiesDefinitions)
	defaultedCapabilities2 := gardencorev1beta1helper.GetCapabilitiesWithAppliedDefaults(capabilities2, capabilitiesDefinitions)

	isSupported := true
	commonCapabilities := getCapabilitiesIntersection(defaultedCapabilities1, defaultedCapabilities2)
	// If the intersection has at least one value for each capability, the capabilities are supported.
	for _, values := range commonCapabilities {
		if len(values) == 0 {
			isSupported = false
			break
		}
	}

	return isSupported
}

// getCapabilitiesIntersection returns the intersection of multiple capabilities objects.
func getCapabilitiesIntersection(capabilitiesList ...gardencorev1beta1.Capabilities) gardencorev1beta1.Capabilities {
	intersection := make(gardencorev1beta1.Capabilities)

	if len(capabilitiesList) == 0 {
		return intersection
	}

	// Initialize intersection with the first capabilities object
	maps.Copy(intersection, capabilitiesList[0])

	intersect := func(slice1, slice2 []string) []string {
		elementSet1 := sets.New(slice1...)
		elementSet2 := sets.New(slice2...)

		return elementSet1.Intersection(elementSet2).UnsortedList()
	}

	// Iterate through the remaining capabilities objects and refine the intersection
	for _, capabilities := range capabilitiesList[1:] {
		for key, values := range intersection {
			intersection[key] = intersect(values, capabilities[key])
		}
	}

	return intersection
}

// HasCapabilities defines an interface for types that contain Capabilities
type HasCapabilities interface {
	GetCapabilities() gardencorev1beta1.Capabilities
	SetCapabilities(gardencorev1beta1.Capabilities)
}

// FindBestCapabilitySet finds the most appropriate capability set from the provided capability sets
// based on the requested machine capabilities and the definitions of capabilities.
func FindBestCapabilitySet[T HasCapabilities](
	capabilitySets []T,
	machineCapabilities gardencorev1beta1.Capabilities,
	capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition,
) (T, error) {
	var zeroValue T
	compatibleCapabilitySets := findCompatibleCapabilitySets(capabilitySets, machineCapabilities, capabilitiesDefinitions)

	if len(compatibleCapabilitySets) == 0 {
		return zeroValue, fmt.Errorf("no compatible capability set found")
	}

	bestMatch, err := selectBestCapabilitySet(compatibleCapabilitySets, capabilitiesDefinitions)
	if err != nil {
		return zeroValue, err
	}
	return bestMatch, nil
}

// findCompatibleCapabilitySets returns all capability sets that are compatible with the given machine capabilities.
func findCompatibleCapabilitySets[T HasCapabilities](
	capabilitySets []T, machineCapabilities gardencorev1beta1.Capabilities, capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition,
) []T {
	var compatibleSets []T
	for _, capabilitySet := range capabilitySets {
		if AreCapabilitiesCompatible(capabilitySet.GetCapabilities(), machineCapabilities, capabilitiesDefinitions) {
			compatibleSets = append(compatibleSets, capabilitySet)
		}
	}
	return compatibleSets
}

// selectBestCapabilitySet selects the most appropriate capability set based on the priority
// of capabilities and their values as defined in capabilitiesDefinitions.
//
// Selection follows a priority-based approach:
// 1. Capabilities are ordered by priority in the definitions list (highest priority first)
// 2. Within each capability, values are ordered by preference (most preferred first)
// 3. Selection is determined by the first capability value difference found
func selectBestCapabilitySet[T HasCapabilities](
	compatibleSets []T,
	capabilitiesDefinitions []gardencorev1beta1.CapabilityDefinition,
) (T, error) {
	var zeroValue T
	if len(compatibleSets) == 1 {
		return compatibleSets[0], nil
	}

	// Apply capability defaults for better comparison
	normalizedSets := make([]T, len(compatibleSets))
	copy(normalizedSets, compatibleSets)

	// Normalize capability sets by applying defaults
	for i := range normalizedSets {
		normalizedSets[i].SetCapabilities(gardencorev1beta1helper.GetCapabilitiesWithAppliedDefaults(
			normalizedSets[i].GetCapabilities(),
			capabilitiesDefinitions,
		))
	}

	// Evaluate capability sets based on capability definitions priority
	remainingSets := normalizedSets

	// For each capability (in priority order)
	for _, capabilityDef := range capabilitiesDefinitions {
		// For each preferred value (in preference order)
		for _, capabilityValue := range capabilityDef.Values {
			var setsWithPreferredValue []T

			// Find sets that support this capability value
			for _, set := range remainingSets {
				if slices.Contains(set.GetCapabilities()[capabilityDef.Name], capabilityValue) {
					setsWithPreferredValue = append(setsWithPreferredValue, set)
				}
			}

			// If we found sets with this value, narrow down our selection
			if len(setsWithPreferredValue) > 0 {
				remainingSets = setsWithPreferredValue

				// If only one set remains, we've found our match
				if len(remainingSets) == 1 {
					return remainingSets[0], nil
				}
			}
		}
	}

	// If we couldn't determine a single best match, this indicates a problem with the cloud profile
	if len(remainingSets) != 1 {
		return zeroValue, fmt.Errorf("found multiple capability sets with identical capabilities; this indicates an invalid cloudprofile was admitted. Please open a bug report at https://github.com/gardener/gardener/issues")
	}

	return remainingSets[0], nil
}
