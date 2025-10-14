// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"github.com/gardener/gardener/pkg/utils"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

// NewNamespacedCloudProfileMutator returns a new instance of a NamespacedCloudProfile mutator.
func NewNamespacedCloudProfileMutator(mgr manager.Manager) extensionswebhook.Mutator {
	return &namespacedCloudProfile{
		client:  mgr.GetClient(),
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
	}
}

type namespacedCloudProfile struct {
	client  client.Client
	decoder runtime.Decoder
}

// Mutate mutates the given NamespacedCloudProfile object.
func (p *namespacedCloudProfile) Mutate(_ context.Context, newObj, _ client.Object) error {
	profile, ok := newObj.(*gardencorev1beta1.NamespacedCloudProfile)
	if !ok {
		return fmt.Errorf("wrong object type %T", newObj)
	}

	if shouldSkipMutation(profile) {
		return nil
	}

	specConfig, statusConfig, err := p.decodeConfigs(profile)
	if err != nil {
		return err
	}

	uniformSpecConfig := TransformProviderConfigToParentFormat(specConfig, profile.Status.CloudProfileSpec.MachineCapabilities)
	statusConfig.MachineImages = mergeMachineImages(uniformSpecConfig.MachineImages, statusConfig.MachineImages)

	return p.updateProfileStatus(profile, statusConfig)
}

func shouldSkipMutation(profile *gardencorev1beta1.NamespacedCloudProfile) bool {
	return profile.DeletionTimestamp != nil ||
		profile.Generation != profile.Status.ObservedGeneration ||
		profile.Spec.ProviderConfig == nil ||
		profile.Status.CloudProfileSpec.ProviderConfig == nil
}

func (p *namespacedCloudProfile) decodeConfigs(profile *gardencorev1beta1.NamespacedCloudProfile) (*v1alpha1.CloudProfileConfig, *v1alpha1.CloudProfileConfig, error) {
	specConfig := &v1alpha1.CloudProfileConfig{}
	statusConfig := &v1alpha1.CloudProfileConfig{}

	if err := p.decodeProviderConfig(profile.Spec.ProviderConfig.Raw, specConfig, "spec"); err != nil {
		return nil, nil, err
	}
	if err := p.decodeProviderConfig(profile.Status.CloudProfileSpec.ProviderConfig.Raw, statusConfig, "status"); err != nil {
		return nil, nil, err
	}

	return specConfig, statusConfig, nil
}

func (p *namespacedCloudProfile) decodeProviderConfig(raw []byte, into *v1alpha1.CloudProfileConfig, configType string) error {
	if _, _, err := p.decoder.Decode(raw, nil, into); err != nil {
		return fmt.Errorf("could not decode providerConfig of %s: %w", configType, err)
	}
	return nil
}

func (p *namespacedCloudProfile) updateProfileStatus(profile *gardencorev1beta1.NamespacedCloudProfile, config *v1alpha1.CloudProfileConfig) error {
	modifiedStatusConfig, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal status config: %w", err)
	}
	profile.Status.CloudProfileSpec.ProviderConfig.Raw = modifiedStatusConfig
	return nil
}

// TransformProviderConfigToParentFormat supports the migration from the deprecated architecture fields to architecture capabilities.
// Depending on whether the parent CloudProfile is in capability format or not, it transforms the given config to
// the capability format or the deprecated architecture fields format respectively.
// It assumes that the given config is either completely in the capability format or in the deprecated architecture fields format.
func TransformProviderConfigToParentFormat(config *v1alpha1.CloudProfileConfig, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) *v1alpha1.CloudProfileConfig {
	if config == nil {
		return &v1alpha1.CloudProfileConfig{}
	}

	transformedConfig := v1alpha1.CloudProfileConfig{
		TypeMeta:      config.TypeMeta,
		MachineImages: transformMachineImages(config.MachineImages, capabilityDefinitions),
	}

	return &transformedConfig
}

func transformMachineImages(images []v1alpha1.MachineImages, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) []v1alpha1.MachineImages {
	isParentInCapabilityFormat := len(capabilityDefinitions) != 0
	result := make([]v1alpha1.MachineImages, 0, len(images))

	for _, img := range images {
		transformedVersions := transformImageVersions(img.Versions, isParentInCapabilityFormat, capabilityDefinitions)
		result = append(result, v1alpha1.MachineImages{
			Name:     img.Name,
			Versions: transformedVersions,
		})
	}

	return result
}

func transformImageVersions(versions []v1alpha1.MachineImageVersion, useCapabilityFormat bool, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) []v1alpha1.MachineImageVersion {
	result := make([]v1alpha1.MachineImageVersion, 0, len(versions))

	for _, version := range versions {
		transformed := v1alpha1.MachineImageVersion{Version: version.Version}
		if useCapabilityFormat {
			transformed.CapabilityFlavors = transformToCapabilityFormat(version, capabilityDefinitions)
		} else {
			transformed.Regions = transformToLegacyFormat(version, capabilityDefinitions)
		}
		result = append(result, transformed)
	}

	return result
}

// sortRegions sorts a slice of RegionAMIMapping by name
func sortRegions(regions []v1alpha1.RegionAMIMapping) {
	slices.SortFunc(regions, func(a, b v1alpha1.RegionAMIMapping) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
}

// transformToCapabilityFormat converts legacy format (regions with architecture) to capability format
func transformToCapabilityFormat(version v1alpha1.MachineImageVersion, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) []v1alpha1.MachineImageFlavor {
	if len(version.CapabilityFlavors) > 0 {
		// Already in capability format, return as-is
		return version.CapabilityFlavors
	}

	if len(version.Regions) == 0 {
		return nil
	}

	// Group regions by architecture
	architectureGroups := make(map[string][]v1alpha1.RegionAMIMapping)

	for _, region := range version.Regions {
		// Default to "amd64" if architecture is not specified (backward compatibility)
		arch := v1beta1constants.ArchitectureAMD64
		if ptr.Deref(region.Architecture, "") != "" {
			arch = *region.Architecture
		}

		// Create a clean region mapping without architecture field for capability format
		cleanRegion := v1alpha1.RegionAMIMapping{
			Name: region.Name,
			AMI:  region.AMI,
			// Architecture field is omitted in capability format
		}

		architectureGroups[arch] = append(architectureGroups[arch], cleanRegion)
	}

	// Convert groups to capability flavors
	var imageFlavors []v1alpha1.MachineImageFlavor
	for arch, regions := range architectureGroups {
		sortRegions(regions)
		flavor := v1alpha1.MachineImageFlavor{
			Regions: regions,
			Capabilities: gardencorev1beta1.Capabilities{
				"architecture": []string{arch},
			},
		}
		imageFlavors = append(imageFlavors, flavor)
	}

	// Sort flavors for consistent output (alphabetically by architecture)\
	slices.SortFunc(imageFlavors, func(a, b v1alpha1.MachineImageFlavor) int {
		archA := getFirstArchitecture(a.Capabilities, capabilityDefinitions)
		archB := getFirstArchitecture(b.Capabilities, capabilityDefinitions)

		if archA < archB {
			return -1
		}
		if archA > archB {
			return 1
		}
		return 0
	})

	return imageFlavors
}

// transformToLegacyFormat converts capability format to legacy format (regions with architecture)
func transformToLegacyFormat(version v1alpha1.MachineImageVersion, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) []v1alpha1.RegionAMIMapping {
	if len(version.Regions) > 0 {
		// Already in legacy format, return as-is
		return version.Regions
	}

	if len(version.CapabilityFlavors) == 0 {
		return nil
	}

	var allRegions []v1alpha1.RegionAMIMapping

	for _, flavor := range version.CapabilityFlavors {
		// Extract architecture from capabilities
		arch := getFirstArchitecture(flavor.Capabilities, capabilityDefinitions)

		// Add architecture field to each region
		for _, region := range flavor.Regions {
			legacyRegion := v1alpha1.RegionAMIMapping{
				Name:         region.Name,
				AMI:          region.AMI,
				Architecture: &arch,
			}
			allRegions = append(allRegions, legacyRegion)
		}
	}

	// Sort regions by name for consistent output
	sortRegions(allRegions)

	return allRegions
}

// getFirstArchitecture extracts the first architecture from capabilities, defaults to "amd64"
func getFirstArchitecture(capabilities gardencorev1beta1.Capabilities, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) string {
	defaultedCapabilities := capabilities
	if len(capabilityDefinitions) > 0 {
		defaultedCapabilities = gardencorev1beta1helper.GetCapabilitiesWithAppliedDefaults(capabilities, capabilityDefinitions)
	}

	if defaultedCapabilities == nil {
		return v1beta1constants.ArchitectureAMD64
	}

	archList, exists := defaultedCapabilities["architecture"]
	if !exists || len(archList) == 0 {
		return v1beta1constants.ArchitectureAMD64
	}

	return archList[0]
}

func mergeMachineImages(specMachineImages, statusMachineImages []v1alpha1.MachineImages) []v1alpha1.MachineImages {
	specImages := utils.CreateMapFromSlice(specMachineImages, func(mi v1alpha1.MachineImages) string { return mi.Name })
	statusImages := utils.CreateMapFromSlice(statusMachineImages, func(mi v1alpha1.MachineImages) string { return mi.Name })
	for _, specMachineImage := range specImages {
		if _, exists := statusImages[specMachineImage.Name]; !exists {
			statusImages[specMachineImage.Name] = specMachineImage
		} else {
			statusImageVersions := utils.CreateMapFromSlice(statusImages[specMachineImage.Name].Versions, func(v v1alpha1.MachineImageVersion) string { return v.Version })
			specImageVersions := utils.CreateMapFromSlice(specImages[specMachineImage.Name].Versions, func(v v1alpha1.MachineImageVersion) string { return v.Version })
			for _, version := range specImageVersions {
				statusImageVersions[version.Version] = version
			}

			statusImages[specMachineImage.Name] = v1alpha1.MachineImages{
				Name:     specMachineImage.Name,
				Versions: slices.Collect(maps.Values(statusImageVersions)),
			}
		}
	}
	return slices.Collect(maps.Values(statusImages))
}
