// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator

import (
	"context"
	"fmt"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

// NewCloudProfileMutator returns a new instance of a CloudProfile mutator.
func NewCloudProfileMutator(mgr manager.Manager) extensionswebhook.Mutator {
	return &cloudProfile{
		client:  mgr.GetClient(),
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
	}
}

type cloudProfile struct {
	client  client.Client
	decoder runtime.Decoder
}

// Mutate mutates the given CloudProfile object.
func (p *cloudProfile) Mutate(_ context.Context, newObj, _ client.Object) error {
	profile, ok := newObj.(*gardencorev1beta1.CloudProfile)
	if !ok {
		return fmt.Errorf("wrong object type %T", newObj)
	}

	// Skip mutation if CloudProfile is being deleted or when no capabilities used in that profile
	if profile.DeletionTimestamp != nil || profile.Spec.ProviderConfig == nil || len(profile.Spec.MachineCapabilities) == 0 {
		return nil
	}

	specConfig := &v1alpha1.CloudProfileConfig{}
	if _, _, err := p.decoder.Decode(profile.Spec.ProviderConfig.Raw, nil, specConfig); err != nil {
		return fmt.Errorf("could not decode providerConfig of cloudProfile for '%s': %w", profile.Name, err)
	}

	overwriteMachineImageCapabilityFlavors(profile, specConfig)
	return nil
}

// overwriteMachineImageCapabilityFlavors updates the capability flavors of machine images in the CloudProfile
func overwriteMachineImageCapabilityFlavors(profile *gardencorev1beta1.CloudProfile, config *v1alpha1.CloudProfileConfig) {
	for _, providerMachineImage := range config.MachineImages {
		// Find the corresponding machine image in the CloudProfile
		imageIdx := slices.IndexFunc(profile.Spec.MachineImages, func(mi gardencorev1beta1.MachineImage) bool {
			return mi.Name == providerMachineImage.Name
		})
		if imageIdx == -1 {
			continue
		}

		// Iterate over versions in the provider's machine image
		for _, providerVersion := range providerMachineImage.Versions {
			// Find the corresponding version in the CloudProfile's machine image
			versionIdx := slices.IndexFunc(profile.Spec.MachineImages[imageIdx].Versions, func(miv gardencorev1beta1.MachineImageVersion) bool {
				return miv.Version == providerVersion.Version
			})
			if versionIdx == -1 {
				continue
			}

			// Support both new format (capabilityFlavors) and old format (regions with architecture)
			if len(providerVersion.CapabilityFlavors) > 0 {
				// New format: use capabilityFlavors directly
				profile.Spec.MachineImages[imageIdx].Versions[versionIdx].CapabilityFlavors = convertCapabilityFlavors(providerVersion.CapabilityFlavors)
			} else if len(providerVersion.Regions) > 0 {
				// Old format: convert regions with architecture to capability flavors
				profile.Spec.MachineImages[imageIdx].Versions[versionIdx].CapabilityFlavors = convertRegionsToCapabilityFlavors(providerVersion.Regions)
			}
		}
	}
}

// convertCapabilityFlavors converts provider capability flavors to CloudProfile capability flavors
func convertCapabilityFlavors(providerFlavors []v1alpha1.MachineImageFlavor) []gardencorev1beta1.MachineImageFlavor {
	capabilityFlavors := make([]gardencorev1beta1.MachineImageFlavor, 0, len(providerFlavors))
	for _, providerFlavor := range providerFlavors {
		capabilityFlavors = append(capabilityFlavors, gardencorev1beta1.MachineImageFlavor{
			Capabilities: providerFlavor.GetCapabilities(),
		})
	}
	return capabilityFlavors
}

// convertRegionsToCapabilityFlavors converts old format (regions with architecture) to capability flavors
func convertRegionsToCapabilityFlavors(regions []v1alpha1.RegionAMIMapping) []gardencorev1beta1.MachineImageFlavor {
	// Group regions by architecture to create capability flavors
	architectureSet := make(map[string]struct{})
	for _, region := range regions {
		arch := "amd64" // default architecture
		if region.Architecture != nil {
			arch = *region.Architecture
		}
		architectureSet[arch] = struct{}{}
	}

	// Create a capability flavor for each unique architecture
	capabilityFlavors := make([]gardencorev1beta1.MachineImageFlavor, 0, len(architectureSet))
	for arch := range architectureSet {
		capabilityFlavors = append(capabilityFlavors, gardencorev1beta1.MachineImageFlavor{
			Capabilities: gardencorev1beta1.Capabilities{
				"architecture": []string{arch},
			},
		})
	}

	// Sort for deterministic output
	slices.SortFunc(capabilityFlavors, func(a, b gardencorev1beta1.MachineImageFlavor) int {
		aArch := ""
		bArch := ""
		if archList, ok := a.Capabilities["architecture"]; ok && len(archList) > 0 {
			aArch = archList[0]
		}
		if archList, ok := b.Capabilities["architecture"]; ok && len(archList) > 0 {
			bArch = archList[0]
		}
		if aArch < bArch {
			return -1
		}
		if aArch > bArch {
			return 1
		}
		return 0
	})

	return capabilityFlavors
}
