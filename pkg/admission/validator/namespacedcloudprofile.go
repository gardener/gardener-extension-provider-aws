// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencoreapi "github.com/gardener/gardener/pkg/api"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorehelper "github.com/gardener/gardener/pkg/apis/core/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

// NewNamespacedCloudProfileValidator returns a new instance of a namespaced cloud profile validator.
func NewNamespacedCloudProfileValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &namespacedCloudProfile{
		client:  mgr.GetClient(),
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
	}
}

type namespacedCloudProfile struct {
	client  client.Client
	decoder runtime.Decoder
}

// Validate validates the given NamespacedCloudProfile objects.
func (p *namespacedCloudProfile) Validate(ctx context.Context, newObj, _ client.Object) error {
	profile, ok := newObj.(*core.NamespacedCloudProfile)
	if !ok {
		return fmt.Errorf("wrong object type %T", newObj)
	}

	if profile.DeletionTimestamp != nil {
		return nil
	}

	cpConfig := &api.CloudProfileConfig{}
	if profile.Spec.ProviderConfig != nil {
		var err error
		cpConfig, err = decodeCloudProfileConfig(p.decoder, profile.Spec.ProviderConfig)
		if err != nil {
			return err
		}
	}

	parentCloudProfile := profile.Spec.Parent
	if parentCloudProfile.Kind != constants.CloudProfileReferenceKindCloudProfile {
		return fmt.Errorf("parent reference must be of kind CloudProfile (unsupported kind: %s)", parentCloudProfile.Kind)
	}
	parentProfile := &gardencorev1beta1.CloudProfile{}
	if err := p.client.Get(ctx, client.ObjectKey{Name: parentCloudProfile.Name}, parentProfile); err != nil {
		return err
	}

	return p.validateNamespacedCloudProfileProviderConfig(cpConfig, profile.Spec, parentProfile.Spec).ToAggregate()
}

// validateNamespacedCloudProfileProviderConfig validates the CloudProfileConfig passed with a NamespacedCloudProfile.
func (p *namespacedCloudProfile) validateNamespacedCloudProfileProviderConfig(providerConfig *api.CloudProfileConfig, profileSpec core.NamespacedCloudProfileSpec, parentSpec gardencorev1beta1.CloudProfileSpec) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, p.validateMachineImages(providerConfig, profileSpec.MachineImages, parentSpec)...)

	return allErrs
}

func (p *namespacedCloudProfile) validateMachineImages(providerConfig *api.CloudProfileConfig, machineImages []core.MachineImage, parentSpec gardencorev1beta1.CloudProfileSpec) field.ErrorList {
	allErrs := field.ErrorList{}

	var parentCloudProfileSpecCore core.CloudProfileSpec
	if err := gardencoreapi.Scheme.Convert(&parentSpec, &parentCloudProfileSpecCore, nil); err != nil {
		return append(allErrs, field.InternalError(field.NewPath(""), err))
	}

	capabilitiesDefinitions := parentCloudProfileSpecCore.Capabilities

	machineImagesPath := field.NewPath("spec.providerConfig.machineImages")
	for i, machineImage := range providerConfig.MachineImages {
		idxPath := machineImagesPath.Index(i)
		allErrs = append(allErrs, validation.ValidateProviderMachineImage(idxPath, machineImage, parentCloudProfileSpecCore.Capabilities)...)
	}

	profileImages := gutil.NewCoreImagesContext(machineImages)
	parentImages := gutil.NewV1beta1ImagesContext(parentSpec.MachineImages)
	providerImages := validation.NewProviderImagesContext(providerConfig.MachineImages)

	for _, machineImage := range profileImages.Images {
		// Check that for each new image version defined in the NamespacedCloudProfile, the image is also defined in the providerConfig.
		_, existsInParent := parentImages.GetImage(machineImage.Name)
		if _, existsInProvider := providerImages.GetImage(machineImage.Name); !existsInParent && !existsInProvider {
			allErrs = append(allErrs, field.Required(machineImagesPath,
				fmt.Sprintf("machine image %s is not defined in the NamespacedCloudProfile providerConfig", machineImage.Name),
			))
			continue
		}
		for _, version := range machineImage.Versions {
			_, existsInParent := parentImages.GetImageVersion(machineImage.Name, version.Version)
			providerImageVersion, exists := providerImages.GetImageVersion(machineImage.Name, version.Version)
			if !existsInParent && !exists {
				allErrs = append(allErrs, field.Required(machineImagesPath,
					fmt.Sprintf("machine image version %s@%s is not defined in the NamespacedCloudProfile providerConfig", machineImage.Name, version.Version),
				))
				// no need to check the capabilities and architectures if the version is not defined in the providerConfig
				continue
			}

			if len(capabilitiesDefinitions) == 0 {
				allErrs = append(allErrs, validateMachineImageArchitectures(machineImage, version, providerImageVersion)...)
			} else {
				allErrs = append(allErrs, validateMachineImageCapabilities(machineImage, version, providerImageVersion, capabilitiesDefinitions)...)
			}
		}
	}
	for imageIdx, machineImage := range providerConfig.MachineImages {
		// Check that the machine image version is not already defined in the parent CloudProfile.
		if _, exists := parentImages.GetImage(machineImage.Name); exists {
			for versionIdx, version := range machineImage.Versions {
				if _, exists := parentImages.GetImageVersion(machineImage.Name, version.Version); exists {
					allErrs = append(allErrs, field.Forbidden(
						field.NewPath("spec.providerConfig.machineImages").Index(imageIdx).Child("versions").Index(versionIdx),
						fmt.Sprintf("machine image version %s@%s is already defined in the parent CloudProfile", machineImage.Name, version.Version),
					))
				}
			}
		}
		// Check that the machine image version is defined in the NamespacedCloudProfile.
		if _, exists := profileImages.GetImage(machineImage.Name); !exists {
			allErrs = append(allErrs, field.Required(
				field.NewPath("spec.providerConfig.machineImages").Index(imageIdx),
				fmt.Sprintf("machine image %s is not defined in the NamespacedCloudProfile .spec.machineImages", machineImage.Name),
			))
			continue
		}
		for versionIdx, version := range machineImage.Versions {
			if _, exists := profileImages.GetImageVersion(machineImage.Name, version.Version); !exists {
				allErrs = append(allErrs, field.Invalid(
					field.NewPath("spec.providerConfig.machineImages").Index(imageIdx).Child("versions").Index(versionIdx),
					fmt.Sprintf("%s@%s", machineImage.Name, version.Version),
					"machine image version is not defined in the NamespacedCloudProfile",
				))
			}
		}
	}

	return allErrs
}

func validateMachineImageCapabilities(machineImage core.MachineImage, version core.MachineImageVersion, providerImageVersion api.MachineImageVersion, capabilitiesDefinition []core.CapabilityDefinition) field.ErrorList {
	allErrs := field.ErrorList{}
	path := field.NewPath("spec.providerConfig.machineImages")
	coreDefaultedCapabilitySets := gardencorehelper.GetCapabilitySetsWithAppliedDefaults(version.CapabilitySets, capabilitiesDefinition)
	regionsCapabilitiesMap := map[string][]core.Capabilities{}

	// 1. Create an error for each capabilitySet in the providerConfig that is not defined in the core machine image version
	for _, capabilitySet := range providerImageVersion.CapabilitySets {
		isFound := false
		for _, coreDefaultedCapabilitySet := range coreDefaultedCapabilitySets {
			defaultedProviderCapabilities := gardencorehelper.GetCapabilitiesWithAppliedDefaults(capabilitySet.Capabilities, capabilitiesDefinition)
			if gutil.AreCapabilitiesEqual(coreDefaultedCapabilitySet.Capabilities, defaultedProviderCapabilities) {
				isFound = true
			}
		}
		if !isFound {
			allErrs = append(allErrs, field.Forbidden(path,
				fmt.Sprintf("machine image version %s@%s has an excess capabilitySet %v, which is not defined in the machineImages spec",
					machineImage.Name, version.Version, capabilitySet.Capabilities)))
		}

		for _, regionMapping := range capabilitySet.Regions {
			regionsCapabilitiesMap[regionMapping.Name] = append(regionsCapabilitiesMap[regionMapping.Name], capabilitySet.Capabilities)
		}
	}

	// 2. Create an error for each capabilitySet in the core machine image version that is not defined in the providerConfig
	for _, coreDefaultedCapabilitySet := range coreDefaultedCapabilitySets {
		isFound := false
		for _, capabilitySet := range providerImageVersion.CapabilitySets {
			defaultedProviderCapabilities := gardencorehelper.GetCapabilitiesWithAppliedDefaults(capabilitySet.Capabilities, capabilitiesDefinition)
			if gutil.AreCapabilitiesEqual(coreDefaultedCapabilitySet.Capabilities, defaultedProviderCapabilities) {
				isFound = true
			}
		}
		if !isFound {
			allErrs = append(allErrs, field.Required(path,
				fmt.Sprintf("machine image version %s@%s has a capabilitySet %v not defined in the NamespacedCloudProfile providerConfig",
					machineImage.Name, version.Version, coreDefaultedCapabilitySet.Capabilities)))
			// no need to check the regions if the capabilitySet is not defined in the providerConfig
			continue
		}

		// 3. Create an error for each region that is not part of every capabilitySet
		for region, regionCapabilities := range regionsCapabilitiesMap {
			isFound := false
			for _, capabilities := range regionCapabilities {
				regionDefaultedCapabilities := gardencorehelper.GetCapabilitiesWithAppliedDefaults(capabilities, capabilitiesDefinition)
				if gutil.AreCapabilitiesEqual(regionDefaultedCapabilities, coreDefaultedCapabilitySet.Capabilities) {
					isFound = true
				}
			}
			if !isFound {
				allErrs = append(allErrs, field.Required(path,
					fmt.Sprintf("machine image version %s@%s is missing region %q in capabilitySet %v in the NamespacedCloudProfile providerConfig",
						machineImage.Name, version.Version, region, coreDefaultedCapabilitySet.Capabilities)))
			}
		}
	}

	return allErrs
}

func validateMachineImageArchitectures(machineImage core.MachineImage, version core.MachineImageVersion, providerImageVersion api.MachineImageVersion) field.ErrorList {
	allErrs := field.ErrorList{}
	regionsArchitectureMap := map[string][]string{}

	for _, regionMapping := range providerImageVersion.Regions {
		providerConfigArchitecture := ptr.Deref(regionMapping.Architecture, constants.ArchitectureAMD64)
		if !slices.Contains(version.Architectures, providerConfigArchitecture) {
			allErrs = append(allErrs, field.Forbidden(
				field.NewPath("spec.providerConfig.machineImages"),
				fmt.Sprintf("machine image version %s@%s in region %q has an excess entry for architecture %q, which is not defined in the machineImages spec",
					machineImage.Name, version.Version, regionMapping.Name, providerConfigArchitecture),
			))
		}
		regionsArchitectureMap[regionMapping.Name] = append(regionsArchitectureMap[regionMapping.Name], providerConfigArchitecture)
	}

	for _, expectedArchitecture := range version.Architectures {
		if len(regionsArchitectureMap) == 0 {
			allErrs = append(allErrs, field.Required(
				field.NewPath("spec.providerConfig.machineImages"),
				fmt.Sprintf("machine image version %s@%s with architecture %q is not defined in the NamespacedCloudProfile providerConfig",
					machineImage.Name, version.Version, expectedArchitecture),
			))
		}
		for region, architectures := range regionsArchitectureMap {
			if !slices.Contains(architectures, expectedArchitecture) {
				allErrs = append(allErrs, field.Required(
					field.NewPath("spec.providerConfig.machineImages"),
					fmt.Sprintf("machine image version %s@%s for region %q with architecture %q is not defined in the NamespacedCloudProfile providerConfig",
						machineImage.Name, version.Version, region, expectedArchitecture),
				))
			}
		}
	}

	return allErrs
}
