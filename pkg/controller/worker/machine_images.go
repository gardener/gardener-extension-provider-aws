// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/controller/worker"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
)

// UpdateMachineImagesStatus implements genericactuator.WorkerDelegate.
func (w *WorkerDelegate) UpdateMachineImagesStatus(ctx context.Context) error {
	if w.machineImages == nil {
		if err := w.generateMachineConfig(ctx); err != nil {
			return fmt.Errorf("unable to generate the machine config: %w", err)
		}
	}

	// Decode the current worker provider status.
	workerStatus, err := w.decodeWorkerProviderStatus()
	if err != nil {
		return fmt.Errorf("unable to decode the worker provider status: %w", err)
	}

	workerStatus.MachineImages = w.machineImages
	if err := w.updateWorkerProviderStatus(ctx, workerStatus); err != nil {
		return fmt.Errorf("unable to update worker provider status: %w", err)
	}

	return nil
}

func (w *WorkerDelegate) selectMachineImageForWorkerPool(name, version string, region string, arch *string, machineCapabilities gardencorev1beta1.Capabilities) (*api.MachineImage, error) {
	selectedMachineImage := &api.MachineImage{
		Name:    name,
		Version: version,
	}

	if capabilitySet, err := helper.FindImageInCloudProfile(w.cloudProfileConfig, name, version, region, arch, machineCapabilities, w.cluster.CloudProfile.Spec.MachineCapabilities); err == nil {
		selectedMachineImage.Capabilities = capabilitySet.Capabilities
		selectedMachineImage.AMI = capabilitySet.Regions[0].AMI
		selectedMachineImage.Architecture = capabilitySet.Regions[0].Architecture
		return selectedMachineImage, nil
	}

	// Try to look up machine image in worker provider status as it was not found in componentconfig.
	if providerStatus := w.worker.Status.ProviderStatus; providerStatus != nil {
		workerStatus := &api.WorkerStatus{}
		if _, _, err := w.decoder.Decode(providerStatus.Raw, nil, workerStatus); err != nil {
			return nil, fmt.Errorf("could not decode worker status of worker '%s': %w", k8sclient.ObjectKeyFromObject(w.worker), err)
		}

		return helper.FindImageInWorkerStatus(workerStatus.MachineImages, name, version, arch, machineCapabilities, w.cluster.CloudProfile.Spec.MachineCapabilities)
	}

	return nil, worker.ErrorMachineImageNotFound(name, version, *arch, region)
}

func appendMachineImage(machineImages []api.MachineImage, machineImage api.MachineImage, capabilityDefinitions []gardencorev1beta1.CapabilityDefinition) []api.MachineImage {
	// support for cloudprofile machine images without capabilities
	if len(capabilityDefinitions) == 0 {
		for _, image := range machineImages {
			if image.Name == machineImage.Name && image.Version == machineImage.Version && machineImage.Architecture == image.Architecture {
				// If the image already exists without capabilities, we can just return the existing list.
				return machineImages
			}
		}
		return append(machineImages, api.MachineImage{
			Name:         machineImage.Name,
			Version:      machineImage.Version,
			AMI:          machineImage.AMI,
			Architecture: machineImage.Architecture,
		})
	}

	defaultedCapabilities := gardencorev1beta1helper.GetCapabilitiesWithAppliedDefaults(machineImage.Capabilities, capabilityDefinitions)

	for _, existingMachineImage := range machineImages {
		existingDefaultedCapabilities := gardencorev1beta1helper.GetCapabilitiesWithAppliedDefaults(existingMachineImage.Capabilities, capabilityDefinitions)
		if existingMachineImage.Name == machineImage.Name && existingMachineImage.Version == machineImage.Version && gardencorev1beta1helper.AreCapabilitiesEqual(defaultedCapabilities, existingDefaultedCapabilities) {
			// If the image already exists with the same capabilities return the existing list.
			return machineImages
		}
	}

	// If the image does not exist, we create a new machine image entry with the capabilities.
	machineImages = append(machineImages, api.MachineImage{
		Name:         machineImage.Name,
		Version:      machineImage.Version,
		AMI:          machineImage.AMI,
		Capabilities: machineImage.Capabilities,
	})

	return machineImages
}
