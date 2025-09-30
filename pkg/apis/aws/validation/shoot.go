// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"

	"github.com/gardener/gardener/pkg/apis/core"
	corehelper "github.com/gardener/gardener/pkg/apis/core/helper"
	validationutils "github.com/gardener/gardener/pkg/utils/validation"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

const (
	overlayKey = "overlay"
	enabledKey = "enabled"
)

// ValidateNetworking validates the network settings of a Shoot.
func ValidateNetworking(networking *core.Networking, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if networking.Nodes == nil && (networking.IPFamilies == nil || slices.Contains(networking.IPFamilies, core.IPFamilyIPv4)) {
		allErrs = append(allErrs, field.Required(fldPath.Child("nodes"), "a nodes CIDR must be provided for AWS shoots"))
	}

	if networking.IPFamilies != nil && slices.Contains(networking.IPFamilies, core.IPFamilyIPv6) {
		allErrs = append(allErrs, validateIPv6(networking, fldPath)...)
	}

	return allErrs
}

// ValidateWorker validates a worker of a Shoot.
func ValidateWorker(worker core.Worker, zones []apisaws.Zone, workerConfig *apisaws.WorkerConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	awsZones := sets.New[string]()
	for _, awsZone := range zones {
		awsZones.Insert(awsZone.Name)
	}

	if worker.Volume == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("volume"), "must not be nil"))
	} else {
		allErrs = append(allErrs, validateVolume(worker.Volume, fldPath.Child("volume"))...)

		if worker.Volume.Type != nil && *worker.Volume.Type == string(apisaws.VolumeTypeIO1) && worker.ProviderConfig == nil {
			allErrs = append(allErrs, field.Required(fldPath.Child("providerConfig"), fmt.Sprintf("WorkerConfig must be set if volume type is %s", apisaws.VolumeTypeIO1)))
		}

		if length := len(worker.DataVolumes); length > 11 {
			allErrs = append(allErrs, field.TooMany(fldPath.Child("dataVolumes"), length, 11))
		}

		for j, volume := range worker.DataVolumes {
			dataVolPath := fldPath.Child("dataVolumes").Index(j)

			allErrs = append(allErrs, validateDataVolume(volume.DeepCopy(), dataVolPath)...)

			if volume.Type != nil && *volume.Type == string(apisaws.VolumeTypeIO1) && worker.ProviderConfig == nil {
				allErrs = append(allErrs, field.Required(fldPath.Child("providerConfig"), fmt.Sprintf("WorkerConfig must be set if data volume type is %s (%s)", apisaws.VolumeTypeIO1, dataVolPath.Child("type"))))
			}
		}
	}

	if len(worker.Zones) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("zones"), "at least one zone must be configured"))
	} else {
		allErrs = append(allErrs, validateZones(worker.Zones, awsZones, fldPath.Child("zones"))...)
	}

	if workerConfig != nil {
		allErrs = append(allErrs, ValidateWorkerConfig(workerConfig, worker.Volume, worker.DataVolumes, fldPath.Child("providerConfig"))...)
	}

	return allErrs
}

// ValidateWorkersUpdate validates updates on `workers`
func ValidateWorkersUpdate(oldWorkers, newWorkers []core.Worker, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	for i, newWorker := range newWorkers {
		for _, oldWorker := range oldWorkers {
			if newWorker.Name == oldWorker.Name {
				if validationutils.ShouldEnforceImmutability(newWorker.Zones, oldWorker.Zones) {
					allErrs = append(allErrs, apivalidation.ValidateImmutableField(newWorker.Zones, oldWorker.Zones, fldPath.Index(i).Child("zones"))...)
				}

				// Changing these fields will cause a change in the calculation of the WorkerPool hash. Currently machine-controller-manager does not provide an UpdateMachine call to update the
				// data volumes or provider config in-place. gardener-node-agent cannot update the provider config in-place either. So we disallow changing these fields if the update strategy is in-place.
				if corehelper.IsUpdateStrategyInPlace(newWorker.UpdateStrategy) {
					if !apiequality.Semantic.DeepEqual(newWorker.ProviderConfig, oldWorker.ProviderConfig) {
						allErrs = append(allErrs, field.Invalid(fldPath.Index(i).Child("providerConfig"), newWorker.ProviderConfig, "providerConfig is immutable when update strategy is in-place"))
					}

					if !apiequality.Semantic.DeepEqual(newWorker.DataVolumes, oldWorker.DataVolumes) {
						allErrs = append(allErrs, field.Invalid(fldPath.Index(i).Child("dataVolumes"), newWorker.DataVolumes, "dataVolumes are immutable when update strategy is in-place"))
					}
				}

				break
			}
		}
	}
	return allErrs
}

func validateZones(zones []string, allowedZones sets.Set[string], fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	for i, workerZone := range zones {
		if !allowedZones.Has(workerZone) {
			allErrs = append(allErrs, field.Invalid(fldPath.Index(i), workerZone, fmt.Sprintf("supported values %v", allowedZones.UnsortedList())))
		}
	}
	if len(zones) > math.MaxInt32 {
		allErrs = append(allErrs, field.Invalid(fldPath, len(zones), "too many zones"))
	}
	return allErrs
}

func validateVolume(vol *core.Volume, fldPath *field.Path) field.ErrorList {
	return validateVolumeFunc(vol.VolumeSize, vol.Type, fldPath)
}

func validateDataVolume(vol *core.DataVolume, fldPath *field.Path) field.ErrorList {
	return validateVolumeFunc(vol.VolumeSize, vol.Type, fldPath)
}

func validateVolumeFunc(size string, volumeType *string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if size == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("size"), "must not be empty"))
	}
	if volumeType == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("type"), "must not be empty"))
	}
	return allErrs
}

func decodeNetworkConfig(network *runtime.RawExtension) (map[string]interface{}, error) {
	var networkConfig map[string]interface{}
	if network == nil || network.Raw == nil {
		return map[string]interface{}{}, nil
	}
	if err := json.Unmarshal(network.Raw, &networkConfig); err != nil {
		return nil, err
	}
	return networkConfig, nil
}

func validateIPv6(networking *core.Networking, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	networkConfig, err := decodeNetworkConfig(networking.ProviderConfig)
	if err != nil {
		return append(allErrs, field.Invalid(fldPath.Child("providerConfig"), networking.ProviderConfig, fmt.Sprintf("failed to decode networking provider config: %v", err)))
	}

	if _, ok := networkConfig[overlayKey]; ok {
		if overlay, ok := networkConfig[overlayKey].(map[string]interface{}); ok {
			if enabled, ok := overlay[enabledKey].(bool); ok && enabled {
				allErrs = append(allErrs, field.Invalid(fldPath.Child("providerConfig").Child(overlayKey).Child(enabledKey), enabled, "overlay must be set to false in conjunction with IPv6"))
			}
		}
	} else {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("ipFamilies"), networking.IPFamilies, "overlay must be set to false in conjunction with IPv6"))
	}

	return allErrs
}
