// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/apis/core"
	validationutils "github.com/gardener/gardener/pkg/utils/validation"
	"github.com/go-test/deep"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	workercontroller "github.com/gardener/gardener-extension-provider-aws/pkg/controller/worker"
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
		networkConfig, err := decodeNetworkConfig(networking.ProviderConfig)
		if err != nil {
			return append(allErrs, field.Invalid(fldPath.Child("providerConfig"), networking.ProviderConfig, fmt.Sprintf("failed to decode networking provider config: %v", err)))
		}

		if _, ok := networkConfig[overlayKey]; ok {
			if overlay, ok := networkConfig[overlayKey].(map[string]interface{}); ok {
				if enabled, ok := overlay[enabledKey].(bool); ok && enabled {
					allErrs = append(allErrs, field.Invalid(fldPath.Child("providerConfig").Child(overlayKey).Child(enabledKey), enabled, "overlay is not supported in conjunction with IPv6"))
				}
			}
		}
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
func ValidateWorkersUpdate(decoder runtime.Decoder, oldWorkers, newWorkers []core.Worker, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	for i, newWorker := range newWorkers {
		for j, oldWorker := range oldWorkers {
			if newWorker.Name == oldWorker.Name {
				if validationutils.ShouldEnforceImmutability(newWorker.Zones, oldWorker.Zones) {
					allErrs = append(allErrs, apivalidation.ValidateImmutableField(newWorker.Zones, oldWorker.Zones, fldPath.Index(i).Child("zones"))...)
				}

				if sets.New(core.AutoInPlaceUpdate, core.ManualInPlaceUpdate).Has(ptr.Deref(newWorker.UpdateStrategy, "")) {
					decodingErrors := field.ErrorList{}

					oldWorkerConfig := &apisaws.WorkerConfig{}
					if err := util.Decode(decoder, oldWorker.ProviderConfig.Raw, oldWorkerConfig); err != nil {
						decodingErrors = append(decodingErrors, field.Invalid(fldPath.Index(j).Child("providerConfig"), string(oldWorker.ProviderConfig.Raw), fmt.Sprintf("could not decode old provider config: %v", err)))
					}

					newWorkerConfig := &apisaws.WorkerConfig{}
					if err := util.Decode(decoder, newWorker.ProviderConfig.Raw, newWorkerConfig); err != nil {
						decodingErrors = append(decodingErrors, field.Invalid(fldPath.Index(i).Child("providerConfig"), string(newWorker.ProviderConfig.Raw), fmt.Sprintf("could not decode new provider config: %v", err)))
					}

					if len(decodingErrors) > 0 {
						// No need to validate further
						allErrs = append(allErrs, decodingErrors...)
					} else {
						allErrs = append(allErrs, validateWorkerConfigImmutability(oldWorkerConfig, newWorkerConfig, fldPath.Index(i).Child("providerConfig"))...)
					}
				}

				break
			}
		}
	}
	return allErrs
}

func validateWorkerConfigImmutability(oldWorkerConfig, newWorkerConfig *apisaws.WorkerConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	oldConfigDataHash := workercontroller.CalculateWorkerConfigDataHash(*oldWorkerConfig)
	newConfigDataHash := workercontroller.CalculateWorkerConfigDataHash(*newWorkerConfig)
	if !slices.Equal(oldConfigDataHash, newConfigDataHash) {
		allErrs = append(allErrs, field.Forbidden(fldPath, "some fields of provider config is immutable when the update strategy is AutoInPlaceUpdate or ManualInPlaceUpdate"))

		if diff := deep.Equal(oldWorkerConfig, newWorkerConfig); diff != nil {
			allErrs = field.ErrorList{field.Forbidden(fldPath, fmt.Sprintf("some fields of provider config is immutable when the update strategy is AutoInPlaceUpdate or ManualInPlaceUpdate. Diff: %s", strings.Join(diff, ", ")))}
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
