// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"

	"github.com/gardener/gardener/pkg/apis/core"
	validationutils "github.com/gardener/gardener/pkg/utils/validation"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateNetworking validates the network settings of a Shoot.
func ValidateNetworking(networking *core.Networking, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if networking.Nodes == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("nodes"), "a nodes CIDR must be provided for AWS shoots"))
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
