// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"

	"github.com/gardener/gardener/pkg/apis/core"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawshelper "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
)

// ValidateWorkerConfig validates a WorkerConfig object.
func ValidateWorkerConfig(workerConfig *apisaws.WorkerConfig, volume *core.Volume, dataVolumes []core.DataVolume, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if volume != nil && volume.Type != nil {
		allErrs = append(allErrs, validateVolumeConfig(workerConfig.Volume, *volume.Type, fldPath.Child("volume"))...)
	}

	var (
		dataVolumeNames       = sets.New[string]()
		dataVolumeConfigNames = sets.New[string]()
	)

	for i, dv := range dataVolumes {
		if dv.Type != nil {
			dataVolumeNames.Insert(dv.Name)

			var vol *apisaws.Volume
			if dvConfig := apisawshelper.FindDataVolumeByName(workerConfig.DataVolumes, dv.Name); dvConfig != nil {
				vol = &dvConfig.Volume
			}

			allErrs = append(allErrs, validateVolumeConfig(vol, *dv.Type, fldPath.Child("dataVolumes").Index(i))...)
		}
	}

	for i, dv := range workerConfig.DataVolumes {
		idxPath := fldPath.Child("dataVolumes").Index(i)

		if !dataVolumeNames.Has(dv.Name) {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("name"), dv.Name, fmt.Sprintf("%s not found in data volumes configured in worker pool", dv.Name)))
		}

		if dataVolumeConfigNames.Has(dv.Name) {
			allErrs = append(allErrs, field.Duplicate(idxPath.Child("name"), dv.Name))
		} else {
			dataVolumeConfigNames.Insert(dv.Name)
		}
	}

	if iam := workerConfig.IAMInstanceProfile; iam != nil {
		if (iam.Name == nil && iam.ARN == nil) || (iam.Name != nil && iam.ARN != nil) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("iamInstanceProfile"), iam, "either <name> or <arn> must be provided"))
		}
		if iam.Name != nil && len(*iam.Name) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("iamInstanceProfile", "name"), "name must not be empty"))
		}
		if iam.ARN != nil && len(*iam.ARN) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("iamInstanceProfile", "arn"), "arn must not be empty"))
		}
	}

	if nodeTemplate := workerConfig.NodeTemplate; nodeTemplate != nil {
		if len(nodeTemplate.Capacity) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("nodeTemplate").Child("capacity"), "capacity must not be empty"))
		}
		for _, capacityAttribute := range []corev1.ResourceName{"cpu", "gpu", "memory"} {
			value, ok := nodeTemplate.Capacity[capacityAttribute]
			if !ok {
				// core resources such as "cpu", "gpu", "memory" need not all be explicitly specified in workerConfig.NodeTemplate.
				// Will fall back to the worker pool's node template if missing.
				continue
			}
			allErrs = append(allErrs, validateResourceQuantityValue(capacityAttribute, value, fldPath.Child("nodeTemplate").Child("capacity").Child(string(capacityAttribute)))...)
		}
	}

	allErrs = append(allErrs, validateInstanceMetadata(workerConfig.InstanceMetadataOptions, fldPath.Child("instanceMetadataOptions"))...)
	allErrs = append(allErrs, validateCpuOptions(workerConfig.CpuOptions, fldPath.Child("cpuOptions"))...)

	return allErrs
}

// ValidateWorkersAgainstCloudProfileOnCreation validates the worker configurations against the cloud profile on creation.
func ValidateWorkersAgainstCloudProfileOnCreation(workers []core.Worker, region string, awsCloudProfile *apisaws.CloudProfileConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, w := range workers {
		allErrs = append(allErrs, validateWorkerConfigAgainstCloudProfile(w, region, awsCloudProfile, fldPath.Index(i))...)
	}
	return allErrs
}

// ValidateWorkersAgainstCloudProfileOnUpdate validates the worker configurations against the cloud profile on update.
func ValidateWorkersAgainstCloudProfileOnUpdate(oldWorkers, newWorkers []core.Worker, region string, awsCloudProfile *apisaws.CloudProfileConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	// Validate the existence of the images the new/updated workers are to use. Validating the images used by old workers is not possible at this point, as they might
	// have been removed from the CloudProfile already.
	for i, newWorker := range newWorkers {
		var w core.Worker
		for _, oldWorker := range oldWorkers {
			if newWorker.Name == oldWorker.Name {
				w = oldWorker
				break
			}
		}
		// Validate only new Workers (i.e. the cases where w was not reassigned above) or those whose image has changed.
		if w.Name == "" || newWorker.Machine.Image != w.Machine.Image {
			allErrs = append(allErrs, validateWorkerConfigAgainstCloudProfile(newWorker, region, awsCloudProfile, fldPath.Index(i))...)
		}
	}

	return allErrs
}

func validateWorkerConfigAgainstCloudProfile(worker core.Worker, region string, awsCloudProfile *apisaws.CloudProfileConfig, fldPath *field.Path) field.ErrorList {
	var (
		allErrs      = field.ErrorList{}
		image        = worker.Machine.Image
		architecture = worker.Machine.Architecture
	)
	// if image is nil a default image is selected from the cloudProfile which therefore trivially exists.
	if image == nil {
		return allErrs
	}

	if _, err := apisawshelper.FindAMIForRegionFromCloudProfile(awsCloudProfile, image.Name, image.Version, region, architecture); err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("machine", "image"), image, fmt.Sprint(err)))
	}
	return allErrs
}

func validateResourceQuantityValue(key corev1.ResourceName, value resource.Quantity, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if value.Cmp(resource.Quantity{}) < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath, value.String(), fmt.Sprintf("%s value must not be negative", key)))
	}

	return allErrs
}

func validateVolumeConfig(volume *apisaws.Volume, volumeType string, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	iopsPath := fldPath.Child("iops")
	if volume != nil && volume.IOPS != nil {
		if *volume.IOPS <= 0 {
			allErrs = append(allErrs, field.Forbidden(iopsPath, "iops must be a positive value"))
		}
	} else if volumeType == string(apisaws.VolumeTypeIO1) {
		allErrs = append(allErrs, field.Required(iopsPath, fmt.Sprintf("iops must be provided when using %s volumes", apisaws.VolumeTypeIO1)))
	}
	if volume != nil && volume.Throughput != nil && *volume.Throughput <= 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("throughput"), *volume.Throughput, "throughput must be a positive value"))
	}

	return allErrs
}

func validateInstanceMetadata(md *apisaws.InstanceMetadataOptions, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	if md == nil {
		return allErrs
	}

	if md.HTTPPutResponseHopLimit != nil {
		// the technical limitations of the AWS API are between 1 and 64, but for the operation "EnableInstanceMetadataV2"
		// to be meaningful we need to only allow hop limit >=2 as this is the prerequisite to enable IMDSv2.
		if *md.HTTPPutResponseHopLimit < 1 || *md.HTTPPutResponseHopLimit > 64 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("httpPutResponseHopLimit"), *md.HTTPPutResponseHopLimit, "only values between 1 and 64 are allowed"))
		}
	}

	if md.HTTPTokens != nil {
		validValues := []apisaws.HTTPTokensValue{apisaws.HTTPTokensRequired, apisaws.HTTPTokensOptional}
		if !slices.Contains(validValues, *md.HTTPTokens) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("httpTokens"), *md.HTTPTokens, fmt.Sprintf("only the following values are allowed: %v", validValues)))
		}
	}
	return allErrs
}

func validateCpuOptions(cpuOptions *apisaws.CpuOptions, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	if cpuOptions == nil {
		return allErrs
	}

	if cpuOptions.CoreCount == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("coreCount"), "CoreCount is required"))
	}

	if cpuOptions.ThreadsPerCore == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("threadsPerCore"), "ThreadsPerCore is required"))
	}

	if threadsPerCore := *cpuOptions.ThreadsPerCore; threadsPerCore > 2 || threadsPerCore < 1 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("threadsPerCore"), threadsPerCore, "ThreadsPerCore must be either '1' or '2'"))
	}

	return allErrs
}
