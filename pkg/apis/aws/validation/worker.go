// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"slices"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/pkg/apis/core"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"gopkg.in/inf.v0"
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

		if id := dv.SnapshotID; id != nil {
			allErrs = append(allErrs, validateSnapshotID(*id, idxPath.Child("snapshotID"))...)
		}
	}

	if iam := workerConfig.IAMInstanceProfile; iam != nil {
		if (iam.Name == nil && iam.ARN == nil) || (iam.Name != nil && iam.ARN != nil) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("iamInstanceProfile"), iam,
				"exactly one of 'name' or 'arn' must be specified"))
		}
		if iam.Name != nil {
			allErrs = append(allErrs, validateIamInstanceProfileName(*iam.Name, fldPath.Child("iamInstanceProfile", "name"))...)
		}
		if iam.ARN != nil {
			allErrs = append(allErrs, validateIamInstanceProfileArn(*iam.ARN, fldPath.Child("iamInstanceProfile", "arn"))...)
		}
	}

	if nodeTemplate := workerConfig.NodeTemplate; nodeTemplate != nil {
		for _, capacityAttribute := range []corev1.ResourceName{"cpu", "gpu", "memory"} {
			value, ok := nodeTemplate.Capacity[capacityAttribute]
			if !ok {
				// core resources such as "cpu", "gpu", "memory" need not all be explicitly specified in workerConfig.NodeTemplate.
				// Will fall back to the worker pool's node template if missing.
				continue
			}
			allErrs = append(allErrs, validateResourceQuantityValue(capacityAttribute, value, fldPath.Child("nodeTemplate").Child("capacity").Child(string(capacityAttribute)))...)
		}

		for capacityAttribute, value := range nodeTemplate.VirtualCapacity {
			// extended resources are required to be whole numbers https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#consuming-extended-resources
			allErrs = append(allErrs, validateResourceQuantityWholeNumber(capacityAttribute, value, fldPath.Child("nodeTemplate").Child("virtualCapacity").Child(string(capacityAttribute)))...)
		}
	}

	if workerConfig.CapacityReservation != nil {
		childPath := fldPath.Child("capacityReservation")
		capacityOpts := *workerConfig.CapacityReservation

		if capacityOpts.CapacityReservationPreference != nil {
			preference := ec2types.CapacityReservationPreference(*capacityOpts.CapacityReservationPreference)
			knownValues := preference.Values()

			if !slices.Contains(knownValues, preference) {
				allErrs = append(
					allErrs,
					field.NotSupported(
						childPath.Child("capacityReservationPreference"),
						preference,
						knownValues,
					),
				)
			}

			if preference != ec2types.CapacityReservationPreferenceCapacityReservationsOnly {
				if capacityOpts.CapacityReservationID != nil || capacityOpts.CapacityReservationResourceGroupARN != nil {
					allErrs = append(
						allErrs,
						field.Forbidden(
							childPath.Child("capacityReservationPreference"),
							fmt.Sprintf(
								"'capacityReservationId' or 'capacityReservationResourceGroupArn' may only be given if 'capacityReservationPreference' is '%s' (or absent)",
								ec2types.CapacityReservationPreferenceCapacityReservationsOnly,
							),
						),
					)
				}
			}
		}

		if capacityOpts.CapacityReservationID != nil {
			allErrs = append(allErrs, validateCapacityReservationID(*capacityOpts.CapacityReservationID, childPath.Child("capacityReservationId"))...)
		}
		if capacityOpts.CapacityReservationResourceGroupARN != nil {
			allErrs = append(allErrs, validateCapacityReservationGroup(*capacityOpts.CapacityReservationResourceGroupARN, childPath.Child("capacityReservationResourceGroupArn"))...)
		}

		if capacityOpts.CapacityReservationID != nil && capacityOpts.CapacityReservationResourceGroupARN != nil {
			allErrs = append(
				allErrs,
				field.Forbidden(
					childPath.Child("capacityReservationId"),
					"only one of 'capacityReservationId' and 'capacityReservationResourceGroupArn' may be given",
				),
			)
		}
	}

	allErrs = append(allErrs, validateInstanceMetadata(workerConfig.InstanceMetadataOptions, fldPath.Child("instanceMetadataOptions"))...)
	allErrs = append(allErrs, validateCpuOptions(workerConfig.CpuOptions, fldPath.Child("cpuOptions"))...)

	return allErrs
}

// ValidateWorkersAgainstCloudProfileOnCreation validates the worker configurations against the cloud profile on creation.
func ValidateWorkersAgainstCloudProfileOnCreation(
	workers []core.Worker,
	region string,
	awsCloudProfile *apisaws.CloudProfileConfig,
	machineTypes []v1beta1.MachineType,
	capabilityDefinitions []v1beta1.CapabilityDefinition,
	fldPath *field.Path,
) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, w := range workers {
		machineType := gardencorev1beta1helper.FindMachineTypeByName(machineTypes, w.Machine.Type)
		if machineType == nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Index(i).Child("machine", "type"), w.Machine.Type, " not found in cloud profile"))
			continue
		}

		allErrs = append(allErrs, validateWorkerConfigAgainstCloudProfile(w, region, awsCloudProfile, machineType.Capabilities, capabilityDefinitions, fldPath.Index(i))...)
	}
	return allErrs
}

// ValidateWorkersAgainstCloudProfileOnUpdate validates the worker configurations against the cloud profile on update.
func ValidateWorkersAgainstCloudProfileOnUpdate(
	oldWorkers, newWorkers []core.Worker,
	region string,
	awsCloudProfile *apisaws.CloudProfileConfig,
	machineTypes []v1beta1.MachineType,
	capabilityDefinitions []v1beta1.CapabilityDefinition,
	fldPath *field.Path,
) field.ErrorList {
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
			machineType := gardencorev1beta1helper.FindMachineTypeByName(machineTypes, newWorker.Machine.Type)
			if machineType == nil {
				allErrs = append(allErrs, field.Invalid(fldPath.Index(i).Child("machine", "type"), w.Machine.Type, " not found in cloud profile"))
				continue
			}

			allErrs = append(allErrs, validateWorkerConfigAgainstCloudProfile(newWorker, region, awsCloudProfile, machineType.Capabilities, capabilityDefinitions, fldPath.Index(i))...)
		}
	}

	return allErrs
}

func validateWorkerConfigAgainstCloudProfile(
	worker core.Worker,
	region string,
	awsCloudProfile *apisaws.CloudProfileConfig,
	machineCapabilities v1beta1.Capabilities,
	capabilityDefinitions []v1beta1.CapabilityDefinition,
	fldPath *field.Path,
) field.ErrorList {
	var (
		allErrs      = field.ErrorList{}
		image        = worker.Machine.Image
		architecture = worker.Machine.Architecture
	)
	// if image is nil a default image is selected from the cloudProfile which therefore trivially exists.
	if image == nil {
		return allErrs
	}

	if _, err := apisawshelper.FindImageInCloudProfile(awsCloudProfile, image.Name, image.Version, region, architecture, machineCapabilities, capabilityDefinitions); err != nil {
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

func validateResourceQuantityWholeNumber(key corev1.ResourceName, value resource.Quantity, fldPath *field.Path) field.ErrorList {
	allErrs := validateResourceQuantityValue(key, value, fldPath)

	dec := value.AsDec()
	var roundedDec inf.Dec
	if roundedDec.Round(dec, 0, inf.RoundExact) == nil {
		allErrs = append(allErrs, field.Invalid(fldPath, value.String(), fmt.Sprintf("%s value must be a whole number", key)))
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

	if cpuOptions.AmdSevSnp != nil {
		amdSevSnp := ec2types.AmdSevSnpSpecification(*cpuOptions.AmdSevSnp)
		allowed := amdSevSnp.Values()
		if !slices.Contains(allowed, amdSevSnp) {
			allErrs = append(allErrs, field.NotSupported(
				fldPath.Child("amdSevSnp"),
				amdSevSnp,
				allowed,
			))
		}
	}

	coreSet := cpuOptions.CoreCount != nil
	threadsSet := cpuOptions.ThreadsPerCore != nil

	// either both must be set or neither
	if coreSet != threadsSet {
		if !coreSet {
			allErrs = append(allErrs, field.Required(fldPath.Child("coreCount"),
				"CoreCount is required when ThreadsPerCore is set"))
		}
		if !threadsSet {
			allErrs = append(allErrs, field.Required(fldPath.Child("threadsPerCore"),
				"ThreadsPerCore is required when CoreCount is set"))
		}
		return allErrs
	}

	if threadsSet {
		tpc := *cpuOptions.ThreadsPerCore
		if tpc != 1 && tpc != 2 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("threadsPerCore"), tpc,
				"ThreadsPerCore must be 1 or 2"))
		}
	}

	return allErrs
}
