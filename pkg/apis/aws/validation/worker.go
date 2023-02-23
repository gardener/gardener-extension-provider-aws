// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validation

import (
	"fmt"

	"github.com/gardener/gardener/pkg/apis/core"
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
		for _, capacityAttribute := range []corev1.ResourceName{"cpu", "gpu", "memory"} {
			value, ok := nodeTemplate.Capacity[capacityAttribute]
			if !ok {
				allErrs = append(allErrs, field.Required(fldPath.Child("nodeTemplate").Child("capacity"), fmt.Sprintf("%s is a mandatory field", capacityAttribute)))
				continue
			}
			allErrs = append(allErrs, validateResourceQuantityValue(capacityAttribute, value, fldPath.Child("nodeTemplate").Child("capacity").Child(string(capacityAttribute)))...)
		}
	}

	allErrs = append(allErrs, validateInstanceMetadata(workerConfig.InstanceMetadata, fldPath.Child("instanceMetadata"))...)

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

func validateInstanceMetadata(md *apisaws.InstanceMetadata, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	if md == nil {
		return allErrs
	}

	if !md.EnableInstanceMetadataV2 && md.HTTPPutResponseHopLimit != nil {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("HTTPPutResponseHopLimit"), *md.HTTPPutResponseHopLimit, "enableInstanceMetadataV2 must be set to specify this field"))
		return allErrs
	}

	if md.EnableInstanceMetadataV2 && md.HTTPPutResponseHopLimit == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("HTTPPutResponseHopLimit"), "this field must be specified if enableInstanceMetadataV2 is enabled"))
		return allErrs
	}

	if md.HTTPPutResponseHopLimit != nil {
		// the technical limitations of the AWS API are between 1 and 64, but for the operation "EnableInstanceMetadataV2"
		// to be meaningful we need to only allow hop limit >=2 as this is the prerequisite to enable IMDSv2.
		if *md.HTTPPutResponseHopLimit < 2 || *md.HTTPPutResponseHopLimit > 64 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("HTTPPutResponseHopLimit"), *md.HTTPPutResponseHopLimit, "only values between 2 and 64 are allowed"))
		}
	}
	return allErrs
}
