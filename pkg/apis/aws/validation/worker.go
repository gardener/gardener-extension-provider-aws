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

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawshelper "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"

	"github.com/gardener/gardener/pkg/apis/core"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateWorkerConfig validates a WorkerConfig object.
func ValidateWorkerConfig(workerConfig *apisaws.WorkerConfig, volume *core.Volume, dataVolumes []core.DataVolume, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if volume != nil && volume.Type != nil {
		allErrs = append(allErrs, validateVolumeConfig(workerConfig.Volume, *volume.Type, fldPath.Child("volume"))...)
	}

	var (
		dataVolumeNames       = sets.NewString()
		dataVolumeConfigNames = sets.NewString()
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

	if volumeType == string(apisaws.VolumeTypeIO1) && (volume == nil || volume.IOPS == nil) {
		allErrs = append(allErrs, field.Required(iopsPath, fmt.Sprintf("iops must be provided when using %s volumes", apisaws.VolumeTypeIO1)))
		return allErrs
	}

	if volume != nil && volume.IOPS != nil && *volume.IOPS < 0 {
		allErrs = append(allErrs, field.Forbidden(iopsPath, "iops must be a non negative value"))
	}
	return allErrs
}
