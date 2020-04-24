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

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateWorkerConfig validates a WorkerConfig object.
func ValidateWorkerConfig(workerConfig *apisaws.WorkerConfig, volumeType *string) field.ErrorList {
	allErrs := field.ErrorList{}

	if volumeType != nil {
		if *volumeType == string(apisaws.VolumeTypeIO1) && (workerConfig.Volume == nil || workerConfig.Volume.IOPS == nil) {
			allErrs = append(allErrs, field.Required(field.NewPath("volume", "iops"), fmt.Sprintf("iops must be provided when using %s volumes", apisaws.VolumeTypeIO1)))
		}

		if workerConfig.Volume != nil && workerConfig.Volume.IOPS != nil {
			iopsPath := field.NewPath("volume", "iops")

			switch *volumeType {
			case string(apisaws.VolumeTypeGP2):
				if *workerConfig.Volume.IOPS < 100 || *workerConfig.Volume.IOPS > 10000 {
					allErrs = append(allErrs, field.Forbidden(iopsPath, fmt.Sprintf("range is 100-10000 iops for %s volumes", apisaws.VolumeTypeGP2)))
				}
			case string(apisaws.VolumeTypeIO1):
				if *workerConfig.Volume.IOPS < 100 || *workerConfig.Volume.IOPS > 20000 {
					allErrs = append(allErrs, field.Forbidden(iopsPath, fmt.Sprintf("range is 100-20000 iops for %s volumes", apisaws.VolumeTypeIO1)))
				}
			default:
				allErrs = append(allErrs, field.Forbidden(iopsPath, fmt.Sprintf("setting iops is only allowed if volume type is %q or %q", apisaws.VolumeTypeGP2, apisaws.VolumeTypeIO1)))
			}
		}
	}

	return allErrs
}
