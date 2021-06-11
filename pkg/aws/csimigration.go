// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package aws

import (
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
)

// CSIMigrationKubernetesVersion is a constant for the Kubernetes version for which the Shoot's CSI migration will be
// performed.
const CSIMigrationKubernetesVersion = "1.18"

// GetCSIMigrationKubernetesVersion returns the Kubernetes version for which CSI migration will be performed.
func GetCSIMigrationKubernetesVersion(cluster *extensionscontroller.Cluster) string {
	if cluster == nil || cluster.Shoot == nil {
		return CSIMigrationKubernetesVersion
	}

	if val, ok := cluster.Shoot.Annotations[extensionsv1alpha1.ShootAlphaCSIMigrationKubernetesVersion]; ok {
		return val
	}

	return CSIMigrationKubernetesVersion
}
