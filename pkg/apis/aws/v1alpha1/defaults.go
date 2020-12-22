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

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetDefaults_ControlPlaneConfig sets
// .storage to empty object.
func SetDefaults_ControlPlaneConfig(obj *ControlPlaneConfig) {
	if obj.Storage == nil {
		obj.Storage = &Storage{}
	}
}

// SetDefaults_Storage sets
// managedDefaultClass to true.
func SetDefaults_Storage(obj *Storage) {
	defaultManagedDefaultClass := true

	if obj.ManagedDefaultClass == nil {
		obj.ManagedDefaultClass = &defaultManagedDefaultClass
	}
}
