// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
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

// SetDefaults_RegionAMIMapping set the architecture of machine ami image.
func SetDefaults_RegionAMIMapping(obj *RegionAMIMapping) {
	if obj.Architecture == nil {
		obj.Architecture = ptr.To(v1beta1constants.ArchitectureAMD64)
	}
}

// SetDefaults_MachineImage set the architecture of machine image.
func SetDefaults_MachineImage(obj *MachineImage) {
	if obj.Architecture == nil {
		obj.Architecture = ptr.To(v1beta1constants.ArchitectureAMD64)
	}
}
