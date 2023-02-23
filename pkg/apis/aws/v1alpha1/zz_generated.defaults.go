//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright (c) SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by defaulter-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// RegisterDefaults adds defaulters functions to the given scheme.
// Public to allow building arbitrary schemes.
// All generated defaulters are covering - they call all nested defaulters.
func RegisterDefaults(scheme *runtime.Scheme) error {
	scheme.AddTypeDefaultingFunc(&CloudProfileConfig{}, func(obj interface{}) { SetObjectDefaults_CloudProfileConfig(obj.(*CloudProfileConfig)) })
	scheme.AddTypeDefaultingFunc(&ControlPlaneConfig{}, func(obj interface{}) { SetObjectDefaults_ControlPlaneConfig(obj.(*ControlPlaneConfig)) })
	scheme.AddTypeDefaultingFunc(&WorkerConfig{}, func(obj interface{}) { SetObjectDefaults_WorkerConfig(obj.(*WorkerConfig)) })
	scheme.AddTypeDefaultingFunc(&WorkerStatus{}, func(obj interface{}) { SetObjectDefaults_WorkerStatus(obj.(*WorkerStatus)) })
	return nil
}

func SetObjectDefaults_CloudProfileConfig(in *CloudProfileConfig) {
	for i := range in.MachineImages {
		a := &in.MachineImages[i]
		for j := range a.Versions {
			b := &a.Versions[j]
			for k := range b.Regions {
				c := &b.Regions[k]
				SetDefaults_RegionAMIMapping(c)
			}
		}
	}
}

func SetObjectDefaults_ControlPlaneConfig(in *ControlPlaneConfig) {
	SetDefaults_ControlPlaneConfig(in)
	if in.Storage != nil {
		SetDefaults_Storage(in.Storage)
	}
}

func SetObjectDefaults_WorkerConfig(in *WorkerConfig) {
	if in.InstanceMetadata != nil {
		SetDefaults_InstanceMetadata(in.InstanceMetadata)
	}
}

func SetObjectDefaults_WorkerStatus(in *WorkerStatus) {
	for i := range in.MachineImages {
		a := &in.MachineImages[i]
		SetDefaults_MachineImage(a)
	}
}
