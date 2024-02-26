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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ControlPlaneConfig contains configuration settings for the control plane.
type ControlPlaneConfig struct {
	metav1.TypeMeta `json:",inline"`

	// CloudControllerManager contains configuration settings for the cloud-controller-manager.
	// +optional
	CloudControllerManager *CloudControllerManagerConfig `json:"cloudControllerManager,omitempty"`

	// LoadBalancerController contains configuration settings for the optional aws-load-balancer-controller (ALB).
	// +optional
	LoadBalancerController *LoadBalancerControllerConfig `json:"loadBalancerController,omitempty"`

	// Storage contains configuration for storage in the cluster.
	// +optional
	Storage *Storage `json:"storage,omitempty"`
}

// CloudControllerManagerConfig contains configuration settings for the cloud-controller-manager.
type CloudControllerManagerConfig struct {
	// FeatureGates contains information about enabled feature gates.
	// +optional
	FeatureGates map[string]bool `json:"featureGates,omitempty"`

	// UseCustomRouteController controls if custom route controller should be used.
	// Defaults to false.
	// +optional
	UseCustomRouteController *bool `json:"useCustomRouteController,omitempty"`
}

// LoadBalancerControllerConfig contains configuration settings for the optional aws-load-balancer-controller (ALB).
type LoadBalancerControllerConfig struct {
	// Enabled controls if the ALB should be deployed.
	Enabled bool `json:"enabled"`

	// IngressClassName is the name of the ingress class the ALB controller will target. Default value is 'alb'.
	// If empty string is specified, it will match all ingresses without ingress class annotation and ingresses of type alb
	// +optional
	IngressClassName *string `json:"ingressClassName,omitempty"`
}

// Storage contains configuration for storage in the cluster.
type Storage struct {
	// ManagedDefaultClass controls if the 'default' StorageClass and 'default' VolumeSnapshotClass
	// would be marked as default. Set to false to manually set the default to another class not
	// managed by Gardener.
	// Defaults to true.
	// +optional
	ManagedDefaultClass *bool `json:"managedDefaultClass,omitempty"`
}