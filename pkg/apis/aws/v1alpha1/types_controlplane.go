// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

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

	// IPAMController contains configuration settings for the optional aws-ipam-controller.
	// +optional
	IPAMController *IPAMControllerConfig `json:"ipamController,omitempty"`

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

// IPAMControllerConfig contains configuration settings for the optional aws-ipam-controller.
type IPAMControllerConfig struct {
	// Enabled controls if the IPAM controller should be deployed.
	Enabled bool `json:"enabled"`
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
