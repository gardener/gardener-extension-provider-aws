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

package aws

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ControlPlaneConfig contains configuration settings for the control plane.
type ControlPlaneConfig struct {
	metav1.TypeMeta

	// CloudControllerManager contains configuration settings for the cloud-controller-manager.
	CloudControllerManager *CloudControllerManagerConfig

	// AWSLoadBalancerController contains configuration settings for the optional aws-load-balancer-controller (ALB).
	AWSLoadBalancerController *AWSLoadBalancerControllerConfig

	// Storage contains configuration for storage in the cluster.
	Storage *Storage
}

// CloudControllerManagerConfig contains configuration settings for the cloud-controller-manager.
type CloudControllerManagerConfig struct {
	// FeatureGates contains information about enabled feature gates.
	FeatureGates map[string]bool

	// UseCustomRouteController controls if custom route controller should be used.
	// Defaults to false.
	UseCustomRouteController *bool
}

// AWSLoadBalancerController contains configuration settings for the optional aws-load-balancer-controller (ALB).
type AWSLoadBalancerControllerConfig struct {
	// Enabled controls if the ALB should be deployed.
	Enabled bool

	// IngressClass controls creation and parameters of the ingress class named `alb`
	IngressClass *IngressClass
}

// IngressClass controls creation and parameters of the ingress class named `alb`
type IngressClass struct {
	// Disabled controls if the alb ingress class should be created.
	Disabled bool

	// IsDefault controls if the ingress class should be the default one.
	IsDefault bool

	// IngressClassParamsSpec defines the spec of the IngressClassParams resource
	// See https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/guide/ingress/ingress_class/#ingressclassparams for more details.
	IngressClassParamsSpec *runtime.RawExtension
}

// Storage contains configuration for storage in the cluster.
type Storage struct {
	// ManagedDefaultClass controls if the 'default' StorageClass and 'default' VolumeSnapshotClass
	// would be marked as default. Set to false to manually set the default to another class not
	// managed by Gardener.
	// Defaults to true.
	ManagedDefaultClass *bool
}
