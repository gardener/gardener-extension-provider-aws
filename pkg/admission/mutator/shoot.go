// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package mutator

import (
	"context"
	"fmt"

	calicov1alpha1 "github.com/gardener/gardener-extension-networking-calico/pkg/apis/calico/v1alpha1"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	versionutils "github.com/gardener/gardener/pkg/utils/version"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewShootMutator returns a new instance of a shoot mutator.
func NewShootMutator() extensionswebhook.Mutator {
	return &shoot{}
}

type shoot struct {
	decoder runtime.Decoder
}

// InjectScheme injects the given scheme into the validator.
func (s *shoot) InjectScheme(scheme *runtime.Scheme) error {
	s.decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
	return nil
}

// Mutate mutates the given shoot object.
func (s *shoot) Mutate(ctx context.Context, new, old client.Object) error {
	overlay := &calicov1alpha1.Overlay{Enabled: false}

	shoot, ok := new.(*gardencorev1beta1.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}

	// source/destination checks are only disabled for kubernetes >= 1.22
	// see https://github.com/gardener/machine-controller-manager-provider-aws/issues/36 for details
	greaterEqual122, err := versionutils.CompareVersions(shoot.Spec.Kubernetes.Version, ">=", "1.22")
	if err != nil {
		return err
	}
	if !greaterEqual122 {
		return nil
	}

	networkConfig, err := s.decodeNetworkingConfig(shoot.Spec.Networking.ProviderConfig)
	if err != nil {
		return err
	}

	if old == nil && networkConfig.Overlay == nil {
		networkConfig.Overlay = overlay
	}

	if old != nil && networkConfig.Overlay == nil {
		oldShoot, ok := old.(*gardencorev1beta1.Shoot)
		if !ok {
			return fmt.Errorf("wrong object type %T", old)
		}
		if oldShoot.DeletionTimestamp != nil {
			return nil
		}
		oldNetworkConfig, err := s.decodeNetworkingConfig(oldShoot.Spec.Networking.ProviderConfig)
		if err != nil {
			return err
		}
		if oldNetworkConfig.Overlay != nil {
			networkConfig.Overlay = oldNetworkConfig.Overlay
		}
	}
	shoot.Spec.Networking.ProviderConfig = &runtime.RawExtension{
		Object: networkConfig,
	}

	controlPlaneConfig, err := s.decodeControlplaneConfig(shoot.Spec.Provider.ControlPlaneConfig)
	if err != nil {
		return err
	}

	if controlPlaneConfig.CloudControllerManager == nil {
		controlPlaneConfig.CloudControllerManager = &awsv1alpha1.CloudControllerManagerConfig{}
	}

	if !networkConfig.Overlay.Enabled {
		if controlPlaneConfig.CloudControllerManager.UseCustomRouteController == nil {
			controlPlaneConfig.CloudControllerManager.UseCustomRouteController = pointer.Bool(true)
		} else {
			*controlPlaneConfig.CloudControllerManager.UseCustomRouteController = true
		}
	} else {
		if controlPlaneConfig.CloudControllerManager.UseCustomRouteController == nil {
			controlPlaneConfig.CloudControllerManager.UseCustomRouteController = pointer.Bool(false)
		} else {
			*controlPlaneConfig.CloudControllerManager.UseCustomRouteController = false
		}
	}

	shoot.Spec.Provider.ControlPlaneConfig = &runtime.RawExtension{
		Object: controlPlaneConfig,
	}

	return nil
}

func (s *shoot) decodeNetworkingConfig(network *runtime.RawExtension) (*calicov1alpha1.NetworkConfig, error) {
	networkConfig := &calicov1alpha1.NetworkConfig{}
	if network != nil && network.Raw != nil {
		if _, _, err := s.decoder.Decode(network.Raw, nil, networkConfig); err != nil {
			return nil, err
		}
	}
	return networkConfig, nil
}

func (s *shoot) decodeControlplaneConfig(controlPlaneConfig *runtime.RawExtension) (*awsv1alpha1.ControlPlaneConfig, error) {
	cp := &awsv1alpha1.ControlPlaneConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
			Kind:       "ControlPlaneConfig",
		},
	}
	if controlPlaneConfig != nil && controlPlaneConfig.Raw != nil {
		if _, _, err := s.decoder.Decode(controlPlaneConfig.Raw, nil, cp); err != nil {
			return nil, err
		}
	}
	return cp, nil
}
