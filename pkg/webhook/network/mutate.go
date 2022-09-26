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

package network

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"

	calicov1alpha1 "github.com/gardener/gardener-extension-networking-calico/pkg/apis/calico/v1alpha1"
	calicov1alpha1helper "github.com/gardener/gardener-extension-networking-calico/pkg/apis/calico/v1alpha1/helper"
	"github.com/gardener/gardener/extensions/pkg/webhook/network"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DisableOverlay = "aws.provider.extensions.gardener.cloud/disableOverlay"
)

// NewMutator creates a new network mutator.
func NewMutator(logger logr.Logger) extensionswebhook.Mutator {
	mutator := &mutator{}
	mutator.mutator = network.NewMutator(logger, mutator.mutateNetworkConfig)
	return mutator
}

type mutator struct {
	client  client.Client
	mutator extensionswebhook.Mutator
}

// InjectClient injects the given client into the mutator.
func (m *mutator) InjectClient(client client.Client) error {
	m.client = client
	return nil
}

// Mutate validates and if needed mutates the given object.
func (m *mutator) Mutate(ctx context.Context, new, old client.Object) error {
	return m.mutator.Mutate(ctx, new, old)
}

func (m *mutator) mutateNetworkConfig(new, old *extensionsv1alpha1.Network) error {
	extensionswebhook.LogMutation(logger, "Network", new.Namespace, new.Name)

	var (
		networkConfig *calicov1alpha1.NetworkConfig
		ipv4          = calicov1alpha1.IPv4{Mode: (*calicov1alpha1.IPv4PoolMode)(pointer.StringPtr(string(calicov1alpha1.Never)))}
		backendNone   = calicov1alpha1.None
		ipv4PoolMode  = calicov1alpha1.Never
		err           error
		ctx           = context.Background()
	)

	gctx := gcontext.NewGardenContext(m.client, new)
	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	greaterEqual122, err := versionutils.CompareVersions(cluster.Shoot.Spec.Kubernetes.Version, ">=", "1.22")
	if err != nil {
		return err
	}
	if !greaterEqual122 {
		return nil
	}

	if old != nil {
		if _, ok := old.GetAnnotations()[DisableOverlay]; ok {
			tmp := new.GetAnnotations()
			tmp[DisableOverlay] = old.GetAnnotations()[DisableOverlay]
			new.SetAnnotations(tmp)
		}
	} else if cluster.Shoot.Status.LastOperation == nil || cluster.Shoot.Status.LastOperation.Type != v1beta1.LastOperationTypeRestore {
		// do network resource update only for a create operation
		tmp := new.GetAnnotations()
		tmp[DisableOverlay] = "true"
		new.SetAnnotations(tmp)
	}

	// source/destination checks are only disabled for kubernetes >= 1.22
	// see https://github.com/gardener/machine-controller-manager-provider-aws/issues/36 for details
	if new.GetAnnotations()[DisableOverlay] == "true" {
		if new.Spec.ProviderConfig != nil {
			networkConfig, err = calicov1alpha1helper.CalicoNetworkConfigFromNetworkResource(new)
			if err != nil {
				return err
			}
		} else {
			networkConfig = &calicov1alpha1.NetworkConfig{
				TypeMeta: metav1.TypeMeta{
					APIVersion: calicov1alpha1.SchemeGroupVersion.String(),
					Kind:       "NetworkConfig",
				},
			}
		}

		if networkConfig.IPv4 == nil {
			networkConfig.IPv4 = &ipv4
		}

		if networkConfig.IPv4 != nil && networkConfig.IPv4.Mode == nil {
			networkConfig.IPv4.Mode = &ipv4PoolMode
		}

		if networkConfig.Backend == nil {
			networkConfig.Backend = &backendNone
		}

		new.Spec.ProviderConfig = &runtime.RawExtension{
			Object: networkConfig,
		}
	}
	return nil
}

func (m *mutator) isKubernetesGreaterOrEqual122(name string) (bool, error) {
	cluster, err := extensions.GetCluster(context.TODO(), m.client, name)
	if err != nil {
		return false, err
	}
	return versionutils.CompareVersions(cluster.Shoot.Spec.Kubernetes.Version, ">=", "1.22")
}
