// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain m copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shootservice

import (
	"context"
	"fmt"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type mutator struct {
	logger           logr.Logger
	wantsShootClient bool
}

// NewMutatorWithShootClient creates a new Mutator that mutates resources in the shoot cluster.
func NewMutatorWithShootClient(logger logr.Logger) extensionswebhook.Mutator {
	return &mutator{logger, true}
}

// WantsShootClient indicates that this mutator wants the shoot client to be injected into the context.
// The corresponding client can be found in the passed context via the ShootClientContextKey.
func (m *mutator) WantsShootClient() bool {
	return m.wantsShootClient
}

// Mutate mutates resources.
func (m *mutator) Mutate(ctx context.Context, newObj, _ client.Object) error {
	service, ok := newObj.(*corev1.Service)
	if !ok {
		return fmt.Errorf("could not mutate: object is not of type corev1.Service")
	}

	// If the object does have a deletion timestamp then we don't want to mutate anything.
	if service.GetDeletionTimestamp() != nil {
		return nil
	}
	extensionswebhook.LogMutation(m.logger, service.Kind, service.Namespace, service.Name)

	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return nil
	}

	if metav1.HasAnnotation(service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-scheme") &&
		service.Annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"] == "internal" ||
		metav1.HasAnnotation(service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-internal") &&
			service.Annotations["service.beta.kubernetes.io/aws-load-balancer-internal"] == "true" ||
		metav1.HasAnnotation(service.ObjectMeta, "extensions.gardener.cloud/ignore-load-balancer") &&
			service.Annotations["extensions.gardener.cloud/ignore-load-balancer"] == "true" {
		return nil
	}

	shootClient, ok := ctx.Value(extensionswebhook.ShootClientContextKey{}).(client.Client)
	if !ok {
		return fmt.Errorf("could not mutate: no shoot client found in context")
	}

	kubeDNSService := &corev1.Service{}
	if err := shootClient.Get(ctx, types.NamespacedName{Name: "kube-dns", Namespace: "kube-system"}, kubeDNSService); err != nil {
		return err
	}
	if slices.Contains(kubeDNSService.Spec.IPFamilies, corev1.IPv6Protocol) {
		metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack")
		metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing")
		metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance")
		metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-type", "external")
	}

	return nil
}
