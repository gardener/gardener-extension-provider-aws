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

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type mutator struct {
	logger logr.Logger
}

// NewMutatorWithShootClient creates a new Mutator that mutates resources in the shoot cluster.
func NewMutatorWithShootClient() extensionswebhook.MutatorWithShootClient {
	return &mutator{
		logger: log.Log.WithName("shoot-service-mutator"),
	}
}

// Mutate mutates resources.
func (m *mutator) Mutate(ctx context.Context, new, _ client.Object, shootClient client.Client) error {
	service, ok := new.(*corev1.Service)
	if !ok {
		return fmt.Errorf("could not mutate: object is not of type corev1.Service")
	}

	// If the object does have a deletion timestamp then we don't want to mutate anything.
	if service.GetDeletionTimestamp() != nil {
		return nil
	}
	extensionswebhook.LogMutation(logger, service.Kind, service.Namespace, service.Name)
	return m.mutateService(ctx, service, shootClient)
}
