// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type actuator struct {
	client     client.Client
	restConfig *rest.Config
}

// NewActuator creates a new Actuator that updates the status of the handled Infrastructure resources.
func NewActuator(mgr manager.Manager) infrastructure.Actuator {
	return &actuator{
		client:     mgr.GetClient(),
		restConfig: mgr.GetConfig(),
	}
}
