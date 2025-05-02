// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket

import (
	"github.com/gardener/gardener/extensions/pkg/controller/backupbucket"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

type actuator struct {
	backupbucket.Actuator
	client           client.Client
	awsClientFactory awsclient.Factory
}

// NewActuator creates a new Actuator that creates/updates backup-bucket.
func NewActuator(mgr manager.Manager, awsClientFactory awsclient.Factory) backupbucket.Actuator {
	return &actuator{
		client:           mgr.GetClient(),
		awsClientFactory: awsClientFactory,
	}
}
