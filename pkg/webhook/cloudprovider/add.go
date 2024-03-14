// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cloudprovider

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/cloudprovider"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

var logger = log.Log.WithName("aws-cloudprovider-webhook")

// AddToManager creates the cloudprovider webhook and adds it to the manager.
func AddToManager(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("adding webhook to manager")
	return cloudprovider.New(mgr, cloudprovider.Args{
		Provider: aws.Type,
		Mutator:  cloudprovider.NewMutator(mgr, logger, NewEnsurer(logger)),
	})
}
