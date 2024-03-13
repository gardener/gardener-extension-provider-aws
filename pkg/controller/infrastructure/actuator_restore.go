// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
)

// Restore takes the infrastructure state and deploys it as terraform state ConfigMap before calling the terraformer
func (a *actuator) Restore(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	flowState, err := a.getStateFromInfraStatus(infrastructure)
	if err != nil {
		return err
	}
	if flowState != nil {
		return a.reconcileWithFlow(ctx, log, infrastructure, flowState)
	}
	if a.shouldUseFlow(infrastructure, cluster) {
		flowState, err = a.migrateFromTerraformerState(ctx, log, infrastructure)
		if err != nil {
			return util.DetermineError(err, helper.KnownCodes)
		}
		return a.reconcileWithFlow(ctx, log, infrastructure, flowState)
	}
	return a.restoreWithTerraformer(ctx, log, infrastructure)
}

func (a *actuator) restoreWithTerraformer(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure) error {
	terraformState, err := terraformer.UnmarshalRawState(infrastructure.Status.State)
	if err != nil {
		return err
	}

	infrastructureStatus, state, err := ReconcileWithTerraformer(
		ctx,
		log,
		a.restConfig,
		a.client,
		a.decoder,
		infrastructure,
		terraformer.CreateOrUpdateState{State: &terraformState.Data},
		a.disableProjectedTokenMount,
	)
	if err != nil {
		return err
	}

	return a.updateProviderStatusTf(ctx, a.client, infrastructure, infrastructureStatus, state)
}
