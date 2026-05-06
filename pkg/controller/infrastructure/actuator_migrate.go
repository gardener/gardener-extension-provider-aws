// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"fmt"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

// Migrate cleans up TGW resources on the old seed and deletes Terraformer resources.
// Called when a shoot is migrated from this seed to another. The shoot's VPC remains
// intact — only TGW attachments, RT associations, and routes are removed.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	// Clean up TGW resources on the old seed (if TGW is enabled).
	if err := a.migrateTGWCleanup(ctx, log, infrastructure, cluster); err != nil {
		// Log but don't fail migration — TGW cleanup is best-effort.
		// Orphaned resources will be caught by the health checker or manual cleanup.
		log.Error(err, "TGW cleanup during migration failed — continuing with migration")
	}

	// Clean up Terraformer resources (ConfigMaps/Secrets).
	tf, err := newTerraformer(log, a.restConfig, aws.TerraformerPurposeInfra, infrastructure)
	if err != nil {
		return err
	}
	return util.DetermineError(CleanupTerraformerResources(ctx, tf), helper.KnownCodes)
}

// migrateTGWCleanup removes TGW resources for a shoot being migrated away from this seed.
// This includes: VPC attachments, RT associations/propagations, routes in seed/globalVPCs.
// The shoot's VPC is NOT deleted — it's migrated to the new seed.
func (a *actuator) migrateTGWCleanup(ctx context.Context, log logr.Logger, infra *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	// Check if the shoot has TGW state to clean up.
	fsOk, _ := helper.HasFlowState(infra.Status)
	if !fsOk {
		return nil
	}

	infraState, _ := helper.InfrastructureStateFromRaw(infra.Status.State)

	// Check if there are any TGW keys in state.
	wb := shared.NewWhiteboard()
	if infraState != nil {
		wb.ImportFromFlatMap(infraState.Data)
	}
	if wb.Get(infraflow.IdentifierTransitGatewayID) == nil &&
		wb.Get(infraflow.IdentifierTransitGatewayAttachment) == nil {
		return nil // No TGW state — nothing to clean.
	}

	log.Info("cleaning up TGW resources for shoot migration",
		"shoot", infra.Namespace, "tgwID", wb.Get(infraflow.IdentifierTransitGatewayID))

	awsClient, err := aws.NewClientFromSecretRef(ctx, a.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return fmt.Errorf("failed to create AWS client for TGW migration cleanup: %w", err)
	}

	effectiveSeed := a.resolveEffectiveSeed(ctx, log, cluster)

	fctx, err := infraflow.NewFlowContext(infraflow.Opts{
		Log:            log,
		Infrastructure: infra,
		State:          infraState,
		AwsClient:      awsClient,
		RuntimeClient:  a.client,
		Shoot:          cluster.Shoot,
		Seed:           effectiveSeed,
		Recorder:       a.recorder,
	})
	if err != nil {
		return fmt.Errorf("failed to create flow context for TGW migration cleanup: %w", err)
	}

	// Use the same discovery-based cleanup as deletion, but the VPC won't be deleted
	// (the delete flow's VPC deletion is a separate step that won't run during migrate).
	return fctx.MigrateTGW(ctx)
}
