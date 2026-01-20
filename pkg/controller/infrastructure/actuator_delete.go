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
)

func (a *actuator) Delete(ctx context.Context, log logr.Logger, infra *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	return util.DetermineError(a.delete(ctx, log, infra, cluster), helper.KnownCodes)
}

func (a *actuator) ForceDelete(_ context.Context, _ logr.Logger, _ *extensionsv1alpha1.Infrastructure, _ *extensionscontroller.Cluster) error {
	return nil
}

// Delete deletes the infrastructure resource using the flow reconciler.
func (a *actuator) delete(ctx context.Context, log logr.Logger, infra *extensionsv1alpha1.Infrastructure, c *extensionscontroller.Cluster) error {
	awsClient, err := aws.NewClientFromSecretRef(ctx, a.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return fmt.Errorf("failed to create new AWS client: %w", err)
	}

	infraState, err := helper.InfrastructureStateFromRaw(infra.Status.State)
	if err != nil {
		return err
	}

	fctx, err := infraflow.NewFlowContext(infraflow.Opts{
		Log:            log,
		Infrastructure: infra,
		State:          infraState,
		AwsClient:      awsClient,
		RuntimeClient:  a.client,
		Shoot:          c.Shoot,
	})
	if err != nil {
		return fmt.Errorf("failed to create flow context: %w", err)
	}
	err = fctx.Delete(ctx)
	if err != nil {
		return err
	}

	tf, err := newTerraformer(log, a.restConfig, aws.TerraformerPurposeInfra, infra)
	if err != nil {
		return err
	}
	return CleanupTerraformerResources(ctx, tf)
}
