// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
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
	"k8s.io/client-go/rest"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

// Migrate deletes only the ConfigMaps and Secrets of the Terraformer.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, _ *extensionscontroller.Cluster) error {
	flowState, err := a.getStateFromInfraStatus(infrastructure)
	if err != nil {
		return err
	}
	if flowState != nil {
		return nil // nothing to do if already using new flow without Terraformer
	}
	return migrateTerraformer(ctx, log, a.restConfig, infrastructure, a.disableProjectedTokenMount)
}

func migrateTerraformer(
	ctx context.Context,
	logger logr.Logger,
	restConfig *rest.Config,
	infrastructure *extensionsv1alpha1.Infrastructure,
	disableProjectedTokenMount bool,
) error {
	tf, err := newTerraformer(logger, restConfig, aws.TerraformerPurposeInfra, infrastructure, disableProjectedTokenMount)
	if err != nil {
		return util.DetermineError(fmt.Errorf("could not create the Terraformer: %+v", err), helper.KnownCodes)
	}

	if err := tf.CleanupConfiguration(ctx); err != nil {
		return err
	}

	return tf.RemoveTerraformerFinalizerFromConfig(ctx)
}
