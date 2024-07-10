// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

// Migrate deletes only the ConfigMaps and Secrets of the Terraformer.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, _ *extensionscontroller.Cluster) error {
	if infrastructure.Status.State != nil {
		return nil // nothing to do if already using new flow without Terraformer
	}
	tf, err := newTerraformer(log, a.restConfig, aws.TerraformerPurposeInfra, infrastructure, a.disableProjectedTokenMount)
	if err != nil {
		return err
	}
	return util.DetermineError(CleanupTerraformerResources(ctx, tf), helper.KnownCodes)
}
