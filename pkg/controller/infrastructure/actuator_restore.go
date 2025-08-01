// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
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
)

// Restore takes the infrastructure state and deploys it as terraform state ConfigMap before calling the terraformer
func (a *actuator) Restore(ctx context.Context, log logr.Logger, infra *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	return util.DetermineError(a.restore(ctx, log, OnRestore, infra, cluster), helper.KnownCodes)
}

func (a *actuator) restore(ctx context.Context, logger logr.Logger, selectorFn SelectorFunc, infra *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	useFlow, err := selectorFn(infra, cluster)
	if err != nil {
		return err
	}

	factory := ReconcilerFactoryImpl{
		log:   logger,
		a:     a,
		infra: infra,
	}

	reconciler, err := factory.Build(useFlow)
	if err != nil {
		return err
	}
	return reconciler.Restore(ctx, infra, cluster)
}
