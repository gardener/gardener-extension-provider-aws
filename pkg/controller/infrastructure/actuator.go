// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
)

type actuator struct {
	client       client.Client
	restConfig   *rest.Config
	gardenReader client.Reader
	gardenWriter client.Client
	recorder     record.EventRecorder
}

// NewActuator creates a new Actuator that updates the status of the handled Infrastructure resources.
func NewActuator(mgr manager.Manager, gardenCluster cluster.Cluster) infrastructure.Actuator {
	var gardenReader client.Reader
	var gardenWriter client.Client
	if gardenCluster != nil {
		gardenReader = gardenCluster.GetAPIReader()
		gardenWriter = gardenCluster.GetClient()
	}
	return &actuator{
		client:       mgr.GetClient(),
		restConfig:   mgr.GetConfig(),
		gardenReader: gardenReader,
		gardenWriter: gardenWriter,
		recorder:     mgr.GetEventRecorderFor("provider-aws-infrastructure"),
	}
}

// resolveEffectiveSeed returns the Seed whose provider config should be used for TGW configuration.
// For ManagedSeed shoots, this is the Seed the shoot becomes (looked up by shoot name),
// not the parent Seed that runs the shoot (cluster.Seed).
// Always reads from the Garden API to get the latest config (cluster.Seed may be stale).
func (a *actuator) resolveEffectiveSeed(ctx context.Context, log logr.Logger, cluster *extensionscontroller.Cluster) *v1beta1.Seed {
	effectiveSeed := cluster.Seed
	if effectiveSeed == nil || a.gardenReader == nil {
		return effectiveSeed
	}

	// Always re-read the Seed from the Garden API to pick up config changes
	// (e.g., isolation mode switch). The cluster.Seed may be stale.
	freshSeed := &v1beta1.Seed{}
	if err := a.gardenReader.Get(ctx, client.ObjectKey{Name: effectiveSeed.Name}, freshSeed); err == nil {
		seedConfig, _ := helper.SeedProviderConfigFromSeed(freshSeed)
		if seedConfig != nil && seedConfig.TransitGateway != nil {
			log.V(1).Info("using fresh Seed from Garden API", "seedName", freshSeed.Name)
			return freshSeed
		}
	}

	// Fallback: check if this shoot IS a ManagedSeed (the shoot becomes a seed).
	// This path only triggers when the parent seed has no TGW config but the
	// ManagedSeed's own Seed does. In our setup, Path 2 above always wins
	// because the parent seed typically has TGW config. Kept as a safety net.
	shootName := cluster.Shoot.Name
	candidateSeed := &v1beta1.Seed{}
	if err := a.gardenReader.Get(ctx, client.ObjectKey{Name: shootName}, candidateSeed); err == nil {
		candidateConfig, _ := helper.SeedProviderConfigFromSeed(candidateSeed)
		if candidateConfig != nil && candidateConfig.TransitGateway != nil {
			log.Info("using ManagedSeed's own Seed for TGW config", "seedName", shootName)
			return candidateSeed
		}
	}

	return effectiveSeed
}
