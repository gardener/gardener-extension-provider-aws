// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var (
	// DefaultAddOptions are the default AddOptions for AddToManager.
	DefaultAddOptions = AddOptions{}
)

// AddOptions are options to apply when adding the AWS infrastructure controller to the manager.
type AddOptions struct {
	// Controller are the controller.Options.
	Controller ctrlcontroller.Options
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
	// ExtensionClasses defines the extension classes this extension is responsible for.
	ExtensionClasses []extensionsv1alpha1.ExtensionClass
	// GardenCluster is the garden cluster for looking up Seed objects.
	GardenCluster cluster.Cluster
}

// AddToManagerWithOptions adds a controller with the given Options to the given manager.
// The opts.Reconciler is being set with a newly instantiated actuator.
func AddToManagerWithOptions(ctx context.Context, mgr manager.Manager, opts AddOptions) error {
	predicates := infrastructure.DefaultPredicates(ctx, mgr, opts.IgnoreOperationAnnotation)

	addArgs := infrastructure.AddArgs{
		Actuator:          NewActuator(mgr, opts.GardenCluster),
		ConfigValidator:   NewConfigValidator(mgr, awsclient.FactoryFunc(awsclient.NewInterface), log.Log),
		ControllerOptions: opts.Controller,
		Predicates:        predicates,
		Type:              aws.Type,
		KnownCodes:        helper.KnownCodes,
		ExtensionClasses:  opts.ExtensionClasses,
	}

	// Watch Seed objects on the Garden API for TGW config and LB scheme changes.
	if opts.GardenCluster != nil {
		gardenClient := opts.GardenCluster.GetClient()
		addArgs.WatchBuilder = extensionscontroller.WatchBuilder{
			// Watcher 1: TGW config changes → infra reconcile only.
			func(ctrl ctrlcontroller.Controller) error {
				return ctrl.Watch(
					source.Kind[client.Object](
						opts.GardenCluster.GetCache(),
						&v1beta1.Seed{},
						handler.EnqueueRequestsFromMapFunc(seedToInfrastructureMapper(mgr.GetClient(), gardenClient)),
						SeedTGWConfigChangedPredicate{},
					),
				)
			},
			// Watcher 2: LB scheme changes → set annotation + infra reconcile (triggers NLB cleanup + shoot reconcile).
			func(ctrl ctrlcontroller.Controller) error {
				return ctrl.Watch(
					source.Kind[client.Object](
						opts.GardenCluster.GetCache(),
						&v1beta1.Seed{},
						handler.EnqueueRequestsFromMapFunc(lbSchemeChangeMapper(mgr.GetClient(), gardenClient)),
						LBSchemeChangedPredicate{},
					),
				)
			},
		}
	}

	// Watcher 3: Cluster CR shoot-transitioned-out-of-Failed → re-enqueue Infra.
	// Compensates for the gardener ShootNotFailedPredicate which blocks events
	// while shoot is Failed. When the shoot recovers, no new event fires on the
	// Infrastructure (the operation=reconcile annotation was already set), so
	// the controller would wait indefinitely for the gardener-extension
	// framework's resync. This watcher fires immediately on the transition.
	addArgs.WatchBuilder = append(addArgs.WatchBuilder,
		func(ctrl ctrlcontroller.Controller) error {
			return ctrl.Watch(
				source.Kind[client.Object](
					mgr.GetCache(),
					&extensionsv1alpha1.Cluster{},
					handler.EnqueueRequestsFromMapFunc(clusterToInfrastructureMapper()),
					shootUnfailedPredicate{},
				),
			)
		},
	)

	return infrastructure.Add(mgr, addArgs)
}

// AddToManager adds a controller with the default Options.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	return AddToManagerWithOptions(ctx, mgr, DefaultAddOptions)
}
