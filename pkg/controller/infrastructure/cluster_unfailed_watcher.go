// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"encoding/json"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// shootUnfailedPredicate fires when a Cluster CR's embedded shoot transitions
// OUT of `Failed` state. This is used to wake the Infrastructure controller
// after gardener's `ShootNotFailedPredicate` had been blocking events while
// the shoot was Failed: when the shoot recovers (e.g., user adds
// `gardener.cloud/operation=retry` and gardenlet starts processing), there
// is typically NO new event on the Infrastructure to trigger the controller
// because the operation=reconcile annotation was set BEFORE the shoot status
// updated. Without this watcher, the controller never picks up the
// already-set annotation and waits indefinitely until something else writes
// to the Infrastructure (or the gardener-extension framework's resync loop
// fires).
type shootUnfailedPredicate struct{}

var _ predicate.Predicate = shootUnfailedPredicate{}

func (shootUnfailedPredicate) Create(_ event.CreateEvent) bool { return false }
func (shootUnfailedPredicate) Delete(_ event.DeleteEvent) bool { return false }
func (shootUnfailedPredicate) Generic(_ event.GenericEvent) bool { return false }

func (shootUnfailedPredicate) Update(e event.UpdateEvent) bool {
	oldFailed := isShootFailedInCluster(e.ObjectOld)
	newFailed := isShootFailedInCluster(e.ObjectNew)
	return oldFailed && !newFailed
}

func isShootFailedInCluster(obj client.Object) bool {
	cluster, ok := obj.(*extensionsv1alpha1.Cluster)
	if !ok || cluster == nil {
		return false
	}
	if cluster.Spec.Shoot.Raw == nil {
		return false
	}
	shoot := &gardencorev1beta1.Shoot{}
	if err := json.Unmarshal(cluster.Spec.Shoot.Raw, shoot); err != nil {
		return false
	}
	return shoot.Status.LastOperation != nil &&
		shoot.Status.LastOperation.State == gardencorev1beta1.LastOperationStateFailed
}

// clusterToInfrastructureMapper enqueues the Infrastructure resource named
// after the shoot in the Cluster's namespace. Each Cluster has a 1:1
// relationship with one Infrastructure resource (named the same as the
// embedded Shoot, in the cluster namespace).
func clusterToInfrastructureMapper() func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		logger := log.FromContext(ctx).WithName("cluster-unfailed-watcher")
		cluster, ok := obj.(*extensionsv1alpha1.Cluster)
		if !ok || cluster == nil {
			return nil
		}
		// Cluster name == shoot namespace (e.g. "shoot--<project>--<shoot>").
		// The Infrastructure for that namespace is named by the embedded shoot.
		shoot := &gardencorev1beta1.Shoot{}
		if cluster.Spec.Shoot.Raw == nil {
			return nil
		}
		if err := json.Unmarshal(cluster.Spec.Shoot.Raw, shoot); err != nil {
			logger.Error(err, "decode embedded Shoot")
			return nil
		}
		req := reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: cluster.Name,
				Name:      shoot.Name,
			},
		}
		logger.Info("shoot transitioned out of Failed — re-enqueueing Infrastructure",
			"namespace", req.Namespace, "name", req.Name)
		return []reconcile.Request{req}
	}
}
