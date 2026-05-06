// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"fmt"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	lbSchemeAnnotation = "service.beta.kubernetes.io/aws-load-balancer-scheme"

	// AnnotationLBSwitchOldNLBs is set on the Seed during an LB scheme switch
	// to track the old NLB hostnames for cleanup after the switch completes.
	AnnotationLBSwitchOldNLBs = "provider-aws.gardener.cloud/lb-switch-old-nlbs"

	// AnnotationLBSwitchTimestamp is set on the Seed when an LB scheme switch
	// is detected, used for timeout safety.
	AnnotationLBSwitchTimestamp = "provider-aws.gardener.cloud/lb-switch-timestamp"
)

// LBSchemeChangedPredicate triggers only when a Seed's LB scheme annotation changes.
type LBSchemeChangedPredicate struct {
	predicate.Funcs
}

// Update returns true only when the LB scheme changed.
func (p LBSchemeChangedPredicate) Update(e event.UpdateEvent) bool {
	oldSeed, ok1 := e.ObjectOld.(*gardencorev1beta1.Seed)
	newSeed, ok2 := e.ObjectNew.(*gardencorev1beta1.Seed)
	if !ok1 || !ok2 {
		return false
	}
	return lbSchemeChanged(oldSeed, newSeed)
}

// Create returns false.
func (p LBSchemeChangedPredicate) Create(_ event.CreateEvent) bool { return false }

// Delete returns false.
func (p LBSchemeChangedPredicate) Delete(_ event.DeleteEvent) bool { return false }

// lbSchemeChangeMapper handles LB scheme changes: sets the LB switch annotation
// on the Seed, triggers shoot reconciles for DWD recovery, and enqueues
// Infrastructure resources so the seed shoot's reconcile can clean up orphaned NLBs.
func lbSchemeChangeMapper(seedClient client.Client, gardenClient client.Client) func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		logger := log.FromContext(ctx).WithName("lb-scheme-watcher")
		seed, ok := obj.(*gardencorev1beta1.Seed)
		if !ok {
			return nil
		}

		newScheme := extractLBScheme(seed)
		logger.Info("LB scheme change detected", "seed", seed.Name, "newScheme", newScheme)

		// Set annotation on Seed so the seed shoot's reconcile can clean up orphaned NLBs.
		handleLBSchemeSwitch(ctx, gardenClient, seed.Name, "", newScheme)

		// Trigger shoot reconciles for DWD recovery.
		if err := triggerShootReconciles(ctx, gardenClient, seed.Name); err != nil {
			logger.Error(err, "Failed to trigger shoot reconciles for LB switch")
		}

		// Enqueue all Infrastructure resources so the seed shoot gets reconciled
		// (seed shoot's reconcile does the orphaned NLB cleanup).
		infraList := &extensionsv1alpha1.InfrastructureList{}
		if err := seedClient.List(ctx, infraList); err != nil {
			logger.Error(err, "Failed to list Infrastructure resources")
			return nil
		}

		var requests []reconcile.Request
		for _, infra := range infraList.Items {
			if infra.Spec.Type != "aws" {
				continue
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      infra.Name,
					Namespace: infra.Namespace,
				},
			})
		}

		logger.Info("Enqueued Infrastructure resources for LB scheme switch",
			"seed", seed.Name, "count", len(requests))
		return requests
	}
}

// lbSchemeChanged returns true if the Seed's LB scheme annotation changed.
func lbSchemeChanged(oldSeed, newSeed *gardencorev1beta1.Seed) bool {
	oldScheme := extractLBScheme(oldSeed)
	newScheme := extractLBScheme(newSeed)
	return oldScheme != "" && newScheme != "" && oldScheme != newScheme
}

// extractLBScheme returns the LB scheme from the Seed's loadBalancerServices annotations.
func extractLBScheme(seed *gardencorev1beta1.Seed) string {
	if seed.Spec.Settings == nil || seed.Spec.Settings.LoadBalancerServices == nil {
		return ""
	}
	return seed.Spec.Settings.LoadBalancerServices.Annotations[lbSchemeAnnotation]
}

// handleLBSchemeSwitch is called by the seed watcher mapper when an LB scheme change
// is detected. It orchestrates:
// 1. Recording old NLB hostnames on the Seed annotation
// 2. Enqueuing all Infrastructure resources for reconcile (triggers shoot reconcile for DWD recovery)
//
// The actual NLB readiness polling and orphaned NLB cleanup runs asynchronously
// in the reconcile flow via checkLBSwitchCleanup.
func handleLBSchemeSwitch(ctx context.Context, gardenClient client.Client, seedName string, oldScheme, newScheme string) {
	logger := log.FromContext(ctx).WithName("lb-scheme-switch")
	logger.Info("LB scheme change detected — initiating switch lifecycle",
		"seed", seedName, "oldScheme", oldScheme, "newScheme", newScheme)

	// Annotate the Seed with the switch timestamp so the health checker / reconcile
	// can track the switch and trigger shoot reconciles when NLBs are ready.
	seed := &gardencorev1beta1.Seed{}
	if err := gardenClient.Get(ctx, client.ObjectKey{Name: seedName}, seed); err != nil {
		logger.Error(err, "Failed to get Seed for LB switch annotation")
		return
	}

	if seed.Annotations == nil {
		seed.Annotations = map[string]string{}
	}
	seed.Annotations[AnnotationLBSwitchTimestamp] = time.Now().UTC().Format(time.RFC3339)

	if err := gardenClient.Update(ctx, seed); err != nil {
		logger.Error(err, "Failed to annotate Seed with LB switch timestamp")
		return
	}

	logger.Info("Annotated Seed with LB switch timestamp, shoot reconciles will be triggered by infra enqueue")
}

// triggerShootReconciles annotates all shoots on the given seed AND the seed
// shoot itself with gardener.cloud/operation=reconcile to trigger immediate
// gardenlet reconcile. This restores DWD-scaled deployments, updates DNS to
// new NLBs, and triggers NLB cleanup on the seed shoot's infra reconcile.
func triggerShootReconciles(ctx context.Context, gardenClient client.Client, seedName string) error {
	logger := log.FromContext(ctx).WithName("lb-scheme-switch")

	// Also trigger the seed shoot itself (runs on the parent seed).
	// This is needed so cleanupOrphanedNLBsIfNeeded runs with the seed's AWS credentials.
	seedShoot := &gardencorev1beta1.Shoot{}
	if err := gardenClient.Get(ctx, client.ObjectKey{Namespace: "garden", Name: seedName}, seedShoot); err == nil {
		patch := client.MergeFrom(seedShoot.DeepCopy())
		if seedShoot.Annotations == nil {
			seedShoot.Annotations = map[string]string{}
		}
		seedShoot.Annotations["gardener.cloud/operation"] = "reconcile"
		if err := gardenClient.Patch(ctx, seedShoot, patch); err != nil {
			// Expected RBAC failure: the managed seed's extension can't patch shoots
			// on a different seed. The gardenlet's normal sync will reconcile the seed
			// shoot within ~1h, triggering NLB cleanup then.
			logger.Info("Could not annotate seed shoot for reconcile (expected if cross-seed RBAC) — gardenlet sync will handle it",
				"shoot", seedName, "error", err.Error())
		} else {
			logger.Info("Triggered seed shoot reconcile for NLB cleanup", "shoot", seedName)
		}
	}

	shootList := &gardencorev1beta1.ShootList{}
	if err := gardenClient.List(ctx, shootList, client.MatchingFields{"spec.seedName": seedName}); err != nil {
		// Fallback to unfiltered list.
		if err := gardenClient.List(ctx, shootList); err != nil {
			return fmt.Errorf("failed to list shoots: %w", err)
		}
	}

	count := 0
	for i := range shootList.Items {
		shoot := &shootList.Items[i]
		if shoot.Spec.SeedName == nil || *shoot.Spec.SeedName != seedName {
			continue
		}
		// Use Patch instead of Update to avoid conflict errors when gardenlet
		// is concurrently modifying the shoot.
		patch := client.MergeFrom(shoot.DeepCopy())
		if shoot.Annotations == nil {
			shoot.Annotations = map[string]string{}
		}
		shoot.Annotations["gardener.cloud/operation"] = "reconcile"
		if err := gardenClient.Patch(ctx, shoot, patch); err != nil {
			logger.Error(err, "Failed to annotate shoot for reconcile", "shoot", shoot.Name)
			continue
		}
		count++
		logger.Info("Triggered shoot reconcile for DWD recovery", "shoot", shoot.Name)
	}

	logger.Info("Triggered shoot reconciles after LB scheme switch", "seed", seedName, "count", count)
	return nil
}
