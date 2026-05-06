// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Prometheus metrics for the TGW invariant route sweep and reconcile drift
// signaling. Auto-exposed at the controller-runtime /metrics endpoint.
//
// Operator value:
//   * rate(tgw_sweep_replacements_total{type="blackhole"}[5m]) shows
//     mode-switch activity (cross-TGW transitions).
//   * tgw_blackhole_unverifiable_total > 0 means manual review needed for
//     blackhole routes whose abandoned TGW we cannot prove was ours.
//   * rate(tgw_reconcile_requeue_total[5m]) shows the completion gate
//     firing — drift is not converging in a single reconcile pass.
//   * tgw_sweep_cap_reached_total > 0 is a defensive signal: investigate
//     before acting, the sweep hit its per-reconcile cap.
//   * tgw_drift_detected_total{source} attributes drift to its source
//     (phase0 = TGW change, sweep = invariant sweep replacement, etc.).
var (
	metricSweepReplacements = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tgw_sweep_replacements_total",
			Help: "Total ReplaceRoute calls made by the invariant sweep, by route state at time of sweep (active = stale active route, blackhole = AWS-marked blackhole route).",
		},
		[]string{"type"},
	)

	metricBlackholeUnverifiable = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tgw_blackhole_unverifiable_total",
			Help: "Blackhole routes the invariant sweep skipped because the abandoned TGW could not be proved as previously ours (state history empty AND live cluster-tag check failed). Operators should review.",
		},
	)

	metricReconcileRequeue = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tgw_reconcile_requeue_total",
			Help: "Reconcile completion gate triggers — drift remained after the final sweep, so Reconcile returned an error to requeue.",
		},
	)

	metricDriftDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tgw_drift_detected_total",
			Help: "Drift detections by source within a single reconcile (phase0 = TGW ID change, phase1 = stale attachment flagged, sweep_active = stale active route swept, sweep_blackhole = blackhole route swept, transient = transient AWS error during sweep).",
		},
		[]string{"source"},
	)

	metricSweepCapReached = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tgw_sweep_cap_reached_total",
			Help: "Per-reconcile sweep cap (maxSweepReplacesPerReconcile) was hit. Defensive signal — investigate for an unintended replace loop.",
		},
	)

	// metricAssociationDrift counts seed-side TGW attachments observed associated
	// with the wrong route table for the current isolation mode. Partitioned by
	// attachment role. Non-zero rate means the canonical-owner contract is
	// drifting and assertSeedSideAssociations is correcting it.
	metricAssociationDrift = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tgw_association_drift_total",
			Help: "Seed-side TGW attachment associations that did not match the configured isolation mode (hub-spoke ↔ shared). Partitioned by attachment role (seed, runtime, globalvpc).",
		},
		[]string{"role"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		metricSweepReplacements,
		metricBlackholeUnverifiable,
		metricReconcileRequeue,
		metricDriftDetected,
		metricSweepCapReached,
		metricAssociationDrift,
	)
}
