// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

// privateRouteTableNameFilter is the substring used to identify private (non-public, non-main)
// route tables by their Name tag. Only private route tables get TGW routes injected.
const privateRouteTableNameFilter = "private"

// reconcileTGWState ensures that the actual AWS TGW state matches the desired config.
// Discovery-based: queries AWS for what exists, compares with desired state, cleans the diff.
// Called after TGW ID resolution in ensureTransitGateway, before any other DAG tasks.
//
// Handles:
//   - Shoot VPC attachments on the wrong TGW (from mode switches)
//   - Orphaned RTs that don't match the current isolation mode
//   - Duplicate RTs from concurrent child shoot reconciles
//   - Stale routes in runtime/globalVPCs pointing to old TGW
//   - Old managed TGW cleanup (attachments, RTs, TGW itself)
//   - Full state reset when TGW ID changes
//
// Returns true if drift was detected and fixed (caller should requeue to verify).
func (c *FlowContext) reconcileTGWState(ctx context.Context, log logr.Logger, tgwID string) (bool, error) {
	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get TGW client: %w", err)
	}

	driftDetected := false
	vpcID := c.state.Get(IdentifierVPC)
	seedShootNS := c.seedShootNamespace

	// --- Phase 0: Detect TGW ID change and reset ALL stale state ---
	previousTGWID := c.state.Get(IdentifierTransitGatewayID)
	tgwChanged := previousTGWID != nil && *previousTGWID != tgwID
	// Record the current AND previous TGW IDs in our ownership history BEFORE
	// the reset wipes other state. Defense in depth — also recorded at the top
	// of reconcile() (caller). The history is consulted by isAbandonedTGWOurs
	// to verify a blackhole's abandoned TGW even after the TGW is deleted from
	// AWS. Both writes are idempotent (Set on existing entry is a no-op).
	c.recordTGWInHistory(log, tgwID)
	if previousTGWID != nil {
		c.recordTGWInHistory(log, *previousTGWID)
	}
	if tgwChanged {
		driftDetected = true
		metricDriftDetected.WithLabelValues("phase0").Inc()
		log.Info("TGW ID changed — resetting all TGW state",
			"previousTGW", *previousTGWID, "newTGW", tgwID)
		c.event(corev1.EventTypeWarning, "TGWModeSwitch", "Transit Gateway changed from %s to %s — resetting all TGW state and migrating attachments", *previousTGWID, tgwID)
		for _, key := range []string{
			IdentifierTransitGatewayAttachment,
			IdentifierSeedVPCTransitGatewayAttachment,
			IdentifierRuntimeVPCTransitGatewayAttachment,
			IdentifierRuntimeVPCID,
			IdentifierRuntimeVPCCIDR,
			IdentifierTransitGatewayManaged,
			IdentifierTransitGatewaySharedRouteTable,
			IdentifierTransitGatewayHubRouteTable,
			IdentifierTransitGatewaySpokeRouteTable,
			IdentifierTransitGatewaySharedRouteTable + "Managed",
			IdentifierTransitGatewayHubRouteTable + "Managed",
			IdentifierTransitGatewaySpokeRouteTable + "Managed",
		} {
			c.state.Delete(key)
		}
	}

	// --- Phase 1: FLAG stale attachments for deferred cleanup ---
	// Don't delete yet — the new attachment must be created first (by ensureTransitGatewayAttachment)
	// to avoid a connectivity gap that triggers DWD. Stale attachments are cleaned up by
	// cleanupStaleAttachments() which runs AFTER the new attachment is created.
	if vpcID != nil {
		allAtts, err := tgwClient.FindTransitGatewayVPCAttachments(ctx, "", *vpcID)
		if err != nil {
			log.Info("warning: failed to find VPC attachments for cleanup", "vpcId", *vpcID, "error", err)
		} else {
			shootPrefix := c.namespace + "-"
			for _, att := range allAtts {
				if att.TransitGatewayId != tgwID {
					attName := att.Tags["Name"]
					if strings.HasPrefix(attName, shootPrefix) {
						driftDetected = true
						metricDriftDetected.WithLabelValues("phase1").Inc()
						c.staleAttachmentIDs = append(c.staleAttachmentIDs, att.TransitGatewayAttachmentId)
						log.Info("flagged stale attachment for deferred cleanup (will delete after new attachment created)",
							"attachmentId", att.TransitGatewayAttachmentId,
							"wrongTGW", att.TransitGatewayId, "correctTGW", tgwID)
						c.event(corev1.EventTypeWarning, "TGWStaleAttachment", "Stale VPC attachment %s on wrong TGW %s (expected %s) — scheduled for cleanup", att.TransitGatewayAttachmentId, att.TransitGatewayId, tgwID)
					}
				}
			}
		}
	}

	// --- Phase 1a: Cross-VPC stale flag — find ALL of our attachments on wrong TGW ---
	//
	// Phase 1 above only catches stale attachments for the SHOOT's own VPC. But this
	// shoot's reconcile may also have created attachments for OTHER VPCs (the seed
	// VPC, mgmt globalVPC, etc.) tagged with our cluster identifier. After a TGW
	// switch, those attachments live on the abandoned TGW and need cleanup too.
	//
	// We search by cluster tag (kubernetes.io/cluster/<this-shoot-namespace>) to find
	// every attachment we created across all VPCs, then flag any not on the current TGW.
	clusterTag := awsclient.Tags{c.tagKeyCluster(): TagValueCluster}
	ourAtts, ourErr := tgwClient.FindTransitGatewayVPCAttachmentsByTags(ctx, clusterTag)
	if ourErr != nil {
		log.Info("warning: failed to find our TGW attachments by cluster tag", "error", ourErr)
	} else {
		seen := sets.New[string]()
		for _, attID := range c.staleAttachmentIDs {
			seen.Insert(attID)
		}
		for _, att := range ourAtts {
			if att.TransitGatewayId == tgwID || isAttachmentTerminal(att.State) {
				continue
			}
			if seen.Has(att.TransitGatewayAttachmentId) {
				continue
			}
			driftDetected = true
			metricDriftDetected.WithLabelValues("phase1a").Inc()
			c.staleAttachmentIDs = append(c.staleAttachmentIDs, att.TransitGatewayAttachmentId)
			seen.Insert(att.TransitGatewayAttachmentId)
			log.Info("flagged stale attachment by cluster tag (cross-VPC)",
				"attachmentId", att.TransitGatewayAttachmentId,
				"name", att.Tags["Name"],
				"vpcId", att.VpcId,
				"wrongTGW", att.TransitGatewayId, "correctTGW", tgwID)
			c.event(corev1.EventTypeWarning, "TGWStaleAttachment",
				"Stale VPC attachment %s (vpc=%s, name=%s) on wrong TGW %s (expected %s) — scheduled for cleanup",
				att.TransitGatewayAttachmentId, att.VpcId, att.Tags["Name"], att.TransitGatewayId, tgwID)
		}
	}

	// (Topology-invariant check runs from ensureTransitGateway AFTER RT
	// resolution, not from here. This phase pre-dates RT resolution and
	// would always see empty resolvedHubRouteTableID.)

	// --- Phase 1b: Delete blackhole TGW routes in this shoot's OWN VPC ---
	//
	// When switching TGW modes (or after an external delete of an old TGW), the
	// shoot VPC's route tables may have routes pointing to a now-deleted TGW
	// that AWS marks as `blackhole`. Cleaning them prevents future CreateRoute
	// calls from failing with RouteAlreadyExists when re-adding the same CIDR
	// against the new TGW.
	//
	// SCOPE LIMIT: only the SHOOT's own VPC. An earlier version extended
	// to seed/runtime/globalVPC RTs, but that was the wrong layer — those RTs
	// are maintained by *other* reconciles (the seed shoot's, each other child
	// shoot's). Deleting a blackhole here doesn't restore the correct route;
	// only the canonical reconcile for that route's CIDR can. Worse, between
	// the delete and the canonical reconcile, the destination is unreachable.
	//
	// For TGW-switch-induced blackholes in seed/runtime/globalVPC RTs, Phase 3
	// (sweepStaleRoutesToCurrentTGW) does the right thing — atomic ReplaceRoute
	// to the current TGW, no observable gap. Don't double up here.
	if vpcID != nil {
		shootRTs, rtErr := c.client.FindRouteTablesByFilters(ctx, []ec2types.Filter{
			{Name: ptr.To("vpc-id"), Values: []string{*vpcID}},
		})
		if rtErr != nil {
			log.Info("warning: failed to find shoot VPC route tables for blackhole cleanup", "error", rtErr)
		} else {
			for _, rt := range shootRTs {
				if !strings.Contains(rt.Tags["Name"], privateRouteTableNameFilter) {
					continue
				}
				for _, r := range rt.Routes {
					if r.TransitGatewayId != nil && r.State != nil && *r.State == "blackhole" && r.DestinationCidrBlock != nil {
						driftDetected = true
						log.Info("deleting blackhole route in shoot VPC",
							"routeTableId", rt.RouteTableId, "cidr", *r.DestinationCidrBlock,
							"staleTGW", *r.TransitGatewayId)
						c.event(corev1.EventTypeWarning, "TGWBlackholeRoute",
							"Deleted blackhole route %s → %s in shoot VPC", *r.DestinationCidrBlock, *r.TransitGatewayId)
						if delErr := c.client.DeleteRoute(ctx, rt.RouteTableId, &awsclient.Route{
							DestinationCidrBlock: r.DestinationCidrBlock,
						}); delErr != nil {
							log.Info("warning: failed to delete blackhole route",
								"routeTableId", rt.RouteTableId, "cidr", *r.DestinationCidrBlock, "error", delErr)
						}
					}
				}
			}
		}
	}

	// --- Phase 2: Clean orphaned/duplicate RTs on managed TGW ---
	if c.isManagedTGWMode() {
		if cleaned := c.cleanOrphanedRouteTables(ctx, log, tgwClient, tgwID, seedShootNS); cleaned {
			driftDetected = true
		}
	}

	// Phase 3 (invariant-based stale-TGW route sweep) runs as a separate DAG task
	// `sweepStaleTGWRoutesAcrossVPCs` after ensureRuntimeVPCAttachment, because Phase 0
	// above wipes IdentifierRuntimeVPCID on tgwChanged, and the sweep needs that ID to
	// find runtime VPC route tables. Running the sweep here would silently no-op for
	// the runtime VPC every cross-TGW switch — exactly the bug observed in earlier testing.

	// --- Phase 4: Cleanup orphaned managed TGWs ---
	// Runs on every reconcile regardless of current mode (ref or managed). Orphaned
	// managed TGWs from a previous mode need cleanup even after switching to ref mode.
	// Scoped to seedShootNS tags: only finds TGWs we created for this seed.
	// The child-count guard inside the function ensures we don't delete a TGW that
	// still has shoots attached (they haven't reconciled to the new TGW yet).
	if seedShootNS != "" {
		c.cleanupOrphanedManagedTGWs(ctx, log, tgwID, seedShootNS)
	}

	if driftDetected {
		log.Info("TGW drift detected and fixed — reconcile will be requeued to verify")
	}
	return driftDetected, nil
}

// cleanOrphanedRouteTables finds and deletes RTs on the managed TGW that don't match
// the current isolation mode (e.g., shared RTs left over from a hub-spoke switch) or
// duplicate RTs from concurrent child shoot reconciles.
// Returns true if any orphaned RTs were cleaned up.
func (c *FlowContext) cleanOrphanedRouteTables(ctx context.Context, log logr.Logger, tgwClient awsclient.Interface, tgwID, seedShootNS string) bool {
	seedTags := awsclient.Tags{
		fmt.Sprintf(TagKeyClusterTemplate, seedShootNS): TagValueCluster,
	}
	allRTs, err := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, seedTags)
	if err != nil {
		log.Info("warning: failed to find TGW RTs by tags", "error", err)
		return false
	}

	wantShared := c.isSharedIsolationMode()
	var keepRTs, orphanRTs []string
	rtsByPurpose := map[string][]string{}

	for _, rt := range allRTs {
		if rt.TransitGatewayId != tgwID {
			continue
		}
		name := rt.Tags["Name"]
		var purpose string
		switch {
		case strings.HasSuffix(name, "-tgw-rt-hub"):
			purpose = "hub"
		case strings.HasSuffix(name, "-tgw-rt-spoke"):
			purpose = "spoke"
		case strings.HasSuffix(name, "-tgw-rt-shared"):
			purpose = "shared"
		default:
			continue
		}
		rtsByPurpose[purpose] = append(rtsByPurpose[purpose], rt.TransitGatewayRouteTableId)
	}

	for purpose, ids := range rtsByPurpose {
		isWanted := (wantShared && purpose == "shared") || (!wantShared && (purpose == "hub" || purpose == "spoke"))
		if isWanted {
			sort.Strings(ids)
			keepRTs = append(keepRTs, ids[0])
			orphanRTs = append(orphanRTs, ids[1:]...)
		} else {
			orphanRTs = append(orphanRTs, ids...)
		}
	}

	if len(orphanRTs) == 0 {
		return false
	}

	log.Info("attempting to clean orphaned/duplicate RTs", "keep", keepRTs, "orphan", orphanRTs)

	// Attempt to delete orphan RTs. AWS rejects deletion of RTs with active
	// associations or propagations (returns IncorrectState). DO NOT forcibly
	// disassociate attachments here — that creates a connectivity gap (the same
	// bug that breaks isolation mode switches). Instead, rely on AWS's safety
	// check: if RT is in use, delete fails, we leave it for next reconcile.
	//
	// Self-healing flow:
	// - Phase 1+2 isolation switch (in ensureTransitGatewayAttachment / ensureSeedVPCAttachment)
	//   moves attachments to the wanted RT, with propagation cleanup on the old RT.
	// - Once all attachments have moved AND old RT propagations are cleaned,
	//   the orphan RT becomes truly empty and AWS allows deletion.
	deletedAny := false
	stillInUse := []string{}
	for _, orphanRT := range orphanRTs {
		log.Info("attempting to delete orphan RT", "routeTableId", orphanRT)
		if delErr := tgwClient.DeleteTransitGatewayRouteTable(ctx, orphanRT); delErr != nil {
			code := awsclient.GetAWSAPIErrorCode(delErr)
			if code == "IncorrectState" || strings.Contains(delErr.Error(), "associations") || strings.Contains(delErr.Error(), "propagations") {
				log.Info("orphan RT still in use — leaving for next reconcile",
					"routeTableId", orphanRT, "code", code)
				stillInUse = append(stillInUse, orphanRT)
			} else {
				log.Info("warning: failed to delete orphan RT", "rt", orphanRT, "error", delErr)
				stillInUse = append(stillInUse, orphanRT)
			}
		} else {
			log.Info("orphan RT deleted (was unused)", "routeTableId", orphanRT)
			deletedAny = true
		}
	}

	if len(stillInUse) > 0 {
		log.Info("some orphan RTs still in use — will retry on next reconcile",
			"stillInUse", stillInUse)
	}

	// Only clear RT state if we actually deleted RTs that were tracked in state.
	// Don't blindly clear — the RTs the state references may still be the wanted ones.
	if deletedAny {
		for _, key := range []string{
			IdentifierTransitGatewaySharedRouteTable,
			IdentifierTransitGatewayHubRouteTable,
			IdentifierTransitGatewaySpokeRouteTable,
		} {
			v := c.state.Get(key)
			if v == nil {
				continue
			}
			// Only clear state for RTs we just deleted.
			for _, deletedRT := range orphanRTs {
				wasStillInUse := false
				for _, inUse := range stillInUse {
					if inUse == deletedRT {
						wasStillInUse = true
						break
					}
				}
				if !wasStillInUse && *v == deletedRT {
					c.state.Delete(key)
					c.state.Delete(key + "Managed")
				}
			}
		}
	}

	// Log duplicate resolution.
	for purpose, ids := range rtsByPurpose {
		isWanted := (wantShared && purpose == "shared") || (!wantShared && (purpose == "hub" || purpose == "spoke"))
		if isWanted && len(ids) > 1 {
			log.Info("resolved duplicate RTs for purpose", "purpose", purpose, "kept", ids[0], "deleted", ids[1:])
		}
	}

	return true
}

// cleanupOrphanedManagedTGWs finds and deletes any managed TGWs tagged with our seed
// that are NOT the currently resolved TGW. Handles the managed→ref switch case.
func (c *FlowContext) cleanupOrphanedManagedTGWs(ctx context.Context, log logr.Logger, currentTGWID, seedShootNS string) {
	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		log.Info("warning: failed to get TGW client for orphaned TGW cleanup", "error", err)
		return
	}

	seedTags := awsclient.Tags{
		fmt.Sprintf(TagKeyClusterTemplate, seedShootNS): TagValueCluster,
	}
	allTGWs, err := tgwClient.FindTransitGatewaysByTags(ctx, seedTags)
	if err != nil {
		log.Info("warning: failed to find managed TGWs by tags", "error", err)
		return
	}

	for _, tgw := range allTGWs {
		if tgw.TransitGatewayId == currentTGWID {
			continue // Current TGW — don't touch.
		}

		log.Info("found orphaned managed TGW — cleaning up", "tgwId", tgw.TransitGatewayId)
		c.event(corev1.EventTypeWarning, "TGWOrphanedCleanup", "Cleaning up orphaned managed Transit Gateway %s", tgw.TransitGatewayId)

		// Check for remaining child shoot attachments.
		allAtts, listErr := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgw.TransitGatewayId)
		if listErr != nil {
			log.Info("warning: failed to list orphaned TGW attachments", "error", listErr)
			continue
		}
		otherChildShoots := 0
		for _, att := range allAtts {
			name := att.Tags["Name"]
			if strings.Contains(name, "-seed-vpc-") || strings.Contains(name, "-runtime-vpc-") || strings.Contains(name, "-gvpc-") {
				continue
			}
			otherChildShoots++
		}
		if otherChildShoots > 0 {
			log.Info("orphaned TGW still has child shoot attachments — skipping", "tgwId", tgw.TransitGatewayId, "count", otherChildShoots)
			continue
		}

		// Delete all attachments.
		for _, att := range allAtts {
			log.Info("deleting orphaned TGW attachment", "attachmentId", att.TransitGatewayAttachmentId)
			if delErr := tgwClient.DeleteTransitGatewayVPCAttachment(ctx, att.TransitGatewayAttachmentId); delErr != nil {
				log.Info("warning: failed to delete orphaned TGW attachment", "attachment", att.TransitGatewayAttachmentId, "error", delErr)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		// Delete RTs by tag discovery.
		allRTs, rtErr := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, seedTags)
		if rtErr == nil {
			for _, rt := range allRTs {
				if rt.TransitGatewayId == tgw.TransitGatewayId {
					log.Info("deleting orphaned TGW RT", "routeTableId", rt.TransitGatewayRouteTableId)
					if delErr := tgwClient.DeleteTransitGatewayRouteTable(ctx, rt.TransitGatewayRouteTableId); delErr != nil {
						log.Info("warning: failed to delete orphaned TGW RT", "rt", rt.TransitGatewayRouteTableId, "error", delErr)
					}
				}
			}
		}

		// Delete the TGW.
		log.Info("deleting orphaned managed TGW", "tgwId", tgw.TransitGatewayId)
		if delErr := tgwClient.DeleteTransitGateway(ctx, tgw.TransitGatewayId); delErr != nil {
			log.Info("warning: failed to delete orphaned managed TGW", "tgwId", tgw.TransitGatewayId, "error", delErr)
		}
	}
}

// collectAutoManagedCIDRs returns the set of CIDRs whose VPC RT routes are
// owned by the extension's TGW reconcile. Used to scope the invariant sweep
// (sweepStaleRoutesToCurrentTGW) so it never touches user custom TGW routes.
//
// The set is the union of:
//   - this shoot's own VPC CIDR (added to seed/runtime/globalVPC RTs as return path)
//   - the seed nodes CIDR (added to shoot/runtime/globalVPC RTs)
//   - peer shoot CIDRs (in shared mode, peers route to each other)
//   - effective globalVPC CIDRs (mgmt + auto-injected runtime VPC primary CIDR)
func (c *FlowContext) collectAutoManagedCIDRs() sets.Set[string] {
	cidrs := sets.New[string]()
	if c.seedNodesCIDR != "" {
		cidrs.Insert(c.seedNodesCIDR)
	}
	if c.config != nil && c.config.Networks.VPC.CIDR != nil && *c.config.Networks.VPC.CIDR != "" {
		cidrs.Insert(*c.config.Networks.VPC.CIDR)
	}
	for _, cidr := range c.peerShootCIDRs {
		if cidr != "" {
			cidrs.Insert(cidr)
		}
	}
	for _, gvpc := range c.resolvedEffectiveGlobalVPCs {
		for _, cidr := range gvpc.CIDRs {
			if cidr != "" {
				cidrs.Insert(cidr)
			}
		}
	}
	return cidrs
}

// maxSweepReplacesPerReconcile bounds the number of ReplaceRoute calls the
// invariant sweep makes in a single reconcile. Defense against a regression
// pushing the sweep into an unintended replacement loop. Validated at 20
// during testing — comfortably above the ~10 replaces a
// normal mode-switch generates across all VPCs.
const maxSweepReplacesPerReconcile = 20

// historyOversizeWarnThreshold is the entry count above which we emit an
// info log (not error) signaling unusual cluster behavior. NO hard cap.
const historyOversizeWarnThreshold = 100

// sweepStaleRoutesToCurrentTGW iterates the VPC's private route tables in two
// tiers and atomically ReplaceRoutes any stale TGW target to currentTGWID.
// Returns true if any replacements were made (caller should set
// tgwDriftDetected so a follow-up reconcile re-verifies).
//
// Tier 1 — ACTIVE stale (state=active, target≠currentTGW):
//   - Require CIDR ∈ autoManagedCIDRs.
//   - Preserves the original user-route safety guarantee — never touch
//     a user's custom-CIDR active route to a non-Gardener TGW.
//
// Tier 2 — BLACKHOLE (state=blackhole, target≠currentTGW):
//   - Require CIDR ∈ extendedAutoManagedCIDRs (autoManagedCIDRs ∪ CIDRs of
//     every VPC currently attached to currentTGW). Captures cross-shoot
//     CIDRs the seed shoot's peerShootCIDRs misses.
//   - AND require provable ownership of the abandoned TGW via
//     isAbandonedTGWOurs (state history OR live cluster-tag check).
//   - Distinguishes transient AWS errors from definitive "not ours" — the
//     transient case skips this entry only and signals drift for retry, the
//     definitive case emits TGWBlackholeUnverifiable for operator review.
//
// Per-reconcile cap (maxSweepReplacesPerReconcile) bounds blast radius if a
// regression pushes the sweep into an unintended replacement loop.
func (c *FlowContext) sweepStaleRoutesToCurrentTGW(
	ctx context.Context,
	log logr.Logger,
	awsClient awsclient.Interface,
	vpcID string,
	currentTGWID string,
	autoManagedCIDRs sets.Set[string],
	description string,
) bool {
	if currentTGWID == "" || autoManagedCIDRs.Len() == 0 {
		return false
	}
	rts, err := awsClient.FindRouteTablesByFilters(ctx, []ec2types.Filter{
		{Name: ptr.To("vpc-id"), Values: []string{vpcID}},
	})
	if err != nil {
		log.Info("warning: failed to find route tables for invariant sweep",
			"vpcId", vpcID, "description", description, "error", err)
		return false
	}
	swept := 0
	for _, rt := range rts {
		if !strings.Contains(rt.Tags["Name"], privateRouteTableNameFilter) {
			continue
		}
		for _, r := range rt.Routes {
			if r.TransitGatewayId == nil || r.DestinationCidrBlock == nil {
				continue
			}
			if *r.TransitGatewayId == currentTGWID {
				continue
			}
			if c.tgwSweepReplacesThisReconcile >= maxSweepReplacesPerReconcile {
				log.Info("invariant sweep: per-reconcile cap reached — abandoning this run",
					"cap", maxSweepReplacesPerReconcile, "vpcId", vpcID, "description", description)
				c.event(corev1.EventTypeWarning, "TGWSweepCapReached",
					"Invariant sweep hit %d replaces in one reconcile — abandoning. Investigate before re-running.",
					maxSweepReplacesPerReconcile)
				metricSweepCapReached.Inc()
				return swept > 0
			}
			isBlackhole := r.State != nil && *r.State == "blackhole"
			abandonedTGW := *r.TransitGatewayId
			cidr := *r.DestinationCidrBlock

			var reason string
			if isBlackhole {
				// Tier 2 — blackhole.
				//
				// Ownership-proof is SUFFICIENT for blackhole sweep (no CIDR scope
				// check). Logic: if the abandoned TGW is provably ours (history or
				// live cluster-tag), then ANY route in our managed VPC RT pointing
				// at that TGW must have been a route WE created (we're the only
				// one writing routes to our TGW in our managed VPCs). The CIDR
				// is by transitive logic an "auto-managed CIDR" even if it isn't
				// in the static set — captures cross-shoot CIDRs that the seed
				// shoot's per-namespace scope misses (e.g., child shoot CIDRs
				// blackholed in runtime VPC after a cross-TGW switch, before the
				// child shoots have moved their attachments to the new TGW).
				//
				// This change replaces the prior `extendedAutoManagedCIDRs` filter
				// for the blackhole tier — that filter was insufficient because
				// it only included CIDRs of VPCs CURRENTLY attached to the new
				// TGW, missing CIDRs that were attached to the old TGW but not
				// yet migrated. Active-stale tier still uses autoManagedCIDRs
				// (narrow scope) to preserve user-route safety.
				ours, transient := c.isAbandonedTGWOurs(ctx, log, awsClient, abandonedTGW)
				if !ours {
					if transient {
						log.Info("invariant sweep: ownership check transient — deferring this entry",
							"rt", rt.RouteTableId, "cidr", cidr, "abandonedTGW", abandonedTGW)
						c.event(corev1.EventTypeWarning, "TGWBlackholeTransient",
							"Blackhole route %s in %s targets %s — ownership check transient, will retry.",
							cidr, description, abandonedTGW)
						metricDriftDetected.WithLabelValues("transient").Inc()
						c.tgwDriftDetected = true
						continue
					}
					log.Info("invariant sweep: blackhole abandoned-TGW unverifiable — skipping",
						"rt", rt.RouteTableId, "cidr", cidr, "abandonedTGW", abandonedTGW, "in", description)
					c.event(corev1.EventTypeWarning, "TGWBlackholeUnverifiable",
						"Blackhole route %s in %s targets %s — cannot prove this TGW was ours, skipping. Manual review recommended.",
						cidr, description, abandonedTGW)
					metricBlackholeUnverifiable.Inc()
					continue
				}
				reason = "TGWBlackholeReplaced"
			} else {
				// Tier 1 — active stale (narrow CIDR scope to protect user routes).
				if !autoManagedCIDRs.Has(cidr) {
					continue
				}
				reason = "TGWStaleRoute"
			}

			log.Info("invariant sweep: replacing stale TGW route",
				"rt", rt.RouteTableId, "cidr", cidr,
				"oldTGW", abandonedTGW, "newTGW", currentTGWID,
				"blackhole", isBlackhole, "in", description)
			c.event(corev1.EventTypeWarning, reason,
				"Replacing stale route %s in %s: %s → %s (blackhole=%v)",
				cidr, description, abandonedTGW, currentTGWID, isBlackhole)
			tgwIDCopy := currentTGWID
			if replaceErr := awsClient.ReplaceRoute(ctx, rt.RouteTableId, &awsclient.Route{
				DestinationCidrBlock: r.DestinationCidrBlock,
				TransitGatewayId:     &tgwIDCopy,
			}); replaceErr != nil {
				log.Info("warning: ReplaceRoute failed during invariant sweep — will retry next reconcile",
					"rt", rt.RouteTableId, "cidr", cidr, "error", replaceErr)
				continue
			}
			swept++
			c.tgwSweepReplacesThisReconcile++
			if isBlackhole {
				metricSweepReplacements.WithLabelValues("blackhole").Inc()
				metricDriftDetected.WithLabelValues("sweep_blackhole").Inc()
			} else {
				metricSweepReplacements.WithLabelValues("active").Inc()
				metricDriftDetected.WithLabelValues("sweep_active").Inc()
			}
		}
	}
	if swept > 0 {
		log.Info("invariant sweep complete", "vpcId", vpcID, "description", description, "routesReplaced", swept)
	}
	return swept > 0
}

// recordTGWInHistory adds a TGW ID to the ownership history. Idempotent.
// Emits an info log if history grows past historyOversizeWarnThreshold —
// signals unusual cluster behavior (e.g., frequent TGW recreation in tests
// or fuzz scenarios) but does NOT cap. See IdentifierPreviousTGWs godoc
// for the rationale.
func (c *FlowContext) recordTGWInHistory(log logr.Logger, tgwID string) {
	if tgwID == "" {
		return
	}
	hist := c.state.GetChild(IdentifierPreviousTGWs)
	hist.Set(tgwID, "true")
	if size := len(hist.Keys()); size > historyOversizeWarnThreshold {
		log.Info("TGW ownership history is unusually large — cluster may be cycling TGWs frequently",
			"size", size, "threshold", historyOversizeWarnThreshold)
	}
}

// pruneGhostTGWHistory drops PreviousTGWs entries whose underlying TGW no
// longer exists in AWS (deleted long ago or never existed). Called once per
// reconcile to keep the ownership history bounded — without this, every
// test run that creates+destroys a managed TGW leaves an entry forever
// (observed: 18 entries after 18 runs, 16 referencing GONE TGWs). See #112.
//
// Best-effort: a single DescribeTransitGateways batch call. Any error
// (throttle, partial response) leaves the history alone — better to keep
// stale-but-correct than partially-pruned-but-wrong, since isAbandonedTGW
// Ours uses this list as evidence of past ownership.
func (c *FlowContext) pruneGhostTGWHistory(ctx context.Context, log logr.Logger, tgwClient awsclient.Interface) {
	hist := c.state.GetChild(IdentifierPreviousTGWs)
	keys := hist.Keys()
	if len(keys) == 0 {
		return
	}
	// Batch lookup: one DescribeTransitGateways call for all entries.
	alive := map[string]bool{}
	for _, id := range keys {
		// GetTransitGateway returns nil + nil error on NotFound; non-nil
		// but State==deleted on a recently-deleted TGW. Prune both cases.
		tgw, err := tgwClient.GetTransitGateway(ctx, id)
		if err != nil {
			// Transient — leave entry alone, retry next reconcile.
			log.V(1).Info("ghost-prune: skipping entry due to lookup error",
				"tgwId", id, "error", err.Error())
			alive[id] = true
			continue
		}
		if tgw == nil {
			continue
		}
		if tgw.State == "deleted" || tgw.State == "deleting" {
			continue
		}
		alive[id] = true
	}
	pruned := 0
	for _, id := range keys {
		if !alive[id] {
			hist.Delete(id)
			pruned++
		}
	}
	if pruned > 0 {
		log.Info("ghost-prune: dropped PreviousTGWs entries for TGWs no longer in AWS",
			"pruned", pruned, "remaining", len(hist.Keys()))
	}
}

// isAbandonedTGWOurs proves whether the abandoned TGW was previously managed
// by this extension. Three-step check:
//
//  1. State history (IdentifierPreviousTGWs): TGW IDs we've ever resolved on
//     this shoot's reconcile. Survives Phase 0 reset; works even if the TGW
//     itself was deleted from AWS. Recorded at the top of reconcile() AND in
//     reconcileTGWState Phase 0 (defense in depth).
//
//  2. Per-reconcile cache (tgwOwnershipCache): memoizes the result for this
//     reconcile pass. Avoids N DescribeTransitGateway calls when the same
//     abandoned TGW ID appears in multiple blackhole routes across VPCs.
//
//  3. Live cluster-tag check via DescribeTransitGateway. Distinguishes
//     transient AWS errors (throttle/timeout — caller should defer this entry
//     only) from definitive NotFound (TGW gone, ownership unprovable).
//
// Returns (ours, transient): caller treats (false, true) as "skip this entry,
// retry next reconcile" and (false, false) as "skip + emit unverifiable event".
func (c *FlowContext) isAbandonedTGWOurs(
	ctx context.Context,
	log logr.Logger,
	_ awsclient.Interface, // unused: TGW lookup uses dedicated TGW client
	abandonedTGWID string,
) (bool, bool) {
	if abandonedTGWID == "" {
		return false, false
	}
	// Step 1: state history.
	if h := c.state.GetChild(IdentifierPreviousTGWs).Get(abandonedTGWID); h != nil && *h == "true" {
		return true, false
	}
	// Step 2: per-reconcile cache.
	if cached, hit := c.tgwOwnershipCache[abandonedTGWID]; hit {
		return cached.ours, cached.transient
	}
	result := ownershipResult{}
	defer func() {
		if c.tgwOwnershipCache == nil {
			c.tgwOwnershipCache = make(map[string]ownershipResult)
		}
		c.tgwOwnershipCache[abandonedTGWID] = result
	}()
	// Step 3: live cluster-tag check via TGW client.
	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		log.Info("warning: failed to get TGW client for ownership check — treating as transient",
			"abandonedTGW", abandonedTGWID, "error", err)
		result.transient = true
		return false, true
	}
	tgw, getErr := tgwClient.GetTransitGateway(ctx, abandonedTGWID)
	if getErr != nil {
		// Distinguish definitive NotFound from transient (throttle, timeout).
		code := awsclient.GetAWSAPIErrorCode(getErr)
		switch code {
		case "InvalidTransitGatewayID.NotFound":
			// Definitive: TGW does not exist. Ownership unprovable via tags.
			return false, false
		case "":
			// No structured AWS error code — likely network/context error.
			log.Info("ownership check transient (no AWS code) — will retry",
				"abandonedTGW", abandonedTGWID, "error", getErr)
			result.transient = true
			return false, true
		default:
			// Throttling, ServiceUnavailable, etc — transient.
			log.Info("ownership check transient AWS error — will retry",
				"abandonedTGW", abandonedTGWID, "code", code, "error", getErr)
			result.transient = true
			return false, true
		}
	}
	if tgw == nil {
		// GetTransitGateway returns nil on terminal/deleted state. Definitive.
		return false, false
	}
	if v, ok := tgw.Tags[c.tagKeyCluster()]; ok && v == TagValueCluster {
		// Persist for future reconciles.
		c.recordTGWInHistory(log, abandonedTGWID)
		result.ours = true
		return true, false
	}
	return false, false
}

// sweepStaleTGWRoutesAcrossVPCs is the DAG task that runs the invariant-based
// stale-TGW route sweep across runtime VPC, every globalVPC, and the seed VPC.
//
// Runs AFTER ensureRuntimeVPCAttachment so IdentifierRuntimeVPCID is fresh —
// reconcileTGWState's Phase 0 wipes that state on tgwChanged, so calling the
// sweep from inside reconcileTGWState would silently no-op for the runtime VPC
// every cross-TGW switch (the exact failure observed in earlier testing).
//
// Self-healing: every reconcile sweeps any auto-managed-CIDR route whose
// target TGW isn't the current resolvedTGWID. No state-based gating, so the
// sweep can't be skipped by per-shoot state inconsistencies across concurrent
// reconciles.
func (c *FlowContext) sweepStaleTGWRoutesAcrossVPCs(ctx context.Context) error {
	if !c.isSeedTGWEnabled() {
		return nil
	}
	log := LogFromContext(ctx)
	tgwID := c.resolvedTGWID
	if tgwID == "" {
		return nil
	}
	autoManagedCIDRs := c.collectAutoManagedCIDRs()
	if autoManagedCIDRs.Len() == 0 {
		return nil
	}

	// Reset per-reconcile counters / caches.
	c.tgwSweepReplacesThisReconcile = 0
	c.tgwOwnershipCache = make(map[string]ownershipResult)

	// Runtime VPC.
	if runtimeVPCID := c.state.Get(IdentifierRuntimeVPCID); runtimeVPCID != nil && *runtimeVPCID != "" {
		if runtimeVPCClient, clientErr := c.getSeedVPCClient(ctx); clientErr == nil {
			if c.sweepStaleRoutesToCurrentTGW(ctx, log, runtimeVPCClient, *runtimeVPCID, tgwID, autoManagedCIDRs, "runtime VPC") {
				c.tgwDriftDetected = true
			}
		} else {
			log.Info("warning: failed to get runtime VPC client for invariant sweep", "error", clientErr)
		}
	}

	// GlobalVPCs.
	if c.seedConfig != nil && c.seedConfig.TransitGateway != nil {
		for i := range c.seedConfig.TransitGateway.GlobalVPCs {
			gvpc := &c.seedConfig.TransitGateway.GlobalVPCs[i]
			if gvpc.VpcID == nil || *gvpc.VpcID == "" {
				continue
			}
			gvpcClient, clientErr := c.getGlobalVPCClient(ctx, gvpc)
			if clientErr != nil {
				log.Info("warning: failed to get globalVPC client for invariant sweep", "name", gvpc.Name, "error", clientErr)
				continue
			}
			if c.sweepStaleRoutesToCurrentTGW(ctx, log, gvpcClient, *gvpc.VpcID, tgwID, autoManagedCIDRs, fmt.Sprintf("globalVPC %s", gvpc.Name)) {
				c.tgwDriftDetected = true
			}
		}
	}

	// Seed VPC (discovered via seedNodesCIDR — works even when state is reset).
	if c.seedNodesCIDR != "" {
		if seedVPCClient, seedClientErr := c.getSeedVPCClient(ctx); seedClientErr == nil {
			if seedVPCs, seedErr := seedVPCClient.FindVpcsByFilters(ctx, []ec2types.Filter{
				{Name: ptr.To("cidr-block-association.cidr-block"), Values: []string{c.seedNodesCIDR}},
			}); seedErr == nil && len(seedVPCs) > 0 {
				if c.sweepStaleRoutesToCurrentTGW(ctx, log, seedVPCClient, seedVPCs[0].VpcId, tgwID, autoManagedCIDRs, "seed VPC") {
					c.tgwDriftDetected = true
				}
			}
		}
	}

	return nil
}

// MigrateTGW cleans up TGW resources when a shoot is migrated away from this seed.
// Removes VPC attachments and routes but does NOT delete the managed TGW itself
// (other shoots may still use it). The shoot's VPC remains intact.
func (c *FlowContext) MigrateTGW(ctx context.Context) error {
	log := c.log.WithName("tgw-migrate")
	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	vpcID := c.state.Get(IdentifierVPC)
	shootCIDR := c.state.Get(IdentifierShootVPCCIDR)

	c.event(corev1.EventTypeNormal, "TGWMigrating", "Cleaning up Transit Gateway resources for shoot migration")

	// Step 1: Delete TGW attachments OWNED BY THIS SHOOT for the shoot's VPC.
	// CRITICAL: filter by our cluster tag — the shared AWS account may host
	// other teams' attachments on the same VPC. Deleting those
	// would break their setup.
	if vpcID != nil {
		allAtts, err := tgwClient.FindTransitGatewayVPCAttachments(ctx, "", *vpcID)
		if err != nil {
			log.Info("warning: failed to find VPC attachments for migration cleanup", "error", err)
		} else {
			ourClusterTag := c.tagKeyCluster()
			for _, att := range allAtts {
				if att.Tags[ourClusterTag] != TagValueCluster {
					log.Info("skipping attachment not owned by this shoot",
						"attachmentId", att.TransitGatewayAttachmentId, "tgwId", att.TransitGatewayId,
						"name", att.Tags["Name"])
					continue
				}
				log.Info("deleting shoot VPC TGW attachment for migration",
					"attachmentId", att.TransitGatewayAttachmentId, "tgwId", att.TransitGatewayId)
				if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, att.TransitGatewayAttachmentId); err != nil {
					log.Info("warning: failed to delete attachment — continuing", "error", err)
				}
			}
		}
	}

	// Step 2: Clean shoot CIDR routes from runtime/globalVPCs and seed VPC.
	if shootCIDR != nil {
		c.cleanupChildShootRoutesFromRuntimeAndGlobalVPCs(ctx, log, *shootCIDR)
	}
	if shootCIDR != nil && c.seedNodesCIDR != "" {
		tgwIDForCleanup := ""
		if tgwIDVal := c.state.Get(IdentifierTransitGatewayID); tgwIDVal != nil {
			tgwIDForCleanup = *tgwIDVal
		}
		c.cleanupSeedVPCRoutes(ctx, log, *shootCIDR, tgwIDForCleanup)
	}

	// Step 3 (managed TGW deletion) is intentionally SKIPPED during migration.
	// The managed TGW may still serve other shoots on this seed.

	log.Info("TGW migration cleanup complete", "shoot", c.namespace)
	return nil
}

// reconcileTGWDeleteState handles TGW cleanup during shoot deletion.
// Discovery-based: finds what exists in AWS and cleans it, regardless of state accuracy.
func (c *FlowContext) reconcileTGWDeleteState(ctx context.Context, log logr.Logger) error {
	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	vpcID := c.state.Get(IdentifierVPC)
	shootCIDR := c.state.Get(IdentifierShootVPCCIDR)

	c.event(corev1.EventTypeNormal, "TGWDeleting", "Cleaning up Transit Gateway resources for shoot deletion")
	// --- Step 1: Find and delete TGW attachments OWNED BY THIS SHOOT for the shoot's VPC ---
	// Discovery-based: searches across ALL TGWs, not just the one in state.
	// CRITICAL: filter by our cluster tag — the shared AWS account may host
	// other teams' attachments on the same VPC. Deleting those
	// would break their setup.
	if vpcID != nil {
		allAtts, err := tgwClient.FindTransitGatewayVPCAttachments(ctx, "", *vpcID)
		if err != nil {
			log.Info("warning: failed to find VPC attachments for delete cleanup", "error", err)
		} else {
			ourClusterTag := c.tagKeyCluster()
			for _, att := range allAtts {
				if att.Tags[ourClusterTag] != TagValueCluster {
					log.Info("skipping attachment not owned by this shoot",
						"attachmentId", att.TransitGatewayAttachmentId, "tgwId", att.TransitGatewayId,
						"name", att.Tags["Name"])
					continue
				}
				log.Info("deleting shoot VPC TGW attachment",
					"attachmentId", att.TransitGatewayAttachmentId, "tgwId", att.TransitGatewayId)
				if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, att.TransitGatewayAttachmentId); err != nil {
					log.Info("warning: failed to delete attachment — continuing", "error", err)
				}
			}
		}
	}

	// --- Step 2: Clean shoot CIDR routes from runtime/globalVPCs ---
	if shootCIDR != nil {
		c.cleanupChildShootRoutesFromRuntimeAndGlobalVPCs(ctx, log, *shootCIDR)
	}
	if shootCIDR != nil && c.seedNodesCIDR != "" {
		tgwIDForCleanup := ""
		if tgwIDVal := c.state.Get(IdentifierTransitGatewayID); tgwIDVal != nil {
			tgwIDForCleanup = *tgwIDVal
		}
		c.cleanupSeedVPCRoutes(ctx, log, *shootCIDR, tgwIDForCleanup)
	}

	// --- Step 3: Check for managed TGW cleanup ---
	// Always discover by tags — don't rely on state (may have been cleared by a switch).
	// Search by both seedName AND shoot name (for ManagedSeed shoots, the shoot name IS
	// the seed name, but after deregistration c.seedName may be the parent seed).
	cleanupSeedNames := sets.New[string]()
	if c.seedName != "" {
		cleanupSeedNames.Insert(c.seedName)
	}
	// The shoot name for a ManagedSeed shoot equals the seed name.
	if c.shootName != "" {
		cleanupSeedNames.Insert(c.shootName)
	}
	for seedNameCandidate := range cleanupSeedNames {
		// Use the resolved seed shoot namespace for tag patterns.
		// If this candidate matches the seed name, use seedShootNamespace (resolved via Infrastructure lookup).
		// Otherwise skip — we can't construct arbitrary namespaces without hardcoding conventions.
		seedShootNS := ""
		if seedNameCandidate == c.seedName {
			seedShootNS = c.seedShootNamespace
		}
		if seedShootNS == "" {
			continue
		}
		seedTags := awsclient.Tags{
			fmt.Sprintf(TagKeyClusterTemplate, seedShootNS): TagValueCluster,
		}
		allTGWs, err := tgwClient.FindTransitGatewaysByTags(ctx, seedTags)
		if err != nil {
			log.Info("warning: failed to find managed TGWs for delete cleanup", "error", err)
		} else {
			for _, tgw := range allTGWs {
				allAtts, listErr := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgw.TransitGatewayId)
				if listErr != nil {
					continue
				}

				// Count remaining child shoot attachments (exclude shared resources).
				otherChildShoots := 0
				for _, att := range allAtts {
					name := att.Tags["Name"]
					if strings.Contains(name, "-seed-vpc-") || strings.Contains(name, "-runtime-vpc-") || strings.Contains(name, "-gvpc-") {
						continue
					}
					otherChildShoots++
				}

				if otherChildShoots > 0 {
					log.Info("managed TGW still has other child shoots — not deleting",
						"tgwId", tgw.TransitGatewayId, "count", otherChildShoots)
					continue
				}

				log.Info("last child shoot — cleaning up managed TGW", "tgwId", tgw.TransitGatewayId)

				// Clean up globalVPC CIDR routes from runtime VPC (reverse of Step 5c).
				// These routes point to the managed TGW and become blackholes after TGW deletion.
				runtimeVPCID := c.state.Get(IdentifierRuntimeVPCID)
				if runtimeVPCID != nil && c.seedConfig != nil && c.seedConfig.TransitGateway != nil {
					runtimeClient, clientErr := c.getSeedVPCClient(ctx)
					if clientErr != nil {
						log.Info("warning: failed to get client for runtime VPC globalVPC route cleanup", "error", clientErr)
					} else {
						for gi := range c.seedConfig.TransitGateway.GlobalVPCs {
							gvpc := &c.seedConfig.TransitGateway.GlobalVPCs[gi]
							for _, cidr := range gvpc.CIDRs {
								log.Info("cleaning up globalVPC CIDR route from runtime VPC", "runtimeVpcId", *runtimeVPCID, "globalVPC", gvpc.Name, "cidr", cidr)
								c.deleteRouteFromVPC(ctx, log, runtimeClient, *runtimeVPCID, cidr, fmt.Sprintf("runtime VPC (globalVPC %s)", gvpc.Name))
							}
						}
					}
				}

				// Delete all remaining shared attachments.
				for _, att := range allAtts {
					log.Info("deleting managed TGW attachment", "attachmentId", att.TransitGatewayAttachmentId)
					if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, att.TransitGatewayAttachmentId); err != nil {
						log.Info("warning: failed to delete — continuing", "error", err)
					}
				}

				// Delete RTs by tag discovery.
				allRTs, rtErr := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, seedTags)
				if rtErr == nil {
					for _, rt := range allRTs {
						if rt.TransitGatewayId == tgw.TransitGatewayId {
							log.Info("deleting managed TGW RT", "routeTableId", rt.TransitGatewayRouteTableId)
							if delErr := tgwClient.DeleteTransitGatewayRouteTable(ctx, rt.TransitGatewayRouteTableId); delErr != nil {
								log.Info("warning: failed to delete managed TGW RT", "rt", rt.TransitGatewayRouteTableId, "error", delErr)
							}
						}
					}
				}

				// Delete the TGW.
				log.Info("deleting managed TGW", "tgwId", tgw.TransitGatewayId)
				if delErr := tgwClient.DeleteTransitGateway(ctx, tgw.TransitGatewayId); delErr != nil {
					log.Info("warning: failed to delete managed TGW", "tgwId", tgw.TransitGatewayId, "error", delErr)
				}
			}
		}
	} // end for seedNameCandidate

	return nil
}

// cleanupStaleAttachments deletes TGW VPC attachments that were flagged by
// reconcileTGWState Phase 1. Runs AFTER ensureTransitGatewayAttachment to ensure
// the new attachment exists before the old ones are removed (no connectivity gap).
func (c *FlowContext) cleanupStaleAttachments(ctx context.Context) error {
	if len(c.staleAttachmentIDs) == 0 {
		return nil
	}
	log := LogFromContext(ctx)

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	log.Info("cleaning up stale TGW attachments (new attachment already created)",
		"count", len(c.staleAttachmentIDs))
	for _, attID := range c.staleAttachmentIDs {
		log.Info("deleting stale TGW attachment", "attachmentId", attID)
		c.event(corev1.EventTypeNormal, "TGWAttachmentDeleted", "Deleted stale VPC attachment %s (was on wrong TGW)", attID)
		if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, attID); err != nil {
			log.Info("warning: failed to delete stale attachment — continuing", "attachmentId", attID, "error", err)
		}
	}
	c.staleAttachmentIDs = nil
	return nil
}
