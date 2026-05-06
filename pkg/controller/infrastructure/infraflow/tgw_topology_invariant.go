// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// assertSeedSideAssociations verifies that the seed-side TGW attachments
// (seed VPC, runtime VPC, managed globalVPCs) are associated with the
// route table that matches the current isolation mode:
//
//   - hub-spoke: associated with the HUB RT
//   - shared:    associated with the SHARED RT
//
// On observed drift, the function emits a TGWAssociationDrift event and
// increments the tgw_association_drift_total{role=...} metric. If this
// reconcile is the canonical owner (the seed shoot itself, identified by
// c.isManagedSeedShoot), it actively corrects the drift via the safe
// pre-propagate → disassociate → associate sequence. Child-shoot
// reconciles only flag the drift and set c.tgwDriftDetected so the
// reconcile completion gate requeues; the seed shoot's own healthcheck
// + reconcile loop is the canonical mover.
//
// This is a defensive invariant: it does not fix the root-cause ownership
// ambiguity (the canonical-owner pattern handles that); it makes the
// wedged-topology state visible and self-healing in the meantime.
func (c *FlowContext) assertSeedSideAssociations(ctx context.Context, log logr.Logger, tgwID string) error {
	// Entry-level diagnostic. Without this, a silent return is indistinguishable
	// from "function never ran" when reading production logs.
	log.Info("topology-invariant: starting seed-side association check",
		"tgwID", tgwID,
		"isolationMode", c.isolationModeString(),
		"isManagedSeedShoot", c.isManagedSeedShoot,
		"resolvedHubRT", c.resolvedHubRouteTableID,
		"resolvedSpokeRT", c.resolvedSpokeRouteTableID,
		"resolvedSharedRT", c.resolvedSharedRouteTableID)

	if tgwID == "" {
		log.Info("topology-invariant: skip — tgwID empty")
		return nil
	}
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil || !c.seedConfig.TransitGateway.Enabled {
		log.Info("topology-invariant: skip — seed TGW disabled")
		return nil
	}

	expected, ok := c.expectedSeedSideRT()
	if !ok {
		log.Info("topology-invariant: skip — expected RT not yet resolved",
			"isolationMode", c.isolationModeString())
		return nil
	}

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client for topology-invariant check: %w", err)
	}

	candidates := c.collectSeedSideAttachments(ctx, log, tgwClient, tgwID)
	log.Info("topology-invariant: candidates collected",
		"expected", expected,
		"count", len(candidates),
		"candidates", summarizeCandidates(candidates))

	for _, cand := range candidates {
		c.checkAndMaybeFixAssociation(ctx, log, tgwClient, cand, tgwID, expected)
	}

	return nil
}

// summarizeCandidates returns a flat string suitable for logging the candidate set.
func summarizeCandidates(cands []seedSideAttachment) string {
	if len(cands) == 0 {
		return "<none>"
	}
	parts := make([]string, 0, len(cands))
	for _, c := range cands {
		parts = append(parts, fmt.Sprintf("%s=%s", c.role, c.attachmentID))
	}
	return strings.Join(parts, ",")
}

// expectedSeedSideRT returns the RT all seed-side attachments must be
// associated with given the current isolation mode, plus a bool indicating
// whether the RT has been resolved this reconcile.
func (c *FlowContext) expectedSeedSideRT() (string, bool) {
	if c.isSharedIsolationMode() {
		return c.resolvedSharedRouteTableID, c.resolvedSharedRouteTableID != ""
	}
	return c.resolvedHubRouteTableID, c.resolvedHubRouteTableID != ""
}

// seedSideAttachment is the audit subject for assertSeedSideAssociations:
// one shared TGW VPC attachment whose RT association must match the
// current isolation mode.
type seedSideAttachment struct {
	role         string // metric label: "seed", "runtime", or "globalvpc"
	humanName    string // event-message identifier (e.g. "seed VPC", "globalVPC mgmt")
	attachmentID string
}

// collectSeedSideAttachments resolves the attachment IDs for every seed-side
// shared role we want to assert. Skips roles whose attachment ID cannot be
// determined (not yet created, state empty, or VPC not yet discovered).
//
// Seed VPC attachment lookup is layered defensively:
//
//   - IdentifierSeedVPCTransitGatewayAttachment is the conventional state key
//     for the seed-side attachment. For child shoot reconciles, this is the
//     authoritative source.
//
//   - For the seed shoot itself (c.isManagedSeedShoot = true), the shoot's
//     own VPC IS the seed VPC, so the relevant attachment ID *also* lives
//     in IdentifierTransitGatewayAttachment. We check both. This is required
//     for two reasons: (1) the seed shoot's own reconcile may not have ever
//     populated the SeedVPC key (it manages the same attachment via its
//     shoot-VPC code path); (2) observed state on long-lived clusters has
//     shown the SeedVPC key drifting to point at the runtime VPC attachment
//     (a separate state-corruption bug surfaced during 2026-04-29 testing),
//     so falling back to the shoot's-own key catches the real drift even
//     when the SeedVPC key is wrong.
//
// Both candidate IDs are deduplicated; if they happen to match (the healthy
// case for the seed shoot), only one assertion runs.
func (c *FlowContext) collectSeedSideAttachments(ctx context.Context, log logr.Logger, tgwClient awsclient.Interface, tgwID string) []seedSideAttachment {
	var out []seedSideAttachment
	seen := map[string]struct{}{}
	addCandidate := func(role, humanName, id string) {
		if id == "" {
			return
		}
		if _, dup := seen[id]; dup {
			return
		}
		seen[id] = struct{}{}
		out = append(out, seedSideAttachment{role: role, humanName: humanName, attachmentID: id})
	}

	// Seed VPC, primary key (used by child shoot reconciles + sometimes the seed shoot).
	if id := c.lookupSeedSideAttachmentID(ctx, log, tgwClient, tgwID, IdentifierSeedVPCTransitGatewayAttachment, c.seedNodesCIDR, "seed VPC"); id != "" {
		addCandidate("seed", "seed VPC", id)
	}

	// Seed VPC, secondary key — only relevant on the seed shoot's own reconcile,
	// where the shoot's own VPC attachment IS the seed VPC attachment.
	if c.isManagedSeedShoot {
		if v := c.state.Get(IdentifierTransitGatewayAttachment); v != nil && *v != "" {
			addCandidate("seed", "seed VPC (managed-seed shoot's own attachment)", *v)
		}
	}

	// Runtime VPC (only relevant when managed mode auto-discovered it; state
	// records IdentifierRuntimeVPCTransitGatewayAttachment if so).
	if v := c.state.Get(IdentifierRuntimeVPCTransitGatewayAttachment); v != nil && *v != "" {
		addCandidate("runtime", "runtime VPC", *v)
	}

	// Managed globalVPCs (referenced ones come with their own AttachmentID and
	// are not in our ownership scope — skip). State lookup goes through the
	// shared helper which handles the hierarchy/root-literal asymmetry; see
	// FlowContext.gvpcAttachmentChild godoc for the persist/restore details.
	if c.seedConfig != nil && c.seedConfig.TransitGateway != nil {
		for i := range c.seedConfig.TransitGateway.GlobalVPCs {
			gvpc := &c.seedConfig.TransitGateway.GlobalVPCs[i]
			if gvpc.AttachmentID != nil && *gvpc.AttachmentID != "" {
				continue // referenced — not ours to manage
			}
			if v := c.getGlobalVPCAttachmentID(gvpc.Name); v != nil && *v != "" {
				addCandidate("globalvpc", fmt.Sprintf("globalVPC %s", gvpc.Name), *v)
			}
		}
	}

	return out
}

// lookupSeedSideAttachmentID returns the seed VPC attachment ID using state
// first, falling back to a VPC+TGW discovery via the seed nodes CIDR. Returns
// empty string when the attachment cannot be determined this reconcile.
func (c *FlowContext) lookupSeedSideAttachmentID(_ context.Context, log logr.Logger, _ awsclient.Interface, _ string, stateKey, vpcCIDRForDiscovery, humanName string) string {
	if v := c.state.Get(stateKey); v != nil && *v != "" {
		return *v
	}
	// Fallback: discover by VPC. Only attempt when we have the seed nodes CIDR
	// or some other way to find the VPC; otherwise return empty (not an error).
	if vpcCIDRForDiscovery == "" {
		return ""
	}
	// Reuse the seed VPC discovery path. discoverSeedVPC is a heavier helper;
	// we only use the lightweight lookup-by-existing-attachment here to avoid
	// duplicating its work. The attachment list filter is by VPC ID, which we
	// don't know without discoverSeedVPC. Prefer to defer rather than do a
	// full discovery in this audit step.
	log.V(1).Info("seed-side attachment ID not in state — deferring topology-invariant check for this role",
		"role", humanName, "stateKey", stateKey)
	return ""
}

// checkAndMaybeFixAssociation looks up the current RT association for one
// seed-side attachment and, on mismatch, emits the drift event/metric and
// (if this is the canonical-owner reconcile) executes the safe move.
//
// Before the association check, verifies the attachment is on our TGW and
// is not terminal — stale-attachment / wrong-TGW cases belong to Phase 1
// (cross-VPC stale flag), not to this invariant.
//
// On the first observation of an empty currentRT, polls briefly to ride
// out AWS eventual-consistency (a disassociate-then-associate operation
// can transiently report "" between calls). Only the post-poll value is
// used to decide drift vs healthy.
func (c *FlowContext) checkAndMaybeFixAssociation(ctx context.Context, log logr.Logger, tgwClient awsclient.Interface, cand seedSideAttachment, tgwID, expectedRT string) {
	log.Info("topology-invariant: checking candidate",
		"role", cand.humanName, "attachmentId", cand.attachmentID, "expectedRT", expectedRT)

	att, attErr := tgwClient.GetTransitGatewayVPCAttachment(ctx, cand.attachmentID)
	if attErr != nil {
		log.Info("topology-invariant: failed to read attachment — deferring",
			"role", cand.humanName, "attachmentId", cand.attachmentID, "error", attErr)
		c.tgwDriftDetected = true
		return
	}
	if att == nil || isAttachmentTerminal(att.State) {
		log.Info("topology-invariant: attachment terminal or missing — Phase 1 will handle",
			"role", cand.humanName, "attachmentId", cand.attachmentID,
			"state", attachmentStateString(att))
		return
	}
	if att.TransitGatewayId != tgwID {
		log.Info("topology-invariant: attachment on a different TGW — Phase 1 stale flag will handle",
			"role", cand.humanName, "attachmentId", cand.attachmentID,
			"actualTGW", att.TransitGatewayId, "expectedTGW", tgwID)
		return
	}

	currentRT := c.readAssociationWithPoll(ctx, log, tgwClient, cand)
	if currentRT == "" {
		// Even after a brief poll, no association. Bootstrap-associate path
		// (in ensureSeedVPCAttachment / ensureTransitGatewayAttachment) handles
		// this case — don't duplicate the work, but signal drift so the
		// reconcile completion gate re-runs once bootstrap finishes.
		log.Info("topology-invariant: attachment unassociated after poll — deferring to bootstrap path",
			"role", cand.humanName, "attachmentId", cand.attachmentID)
		c.tgwDriftDetected = true
		return
	}
	log.Info("topology-invariant: candidate association observed",
		"role", cand.humanName, "attachmentId", cand.attachmentID,
		"currentRT", currentRT, "expectedRT", expectedRT,
		"healthy", currentRT == expectedRT)
	if currentRT == expectedRT {
		return // healthy
	}

	// Drift observed. Emit event + metric regardless of whether we can fix it
	// from this reconcile.
	log.Info("topology-invariant: association drift detected",
		"role", cand.humanName,
		"attachmentId", cand.attachmentID,
		"currentRT", currentRT,
		"expectedRT", expectedRT,
		"isolationMode", c.isolationModeString(),
		"canonicalOwner", c.isManagedSeedShoot)
	c.event(corev1.EventTypeWarning, "TGWAssociationDrift",
		"%s attachment %s is associated with RT %s but isolation mode %q expects RT %s — %s",
		cand.humanName, cand.attachmentID, currentRT, c.isolationModeString(), expectedRT,
		c.driftActionMessage())
	metricAssociationDrift.WithLabelValues(cand.role).Inc()
	c.tgwDriftDetected = true

	if !c.isManagedSeedShoot {
		// Child shoots cannot safely move the seed-side attachment — that's the
		// seed shoot's reconcile job. Leaving tgwDriftDetected=true ensures the
		// reconcile completion gate requeues. The seed shoot's own healthcheck
		// will independently observe the drift and trigger its own reconcile.
		return
	}

	// Canonical-owner reconcile. Execute the safe move:
	//   1. Pre-propagate to the expected RT (idempotent; sets up the new path).
	//   2. Disassociate from the current RT.
	//   3. Associate with the expected RT.
	//
	// Each step tolerates the AWS "already done" error codes. Transient failures
	// preserve tgwDriftDetected for the next reconcile to retry.
	if err := c.moveSeedSideAttachmentRT(ctx, log, tgwClient, cand, currentRT, expectedRT); err != nil {
		log.Info("topology-invariant: move failed — deferring to next reconcile",
			"role", cand.humanName, "attachmentId", cand.attachmentID, "error", err)
		// tgwDriftDetected is already true; nothing else to do.
	}
}

// moveSeedSideAttachmentRT executes the safe RT switch for a seed-side
// attachment. Pre-propagates, disassociates, associates. Idempotent on
// AWS-side "already done" errors.
func (c *FlowContext) moveSeedSideAttachmentRT(ctx context.Context, log logr.Logger, tgwClient awsclient.Interface, cand seedSideAttachment, currentRT, expectedRT string) error {
	// Step 1: pre-propagate. If propagation already exists, AWS returns
	// TransitGatewayRouteTablePropagation.Duplicate — fine.
	log.Info("topology-invariant: pre-propagating to expected RT before move",
		"role", cand.humanName, "attachmentId", cand.attachmentID, "expectedRT", expectedRT)
	if err := tgwClient.EnableTransitGatewayRouteTablePropagation(ctx, expectedRT, cand.attachmentID); err != nil {
		code := awsclient.GetAWSAPIErrorCode(err)
		switch code {
		case "TransitGatewayRouteTablePropagation.Duplicate":
			// already propagated
		case "IncorrectState", "InvalidRouteTableID.NotFound":
			return fmt.Errorf("expected RT %s not yet ready for propagation (code %s); will retry on next reconcile", expectedRT, code)
		default:
			return fmt.Errorf("pre-propagate to %s failed: %w", expectedRT, err)
		}
	}

	// Step 2: disassociate from the current RT.
	log.Info("topology-invariant: disassociating from current RT",
		"role", cand.humanName, "attachmentId", cand.attachmentID, "currentRT", currentRT)
	if err := tgwClient.DisassociateTransitGatewayRouteTable(ctx, currentRT, cand.attachmentID); err != nil {
		code := awsclient.GetAWSAPIErrorCode(err)
		switch code {
		case "InvalidAssociation.NotFound", "Resource.NotAssociated":
			// already disassociated — proceed
		case "IncorrectState":
			return fmt.Errorf("disassociation from %s blocked by transient state; will retry", currentRT)
		default:
			return fmt.Errorf("disassociate from %s failed: %w", currentRT, err)
		}
	}

	// Step 3: associate with the expected RT.
	log.Info("topology-invariant: associating with expected RT",
		"role", cand.humanName, "attachmentId", cand.attachmentID, "expectedRT", expectedRT)
	if err := tgwClient.AssociateTransitGatewayRouteTable(ctx, expectedRT, cand.attachmentID); err != nil {
		code := awsclient.GetAWSAPIErrorCode(err)
		switch code {
		case "Resource.AlreadyAssociated":
			// already done — fine
		case "IncorrectState", "InvalidRouteTableID.NotFound":
			return fmt.Errorf("expected RT %s not yet ready for associate (code %s); will retry", expectedRT, code)
		default:
			return fmt.Errorf("associate with %s failed: %w", expectedRT, err)
		}
	}

	c.event(corev1.EventTypeNormal, "TGWAssociationDriftCorrected",
		"%s attachment %s moved from RT %s to canonical RT %s for isolation mode %q",
		cand.humanName, cand.attachmentID, currentRT, expectedRT, c.isolationModeString())
	log.Info("topology-invariant: move complete",
		"role", cand.humanName, "attachmentId", cand.attachmentID,
		"fromRT", currentRT, "toRT", expectedRT)
	// Signal the actuator to enqueue post-hoc reconciles on every child shoot
	// so their DWD-scaled deployments come back online quickly.
	c.tgwDriftCorrectedThisReconcile = true
	return nil
}

// DriftCorrectedThisReconcile reports whether assertSeedSideAssociations
// executed a successful corrective move during the most recent Reconcile.
// The actuator uses this after Reconcile() returns to trigger post-hoc
// reconciles on every child shoot (DWD recovery path).
func (c *FlowContext) DriftCorrectedThisReconcile() bool {
	return c.tgwDriftCorrectedThisReconcile
}

// isolationModeString returns "shared" or "hub-spoke" for event/log messages.
func (c *FlowContext) isolationModeString() string {
	if c.isSharedIsolationMode() {
		return "shared"
	}
	return "hub-spoke"
}

// attachmentStateString returns the AWS state of an attachment for logging,
// tolerating a nil pointer.
func attachmentStateString(att *awsclient.TransitGatewayVPCAttachment) string {
	if att == nil {
		return "<missing>"
	}
	return att.State
}

// associationPollAttempts is the number of GetTransitGatewayAttachmentAssociation
// retries used to ride out AWS eventual-consistency between disassociate /
// associate operations. Each attempt sleeps 2 seconds before retrying. Total
// worst-case wait: associationPollAttempts × 2s.
//
// 2026-04-30 in-region testing: 10s window observed empty for the entire poll
// despite the underlying associate API having returned ~14s prior. Bumped to
// 30s based on that data point. Matches the inline Phase 2 verify-poll window
// at reconcile.go:2618 ("30s polling").
const associationPollAttempts = 15

// readAssociationWithPoll calls GetTransitGatewayAttachmentAssociation, and on
// an empty initial response polls briefly. AWS returns "" between disassociate
// completion and associate-becomes-visible; without polling, our drift check
// races with that gap and silently mis-classifies a transitional state as
// "unassociated → defer", missing real drift that will be steady-state once
// AWS settles.
func (c *FlowContext) readAssociationWithPoll(ctx context.Context, log logr.Logger, tgwClient awsclient.Interface, cand seedSideAttachment) string {
	for i := 0; i < associationPollAttempts; i++ {
		rt, err := tgwClient.GetTransitGatewayAttachmentAssociation(ctx, cand.attachmentID)
		if err != nil {
			log.Info("topology-invariant: failed to read current association — deferring",
				"role", cand.humanName, "attachmentId", cand.attachmentID, "error", err, "attempt", i+1)
			c.tgwDriftDetected = true
			return ""
		}
		if rt != "" {
			if i > 0 {
				log.Info("topology-invariant: association settled after poll",
					"role", cand.humanName, "attachmentId", cand.attachmentID, "attempt", i+1, "rt", rt)
			}
			return rt
		}
		if i == 0 {
			log.Info("topology-invariant: association is empty on first read — polling briefly to ride out eventual-consistency",
				"role", cand.humanName, "attachmentId", cand.attachmentID)
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(2 * time.Second):
		}
	}
	return "" // empty after the full poll window — caller treats as bootstrap defer
}

// driftActionMessage returns the operator-facing description of what the
// reconciler will do about the observed drift.
func (c *FlowContext) driftActionMessage() string {
	if c.isManagedSeedShoot {
		return "this is the seed shoot reconcile, attempting to correct"
	}
	return "child-shoot reconcile cannot fix; the seed shoot reconcile is the canonical mover and will correct on its next pass"
}
