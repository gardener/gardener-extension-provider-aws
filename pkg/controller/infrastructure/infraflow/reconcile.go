// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- No cryptographic context.
	"errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

const (
	defaultTimeout         = 90 * time.Second
	defaultLongTimeout     = 3 * time.Minute
	allIPv4                = "0.0.0.0/0"
	allIPv6                = "::/0"
	nat64Prefix            = "64:ff9b::/96"
	defaultIPv6NetmaskSize = 56
)

// Reconcile creates and runs the flow to reconcile the AWS infrastructure.
func (c *FlowContext) Reconcile(ctx context.Context) error {
	c.BasicFlowContext = NewBasicFlowContext(c.log, c.state, c.persistState)
	g := c.buildReconcileGraph()
	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{Log: c.log}); err != nil {
		c.log.Error(err, "flow reconciliation failed")
		return errors.Join(flow.Causes(err), c.persistState(ctx))
	}

	// Reconcile completion gate: if drift was detected during the
	// DAG (e.g., the invariant sweep replaced stale routes, isolation switch
	// hit a transient AWS error, ownership check returned transient), run the
	// sweep ONE MORE TIME to converge before reporting success. If drift is
	// STILL detected after the second sweep, return a transient error so
	// Gardener requeues — the next reconcile will retry. Without this gate,
	// Reconcile reports Succeeded with stale routes still present, and the
	// next reconcile only fires on syncPeriod (default 1 hour).
	//
	// Why a SECOND sweep helps: typical scenario is cleanup task in the DAG
	// deletes an attachment AT roughly the same moment as the sweep runs.
	// AWS marks the resulting blackholes after sweep observed the RT. A
	// post-DAG sweep observes the freshly-formed blackholes and replaces them.
	if c.tgwDriftDetected && c.isSeedTGWEnabled() && c.resolvedTGWID != "" {
		c.log.Info("reconcile completion gate: drift detected, running final sweep + topology re-check")
		c.tgwDriftDetected = false
		if err := c.sweepStaleTGWRoutesAcrossVPCs(ctx); err != nil {
			c.log.Info("reconcile completion gate: final sweep error — will requeue", "error", err)
			c.tgwDriftDetected = true
		}
		// Topology-invariant re-check. The first call (in ensureTransitGateway)
		// can race with AWS eventual-consistency on the association API and
		// observe an empty currentRT for an attachment that's mid-associate;
		// the helper defers in that case. By the time we reach the completion
		// gate (DAG done, ~3-5s later in practice), AWS has typically settled.
		// Running the helper again here is the self-healing path: the second
		// call sees the now-stable association and either declares healthy or
		// detects drift and (for the canonical owner) executes the move. This
		// matches the "second sweep" rationale documented above.
		if err := c.assertSeedSideAssociations(ctx, c.log, c.resolvedTGWID); err != nil {
			c.log.Info("reconcile completion gate: topology re-check error — will requeue", "error", err)
			c.tgwDriftDetected = true
		}
		if c.tgwDriftDetected {
			c.log.Info("reconcile completion gate: drift remains after final sweep + topology re-check — returning retry signal")
			c.event(corev1.EventTypeWarning, "TGWReconcileRequeue",
				"TGW reconcile completed with drift remaining; requeuing for next reconcile to converge")
			metricReconcileRequeue.Inc()
			// Persist state before returning so the next reconcile picks up
			// where we left off. Return a non-nil error to signal Gardener
			// that the reconcile is not yet complete.
			if persistErr := c.persistState(ctx); persistErr != nil {
				return errors.Join(persistErr, fmt.Errorf("TGW drift remains after final sweep — requeuing"))
			}
			return fmt.Errorf("TGW drift remains after final sweep — requeuing")
		}
	}

	if c.resolvedTGWID != "" {
		mode := "referenced"
		if c.isManagedTGWMode() {
			mode = "managed"
		}
		isolation := "hub-spoke"
		if c.isSharedIsolationMode() {
			isolation = "shared"
		}
		c.event(corev1.EventTypeNormal, "TGWReconciled", "Transit Gateway %s reconciled successfully (mode=%s, isolation=%s)", c.resolvedTGWID, mode, isolation)
	}

	status := c.computeInfrastructureStatus()
	state := c.computeInfrastructureState()
	egressCIDRs := c.getEgressCIDRs()
	vpcIPv6CidrBlock := c.state.Get(IdentifierVpcIPv6CidrBlock)
	serviceCidr := c.state.Get(IdentifierServiceCIDR)
	return PatchProviderStatusAndState(ctx, c.runtimeClient, c.infra, c.networking, status, state, egressCIDRs, vpcIPv6CidrBlock, serviceCidr)
}

// TGWDriftDetected returns true if reconcileTGWState found and fixed drift.
// The caller should requeue to verify the fix took effect.
func (c *FlowContext) TGWDriftDetected() bool {
	return c.tgwDriftDetected
}

// shootAttachmentRole returns the role of the shoot's TGW attachment for the
// purpose of disableOldRTPropagationIfUnneeded's critical-propagation guard.
// When the shoot itself is a ManagedSeed, its VPC IS the seed VPC for child
// shoots, so we treat it as a seed VPC role and protect its hub propagation.
func (c *FlowContext) shootAttachmentRole() string {
	if c.isManagedSeedShoot {
		return attachmentRoleSeedVPC
	}
	return attachmentRoleShoot
}

// AWS error codes that indicate a TGW route-table API call hit a transient
// state (resource mid-create, mid-delete, or briefly unavailable). Treat them
// as drift — log + signal driftDetected so the next reconcile retries — never
// as a hard error that fails the entire infra reconcile.
//
// "Already done" codes are treated as success (the desired state is satisfied).
const (
	codeAlreadyAssociated         = "Resource.AlreadyAssociated"
	codePropagationDuplicate      = "TransitGatewayRouteTablePropagation.Duplicate"
	codePropagationNotFound       = "TransitGatewayRouteTablePropagation.NotFound"
	codeAssociationNotFound       = "InvalidAssociation.NotFound"
	codeIncorrectState            = "IncorrectState"
	codeRouteTableNotFound        = "InvalidRouteTableID.NotFound"
	codeTGWNotFound               = "InvalidTransitGatewayID.NotFound"
	codeAttachmentNotFound        = "InvalidTransitGatewayAttachmentID.NotFound"
)

// isTransientTGWAPIError returns true if `code` is a known AWS error code that
// indicates a transient state (resource mid-create / mid-delete / briefly
// unavailable). Callers should signal drift and retry on next reconcile.
func isTransientTGWAPIError(code string) bool {
	switch code {
	case codeIncorrectState, codeRouteTableNotFound, codeTGWNotFound, codeAttachmentNotFound:
		return true
	}
	return false
}

// enableTGWPropagation wraps EnableTransitGatewayRouteTablePropagation with the
// uniform error policy: Duplicate is success; transient codes are deferred via
// driftDetected; everything else is a hard error.
func (c *FlowContext) enableTGWPropagation(ctx context.Context, log logr.Logger, client awsclient.Interface, rtID, attachmentID, role string) error {
	if rtID == "" || attachmentID == "" {
		return nil
	}
	err := client.EnableTransitGatewayRouteTablePropagation(ctx, rtID, attachmentID)
	if err == nil {
		return nil
	}
	code := awsclient.GetAWSAPIErrorCode(err)
	switch {
	case code == codePropagationDuplicate:
		return nil
	case isTransientTGWAPIError(code):
		log.Info("propagation hit transient state — deferring",
			"rt", rtID, "attachment", attachmentID, "role", role, "code", code)
		c.tgwDriftDetected = true
		return nil
	}
	return fmt.Errorf("failed to enable propagation to %s RT %s for attachment %s: %w", role, rtID, attachmentID, err)
}

// associateTGWRouteTable wraps AssociateTransitGatewayRouteTable with the same
// transient-error policy. AlreadyAssociated is treated as success.
func (c *FlowContext) associateTGWRouteTable(ctx context.Context, log logr.Logger, client awsclient.Interface, rtID, attachmentID, role string) error {
	if rtID == "" || attachmentID == "" {
		return nil
	}
	err := client.AssociateTransitGatewayRouteTable(ctx, rtID, attachmentID)
	if err == nil {
		return nil
	}
	code := awsclient.GetAWSAPIErrorCode(err)
	switch {
	case code == codeAlreadyAssociated:
		return nil
	case isTransientTGWAPIError(code):
		log.Info("association hit transient state — deferring",
			"rt", rtID, "attachment", attachmentID, "role", role, "code", code)
		c.tgwDriftDetected = true
		return nil
	}
	return fmt.Errorf("failed to associate %s with RT %s for attachment %s: %w", role, rtID, attachmentID, err)
}

// disableTGWPropagation wraps DisableTransitGatewayRouteTablePropagation.
// PropagationNotFound is treated as success (already disabled).
func (c *FlowContext) disableTGWPropagation(ctx context.Context, log logr.Logger, client awsclient.Interface, rtID, attachmentID, role string) error {
	if rtID == "" || attachmentID == "" {
		return nil
	}
	err := client.DisableTransitGatewayRouteTablePropagation(ctx, rtID, attachmentID)
	if err == nil {
		return nil
	}
	code := awsclient.GetAWSAPIErrorCode(err)
	switch {
	case code == codePropagationNotFound:
		return nil
	case isTransientTGWAPIError(code):
		log.Info("disable-propagation hit transient state — deferring",
			"rt", rtID, "attachment", attachmentID, "role", role, "code", code)
		c.tgwDriftDetected = true
		return nil
	}
	return fmt.Errorf("failed to disable propagation from %s RT %s for attachment %s: %w", role, rtID, attachmentID, err)
}

// recordSwitchTimestamp writes the current UTC time to lastSwitchedAtKey after a
// successful Phase 2 switch. The next reconcile uses shouldDeferPingPongSwitch
// to detect cross-extension fights.
func (c *FlowContext) recordSwitchTimestamp(lastSwitchedAtKey string) {
	c.state.Set(lastSwitchedAtKey, time.Now().UTC().Format(time.RFC3339Nano))
}

// shouldDeferPingPongSwitch checks whether a fresh Phase 1 detection
// (currentRT != targetRT, no pending switch) is suspicious — i.e. we just
// completed a Phase 2 switch on this attachment within the cooldown window,
// suggesting another extension instance reverted us. In that case defer
// instead of fighting back. After maxPingPongDefers consecutive deferrals,
// abandon the switch entirely and emit a TGWSwitchDeadlock Warning event so
// an operator notices.
//
// Returns true if the caller should skip Phase 1 (defer or abandoned).
// Returns false if the cooldown has expired or never engaged — proceed with
// the normal Phase 1 path.
func (c *FlowContext) shouldDeferPingPongSwitch(
	log logr.Logger,
	lastSwitchedAtKey, defersKey, attachmentID, currentRT, targetRT string,
) bool {
	lastSwitchedAt := c.state.Get(lastSwitchedAtKey)
	if lastSwitchedAt == nil {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, *lastSwitchedAt)
	if err != nil {
		// Corrupt timestamp — clear and proceed normally.
		c.state.Delete(lastSwitchedAtKey)
		c.state.Delete(defersKey)
		return false
	}
	if time.Since(t) > pingPongCooldownPeriod {
		// Cooldown expired — clear and proceed.
		c.state.Delete(lastSwitchedAtKey)
		c.state.Delete(defersKey)
		return false
	}

	defers := getIsolationSwitchAttempts(c, defersKey)
	if defers >= maxPingPongDefers {
		log.Info("post-switch cooldown exhausted — abandoning RT switch (suspected cross-extension fight)",
			"attachmentId", attachmentID, "currentRT", currentRT, "targetRT", targetRT,
			"defers", defers, "max", maxPingPongDefers, "lastSwitchedAt", t.Format(time.RFC3339))
		c.event(corev1.EventTypeWarning, "TGWSwitchDeadlock",
			"Abandoning RT switch for attachment %s after %d consecutive deferrals (current RT %s, target RT %s) — another writer may be fighting this switch. Manual recovery may be needed.",
			attachmentID, defers, currentRT, targetRT)
		c.state.Delete(lastSwitchedAtKey)
		c.state.Delete(defersKey)
		return true
	}

	incrementIsolationSwitchAttempts(c, defersKey)
	log.Info("deferring RT switch — recently completed Phase 2, suspecting cross-extension fight",
		"attachmentId", attachmentID, "currentRT", currentRT, "targetRT", targetRT,
		"lastSwitchedAt", t.Format(time.RFC3339), "defers", defers+1, "max", maxPingPongDefers)
	c.tgwDriftDetected = true // requeue to re-check after cooldown elapses
	return true
}

// getIsolationSwitchAttempts reads the Phase 2 attempt counter from state.
// Returns 0 if the key is missing or invalid.
func getIsolationSwitchAttempts(c *FlowContext, key string) int {
	v := c.state.Get(key)
	if v == nil {
		return 0
	}
	n, err := strconv.Atoi(*v)
	if err != nil {
		return 0
	}
	return n
}

// incrementIsolationSwitchAttempts bumps the Phase 2 attempt counter by 1.
func incrementIsolationSwitchAttempts(c *FlowContext, key string) {
	n := getIsolationSwitchAttempts(c, key)
	c.state.Set(key, strconv.Itoa(n+1))
}

// Attachment roles passed to disableOldRTPropagationIfUnneeded. Used to enforce
// the "never remove load-bearing propagations" invariant — see criticalProps.
const (
	attachmentRoleShoot      = "shoot"
	attachmentRoleSeedVPC    = "seedVPC"
	attachmentRoleRuntimeVPC = "runtimeVPC"
	attachmentRoleGlobalVPC  = "globalVPC"
)

// disableOldRTPropagationIfUnneeded disables the attachment's propagation on the
// old RT after a successful Phase 2 switch — but only if doing so does NOT
// break a load-bearing route the cluster needs to function.
//
// Two layers of protection:
//
//  1. Critical-propagation table (criticalProps): a hard invariant set indexed
//     by attachment role × RT role. The seed VPC MUST always propagate to hub
//     so the runtime VPC can reach the seed apiserver; without it the seed
//     gardenlet crash-loops, DWD scales down child-shoot control planes, and
//     the ManagedSeed reconciler deadlocks (we observed all three this session).
//     The runtime VPC MUST always propagate to hub for the same routing path.
//     These are NEVER removed by this helper, regardless of mode.
//
//  2. "Wanted in current mode" set: covers the per-mode propagation policy
//     (hub-spoke wants hub+spoke; shared wants hub+spoke+shared). Skips the
//     disable when the OLD RT is still wanted by the current mode.
//
// Best-effort: errors are logged, not returned (cleanup, not critical path).
func (c *FlowContext) disableOldRTPropagationIfUnneeded(
	ctx context.Context, log logr.Logger,
	tgwClient awsclient.Interface, oldRT, attachmentID, attachmentRole string,
) {
	// Layer 1: critical, never-remove propagations.
	criticalProps := map[string]string{
		attachmentRoleSeedVPC:    c.resolvedHubRouteTableID,
		attachmentRoleRuntimeVPC: c.resolvedHubRouteTableID,
	}
	if rt, ok := criticalProps[attachmentRole]; ok && rt != "" && rt == oldRT {
		log.Info("keeping critical propagation — load-bearing for cluster routing",
			"oldRT", oldRT, "attachmentId", attachmentID, "role", attachmentRole)
		return
	}

	// Layer 2: per-mode wanted propagations.
	wantedPropagations := map[string]bool{}
	if c.isSharedIsolationMode() {
		// Shared mode wants propagation on all 3 RTs for cross-RT routing.
		if c.resolvedHubRouteTableID != "" {
			wantedPropagations[c.resolvedHubRouteTableID] = true
		}
		if c.resolvedSpokeRouteTableID != "" {
			wantedPropagations[c.resolvedSpokeRouteTableID] = true
		}
		if c.resolvedSharedRouteTableID != "" {
			wantedPropagations[c.resolvedSharedRouteTableID] = true
		}
	} else {
		// Hub-spoke mode: shoots propagate to hub RT only (spoke propagation
		// would break isolation). Hub VPCs (seed/runtime/mgmt) propagate to
		// both hub and spoke (so child shoots on spoke RT can reach them).
		if c.resolvedHubRouteTableID != "" {
			wantedPropagations[c.resolvedHubRouteTableID] = true
		}
		if c.resolvedSpokeRouteTableID != "" {
			wantedPropagations[c.resolvedSpokeRouteTableID] = true
		}
	}

	if wantedPropagations[oldRT] {
		log.Info("keeping old RT propagation — still wanted in current mode",
			"oldRT", oldRT, "attachmentId", attachmentID)
		return
	}

	log.Info("disabling old RT propagation (not wanted in current mode)",
		"oldRT", oldRT, "attachmentId", attachmentID, "role", attachmentRole)
	if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, oldRT, attachmentID); err != nil {
		if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
			log.Info("warning: failed to disable old RT propagation — continuing",
				"oldRT", oldRT, "attachmentId", attachmentID, "error", err)
		}
	}
}


func (c *FlowContext) buildReconcileGraph() *flow.Graph {
	createVPC := c.config.Networks.VPC.ID == nil
	g := flow.NewGraph("AWS infrastructure reconciliation")

	ensureDhcpOptions := c.AddTask(g, "ensure DHCP options for VPC",
		c.ensureDhcpOptions,
		DoIf(createVPC), Timeout(defaultTimeout))

	ensureVpc := c.AddTask(g, "ensure VPC",
		c.ensureVpc,
		Timeout(defaultTimeout), Dependencies(ensureDhcpOptions))

	ensureVpcIPv6CidrBloc := c.AddTask(g, "ensure IPv6 CIDR Block",
		c.ensureVpcIPv6CidrBlock,
		Timeout(defaultTimeout), Dependencies(ensureVpc))

	ensureDefaultSecurityGroup := c.AddTask(g, "ensure default security group",
		c.ensureDefaultSecurityGroup,
		DoIf(createVPC), Timeout(defaultTimeout), Dependencies(ensureVpc))

	ensureInternetGateway := c.AddTask(g, "ensure internet gateway",
		c.ensureInternetGateway,
		DoIf(createVPC), Timeout(defaultTimeout), Dependencies(ensureVpc))

	ensureEgressOnlyInternetGateway := c.AddTask(g, "ensure egress only gateway ",
		c.ensureEgressOnlyInternetGateway,
		DoIf(createVPC), Timeout(defaultTimeout), Dependencies(ensureVpc))

	_ = c.AddTask(g, "ensure gateway endpoints",
		c.ensureGatewayEndpoints,
		Timeout(defaultTimeout), Dependencies(ensureVpc, ensureDefaultSecurityGroup, ensureInternetGateway))

	ensureMainRouteTable := c.AddTask(g, "ensure main route table",
		c.ensureMainRouteTable,
		Timeout(defaultTimeout), Dependencies(ensureVpc, ensureVpcIPv6CidrBloc, ensureDefaultSecurityGroup, ensureInternetGateway, ensureEgressOnlyInternetGateway))

	ensureNodesSecurityGroup := c.AddTask(g, "ensure nodes security group",
		c.ensureNodesSecurityGroup,
		Timeout(defaultTimeout), Dependencies(ensureVpc))

	// Ensure TGW + route tables BEFORE zones so that resolvedTGWID is available
	// when ensurePrivateRoutingTable → mergeCustomRoutes runs (needs TGW ID for
	// auto-generating globalVPC CIDR routes). Does not need VPC or subnets.
	ensureTransitGateway := c.AddTask(g, "Resolve Transit Gateway",
		c.ensureTransitGateway,
		DoIf(c.isSeedTGWEnabled()), Timeout(defaultLongTimeout))

	ensureZones := c.AddTask(g, "ensure zones resources",
		c.ensureZones,
		Timeout(defaultLongTimeout), Dependencies(ensureVpc, ensureNodesSecurityGroup, ensureVpcIPv6CidrBloc, ensureMainRouteTable, ensureTransitGateway))

	// TGW VPC attachment needs zone subnets, so it runs after zones.
	// Skip for the seed shoot — ensureSeedVPCAttachment already handles the same VPC.
	ensureTGWAttachment := c.AddTask(g, "Attach shoot VPC to TGW",
		c.ensureTransitGatewayAttachment,
		DoIf(c.isSeedTGWEnabled()), Timeout(defaultLongTimeout), Dependencies(ensureZones))

	// Clean up stale TGW attachments AFTER the new attachment is created.
	// This ensures no connectivity gap: new attachment is active before old ones are deleted.
	// Only runs if reconcileTGWState flagged stale attachments during Phase 1.
	_ = c.AddTask(g, "Remove stale TGW attachments",
		c.cleanupStaleAttachments,
		DoIf(c.isSeedTGWEnabled()), Timeout(defaultLongTimeout), Dependencies(ensureTGWAttachment))

	// Seed VPC attachment: auto-discover and attach the seed's own VPC to the TGW
	// so shoot workers can reach internal NLBs. Implicit when TGW is enabled and
	// Seed has a node CIDR. Runs after ensureTransitGateway (needs TGW ID).
	// For the seed shoot, this IS the shoot's VPC attachment (same VPC).
	_ = c.AddTask(g, "Attach seed VPC to TGW",
		c.ensureSeedVPCAttachment,
		DoIf(c.shouldAttachSeedVPC()), Timeout(defaultLongTimeout), Dependencies(ensureTransitGateway))

	// Runtime VPC attachment: in managed TGW mode, attach the runtime VPC (where
	// Garden API lives) to the managed TGW. Auto-discovered from Garden API DNS.
	// Runs for ALL shoots in managed mode (idempotent). The seed shoot's infra
	// is reconciled by the parent seed, so child shoot reconcile is the first
	// time the managed seed's extension runs — it must create the attachment.
	// This task also appends the runtime VPC to resolvedEffectiveGlobalVPCs,
	// which must happen before ensureTGWRoutesInZones reads the list.
	ensureRuntimeVPCAttachment := c.AddTask(g, "Attach runtime VPC to TGW",
		c.ensureRuntimeVPCAttachment,
		DoIf(c.isManagedTGWMode()), Timeout(defaultLongTimeout), Dependencies(ensureTransitGateway))

	// After the TGW VPC attachment is created, re-reconcile zone route tables to add
	// TGW routes (seed VPC CIDR, globalVPC CIDRs, runtime VPC CIDR). On the first
	// reconcile, ensureZones skips TGW routes (no attachment yet). This task patches
	// them in after the attachment exists.
	// Depends on ensureRuntimeVPCAttachment because it appends the runtime VPC to
	// resolvedEffectiveGlobalVPCs — without this dependency, buildTGWRoutes() could
	// read the list before the runtime VPC entry is added, missing the route.
	ensureRoutesInZones := c.AddTask(g, "Update VPC route tables for TGW",
		c.ensureTGWRoutesInZones,
		DoIf(c.isSeedTGWEnabled()), Timeout(defaultLongTimeout), Dependencies(ensureTGWAttachment, ensureRuntimeVPCAttachment))

	// Invariant-based stale-TGW route sweep across runtime + globalVPC + seed VPC.
	// Runs AFTER ensureRuntimeVPCAttachment because reconcileTGWState's Phase 0
	// wipes IdentifierRuntimeVPCID on a TGW change, and the sweep needs that ID
	// to find runtime VPC route tables. Without this placement the runtime VPC
	// sweep silently no-ops on every cross-TGW switch (the failure observed on
	// observed: blackhole routes left in runtime VPC after a cross-TGW switch).
	_ = c.AddTask(g, "Sweep stale TGW routes",
		c.sweepStaleTGWRoutesAcrossVPCs,
		DoIf(c.isSeedTGWEnabled()), Timeout(defaultLongTimeout), Dependencies(ensureRuntimeVPCAttachment, ensureRoutesInZones))

	// Shoot-level TGW attachment (independent of seed TGW — additive).
	_ = c.AddTask(g, "ensure shoot-level transit gateway VPC attachment",
		c.ensureShootTransitGatewayAttachment,
		DoIf(c.isShootTGWEnabled()), Timeout(defaultLongTimeout), Dependencies(ensureZones))

	// Cleanup shoot-level TGW when previously enabled but now disabled/removed.
	// This is independent of seed-level TGW cleanup below.
	_ = c.AddTask(g, "cleanup disabled shoot-level transit gateway",
		c.cleanupDisabledShootTransitGateway,
		DoIf(!c.isShootTGWEnabled() && c.state.Get(IdentifierShootTransitGatewayAttachment) != nil),
		Timeout(defaultLongTimeout), Dependencies(ensureZones))

	// Cleanup when seed-level TGW was previously enabled but is now disabled/removed from config.
	// Cleanup disabled TGW: discovery-first approach.
	// Runs when TGW is disabled in config but AWS resources may exist from previous enabled state.
	// Uses AWS API discovery (not state) to find resources, so it works regardless of which
	// shoot's state has the IDs. Idempotent with the delete path.
	_ = c.AddTask(g, "cleanup disabled transit gateway",
		c.cleanupDisabledTransitGateway,
		DoIf(c.shouldCleanupTGW()), Timeout(defaultLongTimeout), Dependencies(ensureZones))

	_ = c.AddTask(g, "ensure efs file system",
		c.ensureEfs,
		DoIf(c.isCsiEfsEnabled()), Timeout(defaultTimeout), Dependencies(ensureZones))

	_ = c.AddTask(g, "ensure subnet cidr reservation",
		c.ensureSubnetCidrReservation,
		Timeout(defaultLongTimeout), Dependencies(ensureZones))

	_ = c.AddTask(g, "ensure egress CIDRs",
		c.ensureEgressCIDRs,
		Timeout(defaultLongTimeout), Dependencies(ensureZones))

	ensureIAMRole := c.AddTask(g, "ensure IAM role",
		c.ensureIAMRole,
		Timeout(defaultTimeout))

	_ = c.AddTask(g, "ensure IAM instance profile",
		c.ensureIAMInstanceProfile,
		Timeout(defaultTimeout), Dependencies(ensureIAMRole))

	_ = c.AddTask(g, "ensure IAM role policy",
		c.ensureIAMRolePolicy,
		Timeout(defaultTimeout), Dependencies(ensureIAMRole))

	_ = c.AddTask(g, "ensure key pair",
		c.ensureKeyPair,
		Timeout(defaultTimeout))

	return g
}

func (c *FlowContext) getDesiredDhcpOptions() *awsclient.DhcpOptions {
	dhcpDomainName := "ec2.internal"

	// This handles a special case for a rule predefined by AWS.
	// See https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-overview-DSN-queries-to-vpc.html
	if c.infraSpec.Region != "us-east-1" {
		dhcpDomainName = fmt.Sprintf("%s.compute.internal", c.infraSpec.Region)
	}

	return &awsclient.DhcpOptions{
		Tags: c.commonTags,
		DhcpConfigurations: map[string][]string{
			"domain-name":         {dhcpDomainName},
			"domain-name-servers": {"AmazonProvidedDNS"},
		},
	}
}

func (c *FlowContext) ensureDhcpOptions(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := c.getDesiredDhcpOptions()
	current, err := FindExisting(ctx, c.state.Get(IdentifierDHCPOptions), c.commonTags,
		c.client.GetVpcDhcpOptions, c.client.FindVpcDhcpOptionsByTags)
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierDHCPOptions, current.DhcpOptionsId)
		if _, err := c.updater.UpdateEC2Tags(ctx, current.DhcpOptionsId, c.commonTags, current.Tags); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateVpcDhcpOptions(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierDHCPOptions, created.DhcpOptionsId)
	}

	return nil
}

func (c *FlowContext) ensureVpc(ctx context.Context) error {
	if c.config.Networks.VPC.ID != nil {
		return c.ensureExistingVpc(ctx)
	}
	return c.ensureManagedVpc(ctx)
}

func (c *FlowContext) getIpFamilies() []v1beta1.IPFamily {
	if c.networking != nil {
		return c.networking.IPFamilies
	}
	return []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}
}

func (c *FlowContext) ensureManagedVpc(ctx context.Context) error {
	log := LogFromContext(ctx)
	log.Info("using managed VPC")
	// Default to shared tenancy unless dedicated tenancy is explicitly enabled.
	// AWS API does this as well, so all VPCs created before have instanceTenancy = "default".
	instanceTenancy := ec2types.TenancyDefault
	if c.config.EnableDedicatedTenancyForVPC != nil && *c.config.EnableDedicatedTenancyForVPC {
		instanceTenancy = ec2types.TenancyDedicated
	}
	desired := &awsclient.VPC{
		Tags:               c.commonTags,
		EnableDnsSupport:   true,
		EnableDnsHostnames: true,
		DhcpOptionsId:      c.state.Get(IdentifierDHCPOptions),
		InstanceTenancy:    instanceTenancy,
	}

	if (c.config.DualStack != nil && c.config.DualStack.Enabled) || ContainsIPv6(c.getIpFamilies()) {
		if c.config.Networks.VPC.Ipv6IpamPool != nil && c.config.Networks.VPC.Ipv6IpamPool.ID != nil {
			desired.AssignGeneratedIPv6CidrBlock = false
			desired.Ipv6IpamPoolId = c.config.Networks.VPC.Ipv6IpamPool.ID
			desired.Ipv6NetmaskLength = ptr.To(int32(defaultIPv6NetmaskSize))
		} else {
			desired.AssignGeneratedIPv6CidrBlock = true
		}
	}

	if c.config.Networks.VPC.CIDR == nil {
		return fmt.Errorf("missing VPC CIDR")
	}

	// Currently it is not possible to create a VPC without an IPv4 CIDR block
	// IPv4 range must also be specified for IPv6 only
	desired.CidrBlock = *c.config.Networks.VPC.CIDR

	current, err := FindExisting(ctx, c.state.Get(IdentifierVPC), c.commonTags,
		c.client.GetVpc, c.client.FindVpcsByTags)
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(IdentifierVPC, current.VpcId)
		if current.IPv6CidrBlock != "" {
			c.state.Set(IdentifierVpcIPv6CidrBlock, current.IPv6CidrBlock)
		}
		_, err := c.updater.UpdateVpc(ctx, desired, current)
		if err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateVpc(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierVPC, created.VpcId)
		_, err = c.updater.UpdateVpc(ctx, desired, created)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *FlowContext) ensureVpcIPv6CidrBlock(ctx context.Context) error {
	if (c.config.DualStack != nil && c.config.DualStack.Enabled) || ContainsIPv6(c.getIpFamilies()) {
		vpcID := *c.state.Get(IdentifierVPC) // guaranteed to be set because of ensureVPC dependency
		ipv6CidrBlock, err := c.client.WaitForIPv6Cidr(ctx, vpcID)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierVpcIPv6CidrBlock, ipv6CidrBlock)
	}
	return nil
}

func (c *FlowContext) ensureExistingVpc(ctx context.Context) error {
	vpcID := *c.config.Networks.VPC.ID
	log := LogFromContext(ctx)
	log.Info("using configured VPC", "vpc", vpcID)
	current, err := c.client.GetVpc(ctx, vpcID)
	if err != nil {
		return err
	}
	if current == nil {
		return fmt.Errorf("VPC %s has not been found", vpcID)
	}
	c.state.Set(IdentifierVPC, vpcID)
	if err := c.validateVpc(ctx, current); err != nil {
		return err
	}
	gw, err := c.client.FindInternetGatewayByVPC(ctx, vpcID)
	if err != nil {
		return fmt.Errorf("internet Gateway not found for VPC %s", vpcID)
	}
	c.state.Set(IdentifierInternetGateway, gw.InternetGatewayId)

	if ContainsIPv6(c.getIpFamilies()) {
		eogw, err := c.client.FindEgressOnlyInternetGatewayByVPC(ctx, vpcID)
		if err != nil || eogw == nil {
			return fmt.Errorf("Egress-Only Internet Gateway not found for VPC %s", vpcID)
		}
		c.state.Set(IdentifierEgressOnlyInternetGateway, eogw.EgressOnlyInternetGatewayId)
	}
	return nil
}

func (c *FlowContext) validateVpc(ctx context.Context, item *awsclient.VPC) error {
	if !item.EnableDnsHostnames {
		return fmt.Errorf("VPC attribute enableDnsHostnames must be set")
	}
	if !item.EnableDnsSupport {
		return fmt.Errorf("VPC attribute enableDnsSupport must be set")
	}
	if item.DhcpOptionsId == nil {
		return fmt.Errorf("missing DhcpOptions for VPC")
	}
	options, err := c.client.GetVpcDhcpOptions(ctx, *item.DhcpOptionsId)
	if err != nil {
		return err
	}
	if options == nil {
		return fmt.Errorf("DhcpOptions for VPC not found: %s", *item.DhcpOptionsId)
	}
	desired := c.getDesiredDhcpOptions()
	for k, v := range desired.DhcpConfigurations {
		if !reflect.DeepEqual(options.DhcpConfigurations[k], v) {
			return fmt.Errorf("missing DhcpConfiguration '%s'='%s' (actual: %s)",
				k, strings.Join(v, ","), strings.Join(options.DhcpConfigurations[k], ","))
		}
	}
	if (ContainsIPv6(c.getIpFamilies()) || (c.config.DualStack != nil && c.config.DualStack.Enabled)) && item.IPv6CidrBlock == "" {
		return fmt.Errorf("VPC has no ipv6 CIDR")
	}
	return nil
}

func (c *FlowContext) ensureDefaultSecurityGroup(ctx context.Context) error {
	current, err := c.client.FindDefaultSecurityGroupByVpcId(ctx, *c.state.Get(IdentifierVPC))
	if err != nil {
		return err
	}
	if current == nil {
		return fmt.Errorf("default security group not found")
	}

	c.state.Set(IdentifierDefaultSecurityGroup, current.GroupId)
	desired := current.Clone()
	desired.Rules = nil
	if _, err := c.updater.UpdateSecurityGroup(ctx, desired, current); err != nil {
		return err
	}
	return nil
}

func (c *FlowContext) ensureInternetGateway(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := &awsclient.InternetGateway{
		Tags:  c.commonTags,
		VpcId: c.state.Get(IdentifierVPC),
	}
	current, err := FindExisting(ctx, c.state.Get(IdentifierInternetGateway), c.commonTags,
		c.client.GetInternetGateway, c.client.FindInternetGatewaysByTags,
		func(item *awsclient.InternetGateway) bool {
			return c.isVpcMatchingState(item.VpcId)
		})
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierInternetGateway, current.InternetGatewayId)
		if err := c.client.AttachInternetGateway(ctx, *c.state.Get(IdentifierVPC), current.InternetGatewayId); err != nil {
			return err
		}
		if _, err := c.updater.UpdateEC2Tags(ctx, current.InternetGatewayId, c.commonTags, current.Tags); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateInternetGateway(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierInternetGateway, created.InternetGatewayId)
		if err := c.client.AttachInternetGateway(ctx, *c.state.Get(IdentifierVPC), created.InternetGatewayId); err != nil {
			return err
		}
	}

	return nil
}

func (c *FlowContext) ensureGatewayEndpoints(ctx context.Context) error {
	log := LogFromContext(ctx)
	child := c.state.GetChild(ChildIdVPCEndpoints)

	var desired []*awsclient.VpcEndpoint
	for _, endpoint := range c.config.Networks.VPC.GatewayEndpoints {
		desired = append(desired, &awsclient.VpcEndpoint{
			Tags:          c.commonTagsWithSuffix(fmt.Sprintf("gw-%s", endpoint)),
			VpcId:         c.state.Get(IdentifierVPC),
			ServiceName:   c.vpcEndpointServiceNamePrefix() + endpoint,
			IpAddressType: string(toEc2IpAddressType(c.getIpFamilies())),
		})
	}
	current, err := c.collectExistingVPCEndpoints(ctx)
	if err != nil {
		return err
	}

	toBeDeleted, toBeCreated, toBeChecked := diffByID(desired, current, c.extractVpcEndpointName)

	// Delete removed endpoints and their associations
	for _, item := range toBeDeleted {
		vpcEndpointName := c.extractVpcEndpointName(item)
		for _, zoneKey := range child.GetChildrenKeys() {
			zoneChild := child.GetChild(zoneKey)
			if routeTableId := zoneChild.Get(IdentifierZoneRouteTable); routeTableId != nil {
				if err := c.client.DeleteVpcEndpointRouteTableAssociation(ctx, *routeTableId, item.VpcEndpointId); err != nil {
					return err
				}
			}
		}
		if err := c.client.DeleteVpcEndpoint(ctx, item.VpcEndpointId); err != nil {
			return err
		}
		child.SetPtr(vpcEndpointName, nil)
	}

	// Create new endpoints
	for _, item := range toBeCreated {
		log.Info("creating...", "serviceName", item.ServiceName)
		created, err := c.client.CreateVpcEndpoint(ctx, item)
		if err != nil {
			return err
		}
		child.Set(c.extractVpcEndpointName(item), created.VpcEndpointId)
	}

	for _, pair := range toBeChecked {
		child.Set(c.extractVpcEndpointName(pair.current), pair.current.VpcEndpointId)
		// Ensure tags on existing endpoints
		if _, err := c.updater.UpdateEC2Tags(ctx, pair.current.VpcEndpointId, pair.desired.Tags, pair.current.Tags); err != nil {
			return err
		}
		// Ensure IpAddressType on existing endpoints
		// Modifying the IpAddressType to or from IPv6 is not supported by AWS
		if pair.current.IpAddressType != pair.desired.IpAddressType &&
			ec2types.IpAddressType(pair.current.IpAddressType) != ec2types.IpAddressTypeIpv6 &&
			ec2types.IpAddressType(pair.desired.IpAddressType) != ec2types.IpAddressTypeIpv6 {
			log.Info("updating ip address type...", "serviceName", pair.current.ServiceName)
			err = c.client.UpdateVpcEndpointIpAddressType(ctx, pair.current.VpcEndpointId, pair.desired.IpAddressType)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *FlowContext) collectExistingVPCEndpoints(ctx context.Context) ([]*awsclient.VpcEndpoint, error) {
	child := c.state.GetChild(ChildIdVPCEndpoints)
	var ids []string
	for _, id := range child.AsMap() {
		ids = append(ids, id)
	}
	var current []*awsclient.VpcEndpoint
	if len(ids) > 0 {
		found, err := c.client.GetVpcEndpoints(ctx, ids)
		if err != nil {
			return nil, err
		}
		current = found
	}
	filters := awsclient.WithFilters().WithVpcId(*c.state.Get(IdentifierVPC)).WithTags(c.clusterTags()).Build()
	foundByTags, err := c.client.FindVpcEndpoints(ctx, filters)
	if err != nil {
		return nil, err
	}
outer:
	for _, item := range foundByTags {
		for _, currentItem := range current {
			if item.VpcEndpointId == currentItem.VpcEndpointId {
				continue outer
			}
		}
		current = append(current, item)
	}
	return current, nil
}

func (c *FlowContext) ensureMainRouteTable(ctx context.Context) error {
	log := LogFromContext(ctx)

	desired := &awsclient.RouteTable{
		Tags:  c.commonTags,
		VpcId: c.state.Get(IdentifierVPC),
		Routes: []*awsclient.Route{
			{
				DestinationCidrBlock: ptr.To(allIPv4),
				GatewayId:            c.state.Get(IdentifierInternetGateway),
			},
		},
	}
	if c.state.Get(IdentifierVpcIPv6CidrBlock) != nil {
		desired.Routes = append(desired.Routes, &awsclient.Route{
			DestinationIpv6CidrBlock: ptr.To(allIPv6),
			GatewayId:                c.state.Get(IdentifierInternetGateway),
		})
	}
	current, err := FindExisting(ctx, c.state.Get(IdentifierMainRouteTable), c.commonTags,
		c.client.GetRouteTable, c.client.FindRouteTablesByTags,
		func(item *awsclient.RouteTable) bool {
			return c.isVpcMatchingState(item.VpcId)
		})
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierMainRouteTable, current.RouteTableId)
		c.state.SetObject(ObjectMainRouteTable, current)
		log.Info("updating route table...")
		if _, err := c.updater.UpdateRouteTable(ctx, log, desired, current); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateRouteTable(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierMainRouteTable, created.RouteTableId)
		c.state.SetObject(ObjectMainRouteTable, created)
		log.Info("updating route table...")
		if _, err := c.updater.UpdateRouteTable(ctx, log, desired, created); err != nil {
			return err
		}
	}

	return nil
}

func (c *FlowContext) ensureNodesSecurityGroup(ctx context.Context) error {
	log := LogFromContext(ctx)
	groupName := fmt.Sprintf("%s-nodes", c.namespace)

	desired := &awsclient.SecurityGroup{
		Tags:        c.commonTagsWithSuffix("nodes"),
		GroupName:   groupName,
		VpcId:       c.state.Get(IdentifierVPC),
		Description: ptr.To("Security group for nodes"),
		Rules: []*awsclient.SecurityGroupRule{
			{
				Type:     awsclient.SecurityGroupRuleTypeIngress,
				Protocol: "-1",
				Self:     true,
			},
			{
				Type:     awsclient.SecurityGroupRuleTypeIngress,
				FromPort: ptr.To[int32](30000),
				ToPort:   ptr.To[int32](32767),
				Protocol: "tcp",
				CidrBlocks: func() []string {
					if containsIPv4(c.getIpFamilies()) {
						return []string{allIPv4}
					}
					return nil
				}(),
				CidrBlocksv6: func() []string {
					if ContainsIPv6(c.getIpFamilies()) {
						return []string{allIPv6}
					}
					return nil
				}(),
			},
			{
				Type:     awsclient.SecurityGroupRuleTypeIngress,
				FromPort: ptr.To[int32](30000),
				ToPort:   ptr.To[int32](32767),
				Protocol: "udp",
				CidrBlocks: func() []string {
					if containsIPv4(c.getIpFamilies()) {
						return []string{allIPv4}
					}
					return nil
				}(),
				CidrBlocksv6: func() []string {
					if ContainsIPv6(c.getIpFamilies()) {
						return []string{allIPv6}
					}
					return nil
				}(),
			},
			{
				Type:     awsclient.SecurityGroupRuleTypeEgress,
				Protocol: "-1",
				CidrBlocks: func() []string {
					if containsIPv4(c.getIpFamilies()) {
						return []string{allIPv4}
					}
					return nil
				}(),
				CidrBlocksv6: func() []string {
					if ContainsIPv6(c.getIpFamilies()) {
						return []string{allIPv6}
					}
					return nil
				}(),
			},
		},
	}

	// Shared TGW mode: allow ingress from peer shoot CIDRs on all protocols. The
	// shared isolation contract is "every shoot can reach every other shoot via
	// the TGW", which requires both routes (added by buildTGWRoutes) AND security
	// group permission for cross-shoot traffic. Without this rule, the routes
	// exist but the destination's nodes-SG silently drops the SYN.
	//
	// Hub-spoke mode is the opposite contract — peer shoots are isolated — so
	// this rule is only added in shared mode.
	if c.isSharedIsolationMode() && len(c.peerShootCIDRs) > 0 && containsIPv4(c.getIpFamilies()) {
		desired.Rules = append(desired.Rules, &awsclient.SecurityGroupRule{
			Type:       awsclient.SecurityGroupRuleTypeIngress,
			Protocol:   "-1",
			CidrBlocks: append([]string(nil), c.peerShootCIDRs...),
		})
	}

	// TODO: @hebelsan - remove processedZones after migration of shoots with duplicated zone name entries
	processedZones := sets.New[string]()
	for index, zone := range c.config.Networks.Zones {
		if processedZones.Has(zone.Name) {
			continue
		}
		processedZones.Insert(zone.Name)

		ruleNodesInternalTCP := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](30000),
			ToPort:   ptr.To[int32](32767),
			Protocol: "tcp",
		}

		ruleNodesInternalUDP := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](30000),
			ToPort:   ptr.To[int32](32767),
			Protocol: "udp",
		}

		ruleNodesPublicTCP := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](30000),
			ToPort:   ptr.To[int32](32767),
			Protocol: "tcp",
		}

		ruleNodesPublicUDP := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](30000),
			ToPort:   ptr.To[int32](32767),
			Protocol: "udp",
		}

		ruleEfsInboundNFS := &awsclient.SecurityGroupRule{
			Type:     awsclient.SecurityGroupRuleTypeIngress,
			FromPort: ptr.To[int32](2049),
			ToPort:   ptr.To[int32](2049),
			Protocol: "tcp",
		}

		if containsIPv4(c.getIpFamilies()) {
			ruleNodesInternalTCP.CidrBlocks = []string{zone.Internal}
			ruleNodesInternalUDP.CidrBlocks = []string{zone.Internal}
			ruleEfsInboundNFS.CidrBlocks = []string{zone.Internal}
			ruleNodesPublicTCP.CidrBlocks = []string{zone.Public}
			ruleNodesPublicUDP.CidrBlocks = []string{zone.Public}
		}

		if ContainsIPv6(c.getIpFamilies()) {
			ipv6CidrBlock := c.state.Get(IdentifierVpcIPv6CidrBlock)
			if ipv6CidrBlock != nil {
				subnetPrefixLength := 64
				internalSubnetCidrIPv6, err := cidrSubnet(*ipv6CidrBlock, subnetPrefixLength, 2+3*index)
				if err != nil {
					return err
				}
				publicSubnetCidrIPv6, err := cidrSubnet(*ipv6CidrBlock, subnetPrefixLength, 3+3*index)
				if err != nil {
					return err
				}
				ruleNodesInternalTCP.CidrBlocksv6 = []string{internalSubnetCidrIPv6}
				ruleNodesInternalUDP.CidrBlocksv6 = []string{internalSubnetCidrIPv6}
				ruleEfsInboundNFS.CidrBlocksv6 = []string{internalSubnetCidrIPv6}
				ruleNodesPublicTCP.CidrBlocksv6 = []string{publicSubnetCidrIPv6}
				ruleNodesPublicUDP.CidrBlocksv6 = []string{publicSubnetCidrIPv6}
			}
		}
		desired.Rules = append(desired.Rules, ruleNodesInternalTCP, ruleNodesInternalUDP, ruleNodesPublicTCP, ruleNodesPublicUDP)
		if c.isCsiEfsEnabled() {
			desired.Rules = append(desired.Rules, ruleEfsInboundNFS)
		}
	}
	current, err := FindExisting(ctx, c.state.Get(IdentifierNodesSecurityGroup), c.commonTagsWithSuffix("nodes"),
		c.client.GetSecurityGroup, c.client.FindSecurityGroupsByTags,
		func(item *awsclient.SecurityGroup) bool {
			return item.GroupName == groupName && c.isVpcMatchingState(item.VpcId)
		})
	if err != nil {
		return err
	}
	if current != nil {
		c.state.Set(IdentifierNodesSecurityGroup, current.GroupId)
		if _, err := c.updater.UpdateSecurityGroup(ctx, desired, current); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateSecurityGroup(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierNodesSecurityGroup, created.GroupId)
		current, err = c.client.GetSecurityGroup(ctx, created.GroupId)
		if err != nil {
			return err
		}
		if _, err := c.updater.UpdateSecurityGroup(ctx, desired, current); err != nil {
			return err
		}
	}

	return nil
}

func (c *FlowContext) ensureEgressCIDRs(ctx context.Context) error {
	var egressIPs []string
	tags := awsclient.Tags{
		c.tagKeyCluster(): TagValueCluster,
	}
	filters := awsclient.WithFilters().WithTags(tags).WithVpcId(*c.state.Get(IdentifierVPC)).Build()
	nats, err := c.client.FindNATGateways(ctx, filters)
	if err != nil {
		return err
	}
	for _, nat := range nats {
		if nat.State != string(ec2types.NatGatewayStateAvailable) {
			continue
		}
		egressIPs = append(egressIPs, fmt.Sprintf("%s/32", nat.PublicIP))
	}
	c.state.Set(IdentifierEgressCIDRs, strings.Join(egressIPs, ","))
	return nil
}

func (c *FlowContext) ensureZones(ctx context.Context) error {
	log := LogFromContext(ctx)
	var desired []*awsclient.Subnet

	// TODO: @hebelsan - remove processedZones after migration of shoots with duplicated zone name entries
	processedZones := sets.New[string]()
	for index, zone := range c.config.Networks.Zones {
		if processedZones.Has(zone.Name) {
			continue
		}
		processedZones.Insert(zone.Name)

		ipv6CidrBlock := c.state.Get(IdentifierVpcIPv6CidrBlock)
		subnetPrefixLength := 64
		var subnetCIDRs []string
		if ipv6CidrBlock != nil {
			for i := 0; i < 3; i++ {
				subnetCIDR, err := cidrSubnet(*ipv6CidrBlock, subnetPrefixLength, i+3*index)
				if err != nil {
					return err
				}
				subnetCIDRs = append(subnetCIDRs, subnetCIDR)
			}
		}
		helper := c.zoneSuffixHelpers(zone.Name)
		tagsWorkers := c.commonTagsWithSuffix(helper.GetSuffixSubnetWorkers())
		tagsPublic := c.commonTagsWithSuffix(helper.GetSuffixSubnetPublic())
		tagsPublic[TagKeyRolePublicELB] = TagValueELB
		tagsPrivate := c.commonTagsWithSuffix(helper.GetSuffixSubnetPrivate())
		tagsPrivate[TagKeyRolePrivateELB] = TagValueELB
		workersCIDR := zone.Workers
		if !containsIPv4(c.getIpFamilies()) {
			workersCIDR = ""
		}
		desired = append(desired,
			&awsclient.Subnet{
				Tags:                                    tagsWorkers,
				VpcId:                                   c.state.Get(IdentifierVPC),
				AvailabilityZone:                        zone.Name,
				AssignIpv6AddressOnCreation:             ptr.To(ContainsIPv6(c.getIpFamilies())),
				CidrBlock:                               workersCIDR,
				Ipv6Native:                              ptr.To(!containsIPv4(c.getIpFamilies())),
				EnableResourceNameDnsAAAARecordOnLaunch: ptr.To(!containsIPv4(c.getIpFamilies())),
				EnableDns64:                             ptr.To(!containsIPv4(c.getIpFamilies())),
			},
			// Load balancers can only be deployed to subnets that have an IPv4 CIDR.
			// Therefore, internal and public subnets must not be IPv6 native.
			&awsclient.Subnet{
				Tags:                        tagsPrivate,
				VpcId:                       c.state.Get(IdentifierVPC),
				AvailabilityZone:            zone.Name,
				AssignIpv6AddressOnCreation: ptr.To(ContainsIPv6(c.getIpFamilies())),
				CidrBlock:                   zone.Internal,
			},
			&awsclient.Subnet{
				Tags:                        tagsPublic,
				VpcId:                       c.state.Get(IdentifierVPC),
				AvailabilityZone:            zone.Name,
				AssignIpv6AddressOnCreation: ptr.To(ContainsIPv6(c.getIpFamilies())),
				CidrBlock:                   zone.Public,
			},
		)

		for i := 0; i < 3; i++ {
			if len(subnetCIDRs) == 3 && subnetCIDRs[i] != "" {
				desired[i+3*index].Ipv6CidrBlocks = []string{subnetCIDRs[i]}
			}
		}
	}
	// update flow state if subnet suffixes have been added
	if err := c.PersistState(ctx); err != nil {
		return err
	}
	current, err := c.collectExistingSubnets(ctx)
	if err != nil {
		return err
	}

	log.Info("Found existing subnets", "subnetIDs", mmap(current, func(t *awsclient.Subnet) string {
		return t.SubnetId
	}))
	toBeDeleted, toBeCreated, toBeChecked := diffByID(desired, current, func(item *awsclient.Subnet) string {
		if item.Ipv6CidrBlocks != nil && item.CidrBlock == "" {
			return item.AvailabilityZone + "-" + item.Ipv6CidrBlocks[0]
		}
		return item.AvailabilityZone + "-" + item.CidrBlock
	})

	g := flow.NewGraph("AWS infrastructure reconciliation: zones")

	if err := c.addZoneDeletionTasksBySubnets(g, toBeDeleted); err != nil {
		return err
	}

	dependencies := newZoneDependencies()
	for _, item := range toBeCreated {
		taskID, err := c.addSubnetReconcileTasks(g, item, nil)
		if err != nil {
			return err
		}
		dependencies.Append(item.AvailabilityZone, taskID)
	}
	for _, pair := range toBeChecked {
		taskID, err := c.addSubnetReconcileTasks(g, pair.desired, pair.current)
		if err != nil {
			return err
		}
		dependencies.Append(pair.desired.AvailabilityZone, taskID)
	}

	// TODO: @hebelsan - remove processedZones after migration of shoots with duplicated zone name entries
	processedZones = sets.New[string]()
	for _, item := range c.config.Networks.Zones {
		if processedZones.Has(item.Name) {
			continue
		}
		processedZones.Insert(item.Name)

		zone := item
		c.addZoneReconcileTasks(g, &zone, dependencies.Get(zone.Name))
	}
	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{Log: c.log}); err != nil {
		return flow.Causes(err)
	}
	return nil
}

func (c *FlowContext) addZoneDeletionTasksBySubnets(g *flow.Graph, toBeDeleted []*awsclient.Subnet) error {
	toBeDeletedZones := sets.NewString()
	for _, item := range toBeDeleted {
		toBeDeletedZones.Insert(getZoneName(item))
	}
	dependencies := newZoneDependencies()
	for zoneName := range toBeDeletedZones {
		taskID := c.addZoneDeletionTasks(g, zoneName)
		dependencies.Append(zoneName, taskID)
	}
	for _, item := range toBeDeleted {
		if err := c.addSubnetDeletionTasks(g, item, dependencies.Get(item.AvailabilityZone)); err != nil {
			return err
		}
	}
	return nil
}

func (c *FlowContext) collectExistingSubnets(ctx context.Context) ([]*awsclient.Subnet, error) {
	child := c.state.GetChild(ChildIdZones)
	var ids []string
	for _, zoneKey := range child.GetChildrenKeys() {
		zoneChild := child.GetChild(zoneKey)
		if id := zoneChild.Get(IdentifierZoneSubnetWorkers); id != nil {
			ids = append(ids, *id)
		}
		if id := zoneChild.Get(IdentifierZoneSubnetPublic); id != nil {
			ids = append(ids, *id)
		}
		if id := zoneChild.Get(IdentifierZoneSubnetPrivate); id != nil {
			ids = append(ids, *id)
		}
	}

	var current []*awsclient.Subnet
	if len(ids) > 0 {
		found, err := c.client.GetSubnets(ctx, ids)
		if err != nil {
			return nil, err
		}
		current = found
	}
	foundSubnets, err := c.client.FindSubnets(ctx, awsclient.WithFilters().WithVpcId(*c.state.Get(IdentifierVPC)).WithTags(c.clusterTags()).Build())
	if err != nil {
		return nil, err
	}
	for _, item := range foundSubnets {
		func() {
			for _, currentItem := range current {
				if item.SubnetId == currentItem.SubnetId {
					return
				}
			}
			current = append(current, item)
		}()
	}
	return current, nil
}

func (c *FlowContext) addSubnetReconcileTasks(g *flow.Graph, desired, current *awsclient.Subnet) (flow.TaskIDer, error) {
	zoneName, subnetKey, err := c.getSubnetKey(desired)
	if err != nil {
		return nil, err
	}
	suffix := fmt.Sprintf("%s-%s", zoneName, subnetKey)
	if ptr.Deref(desired.AssignIpv6AddressOnCreation, true) {
		return c.AddTask(g, "ensure IPv6 subnet "+suffix,
			c.ensureSubnetIPv6(subnetKey, desired, current),
			Timeout(defaultTimeout)), nil
	}
	return c.AddTask(g, "ensure subnet "+suffix,
		c.ensureSubnet(subnetKey, desired, current),
		Timeout(defaultTimeout)), nil
}

func (c *FlowContext) addZoneReconcileTasks(g *flow.Graph, zone *aws.Zone, dependencies []flow.TaskIDer) {
	ensureRecreateNATGateway := c.AddTask(g, "ensure NAT gateway recreation "+zone.Name,
		c.ensureRecreateNATGateway(zone),
		Timeout(defaultTimeout), Dependencies(dependencies...))

	ensureElasticIP := c.AddTask(g, "ensure NAT gateway elastic IP "+zone.Name,
		c.ensureElasticIP(zone),
		Timeout(defaultTimeout), Dependencies(dependencies...), Dependencies(ensureRecreateNATGateway))

	ensureNATGateway := c.AddTask(g, "ensure NAT gateway "+zone.Name,
		c.ensureNATGateway(zone),
		Timeout(defaultLongTimeout), Dependencies(dependencies...), Dependencies(ensureElasticIP))

	ensureRoutingTable := c.AddTask(g, "ensure route table "+zone.Name,
		c.ensurePrivateRoutingTable(zone.Name),
		Timeout(defaultTimeout), Dependencies(dependencies...), Dependencies(ensureNATGateway))

	_ = c.AddTask(g, "ensure route table associations "+zone.Name,
		c.ensureRoutingTableAssociations(zone.Name),
		Timeout(defaultTimeout), Dependencies(dependencies...), Dependencies(ensureRoutingTable))

	_ = c.AddTask(g, "ensure VPC endpoints route table associations "+zone.Name,
		c.ensureVPCEndpointsRoutingTableAssociations(zone.Name),
		Timeout(defaultTimeout), Dependencies(dependencies...), Dependencies(ensureRoutingTable))
}

func (c *FlowContext) addZoneDeletionTasks(g *flow.Graph, zoneName string) flow.TaskIDer {
	deleteRoutingTableAssocs := c.AddTask(g, "delete route table associations "+zoneName,
		c.deleteRoutingTableAssociations(zoneName),
		Timeout(defaultTimeout))

	deleteRoutingTable := c.AddTask(g, "delete route table "+zoneName,
		c.deletePrivateRoutingTable(zoneName),
		Timeout(defaultTimeout), Dependencies(deleteRoutingTableAssocs))

	deleteNATGateway := c.AddTask(g, "delete NAT gateway "+zoneName,
		c.deleteNATGateway(zoneName),
		Timeout(defaultLongTimeout), Dependencies(deleteRoutingTable))

	_ = c.AddTask(g, "delete NAT gateway elastic IP "+zoneName,
		c.deleteElasticIP(zoneName),
		Timeout(defaultTimeout), Dependencies(deleteNATGateway))

	return deleteNATGateway
}

func (c *FlowContext) addSubnetDeletionTasks(g *flow.Graph, item *awsclient.Subnet, dependencies []flow.TaskIDer) error {
	zoneName, subnetKey, err := c.getSubnetKey(item)
	if err != nil {
		return err
	}
	suffix := fmt.Sprintf("%s-%s", zoneName, subnetKey)
	_ = c.AddTask(g, "delete subnet resource "+suffix,
		c.deleteSubnet(subnetKey, item),
		Timeout(defaultTimeout), Dependencies(dependencies...))
	return nil
}

func (c *FlowContext) deleteSubnet(subnetKey string, item *awsclient.Subnet) flow.TaskFn {
	zoneChild := c.getSubnetZoneChildByItem(item)
	return func(ctx context.Context) error {
		if zoneChild.Get(subnetKey) == nil {
			return nil
		}
		log := LogFromContext(ctx)
		log.Info("deleting...", "SubnetID", item.SubnetId)
		waiter := informOnWaiting(log, 10*time.Second, "still deleting...", "SubnetID", item.SubnetId)
		err := c.client.DeleteSubnet(ctx, item.SubnetId)
		waiter.Done(err)
		if err != nil {
			return err
		}
		zoneChild.Delete(subnetKey)
		return nil
	}
}

func (c *FlowContext) ensureSubnet(subnetKey string, desired, current *awsclient.Subnet) flow.TaskFn {
	zoneChild := c.getSubnetZoneChildByItem(desired)
	if current == nil {
		return func(ctx context.Context) error {
			log := LogFromContext(ctx)
			log.Info("creating...")
			created, err := c.client.CreateSubnet(ctx, desired, defaultTimeout)
			if err != nil {
				return err
			}
			zoneChild.Set(subnetKey, created.SubnetId)
			return nil
		}
	}
	return func(ctx context.Context) error {
		zoneChild.Set(subnetKey, current.SubnetId)
		modified, err := c.updater.UpdateSubnet(ctx, desired, current)
		if err != nil {
			return err
		}
		if modified {
			log := LogFromContext(ctx)
			log.Info("updated")
		}
		return nil
	}
}

func (c *FlowContext) ensureSubnetIPv6(subnetKey string, desired, current *awsclient.Subnet) flow.TaskFn {
	zoneChild := c.getSubnetZoneChildByItem(desired)
	if current == nil {
		return func(ctx context.Context) error {
			log := LogFromContext(ctx)
			log.Info("creating...")
			var lastErr error
			for attempts := 0; attempts < 256; attempts++ {
				created, err := c.client.CreateSubnet(ctx, desired, defaultTimeout)
				if err == nil {
					zoneChild.Set(subnetKey, created.SubnetId)
					return nil
				}
				// Check for InvalidSubnet.Conflict error
				apiErrCode := awsclient.GetAWSAPIErrorCode(err)
				if apiErrCode == "InvalidSubnet.Conflict" {
					log.Info("CIDR conflict, trying next CIDR block")
					newCIDRs, nextErr := calcNextIPv6CidrBlock(desired.Ipv6CidrBlocks[0])
					if nextErr != nil {
						return nextErr
					}
					desired.Ipv6CidrBlocks = []string{newCIDRs}
					lastErr = err
					continue
				}
				// Any other error, return immediately
				return err
			}
			// If we exhausted all attempts, return the last error
			if lastErr != nil {
				return lastErr
			}
			return fmt.Errorf("failed to create subnet after multiple attempts")
		}
	}
	return func(ctx context.Context) error {
		zoneChild.Set(subnetKey, current.SubnetId)
		modified, err := c.updater.UpdateSubnet(ctx, desired, current)
		if err != nil {
			return err
		}
		if modified {
			log := LogFromContext(ctx)
			log.Info("updated")
		}
		return nil
	}
}

func (c *FlowContext) ensureSubnetCidrReservation(ctx context.Context) error {
	if !ContainsIPv6(c.getIpFamilies()) {
		return nil
	}

	subnets, err := c.collectExistingSubnets(ctx)
	if err != nil {
		return err
	}

	for _, subnet := range subnets {
		_, key, err := c.getSubnetKey(subnet)
		if err != nil {
			return err
		}

		if key == IdentifierZoneSubnetWorkers {
			cidr, err := cidrSubnet(subnet.Ipv6CidrBlocks[0], 108, 1)
			if err != nil {
				return err
			}

			currentCidrs, err := c.client.GetIPv6CIDRReservations(ctx, subnet)
			if err != nil {
				return err
			}

			if slices.Contains(currentCidrs, cidr) {
				c.state.Set(IdentifierServiceCIDR, cidr)
				return nil
			}
		}
	}

	// we didn't find a CIDR reservation on a subnet
	// create a new one at the first nodes subnet we find
	for _, subnet := range subnets {
		_, key, err := c.getSubnetKey(subnet)
		if err != nil {
			return err
		}

		if key == IdentifierZoneSubnetWorkers {
			cidr, err := cidrSubnet(subnet.Ipv6CidrBlocks[0], 108, 1)
			if err != nil {
				return err
			}

			cidr, err = c.client.CreateCIDRReservation(ctx, subnet, cidr, "explicit")
			if err != nil {
				return err
			}
			c.state.Set(IdentifierServiceCIDR, cidr)
			return nil
		}
	}
	return nil
}

func (c *FlowContext) ensureElasticIP(zone *aws.Zone) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		helper := c.zoneSuffixHelpers(zone.Name)
		child := c.getSubnetZoneChild(zone.Name)
		id := child.Get(IdentifierManagedZoneNATGWElasticIP)
		if zone.ElasticIPAllocationID != nil {
			// check if we need to clean up gardener managed IP, after user switched from managed to unmanaged
			if id != nil && *id != *zone.ElasticIPAllocationID {
				ip, err := c.client.GetElasticIP(ctx, *id)
				if err != nil {
					return err
				}
				// make sure that the EIP is not in use
				if ip != nil && ip.AssociationID == nil {
					log.Info("deleting unused managed elastic IP found in state", "id", *id)
					err = c.deleteElasticIpWithWait(ctx, ip)
					if err != nil {
						return err
					}
					child.Delete(IdentifierManagedZoneNATGWElasticIP)
				}
			}
			return nil
		}
		desired := &awsclient.ElasticIP{
			Tags: c.commonTagsWithSuffix(helper.GetSuffixElasticIP()),
			Vpc:  true,
		}
		current, err := FindExisting(ctx, id, desired.Tags, c.client.GetElasticIP, c.client.FindElasticIPsByTags)
		if err != nil {
			return err
		}

		if current != nil {
			child.Set(IdentifierManagedZoneNATGWElasticIP, current.AllocationId)
			if _, err := c.updater.UpdateEC2Tags(ctx, current.AllocationId, desired.Tags, current.Tags); err != nil {
				return err
			}
		} else {
			log.Info("creating...")
			created, err := c.client.CreateElasticIP(ctx, desired)
			if err != nil {
				return err
			}
			child.Set(IdentifierManagedZoneNATGWElasticIP, created.AllocationId)
		}

		return nil
	}
}

func (c *FlowContext) deleteElasticIP(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		child := c.getSubnetZoneChild(zoneName)
		if child.Get(IdentifierManagedZoneNATGWElasticIP) == nil {
			return nil
		}
		helper := c.zoneSuffixHelpers(zoneName)
		tags := c.commonTagsWithSuffix(helper.GetSuffixElasticIP())
		current, err := FindExisting(ctx, child.Get(IdentifierManagedZoneNATGWElasticIP), tags, c.client.GetElasticIP, c.client.FindElasticIPsByTags)
		if err != nil {
			return err
		}
		err = c.deleteElasticIpWithWait(ctx, current)
		if err != nil {
			return err
		}
		child.Delete(IdentifierManagedZoneNATGWElasticIP)
		return nil
	}
}

func (c *FlowContext) deleteElasticIpWithWait(ctx context.Context, elasticIP *awsclient.ElasticIP) error {
	if elasticIP != nil {
		log := LogFromContext(ctx)
		log.Info("deleting...", "AllocationId", elasticIP.AllocationId)
		waiter := informOnWaiting(log, 10*time.Second, "still deleting...", "AllocationId", elasticIP.AllocationId)
		err := c.client.DeleteElasticIP(ctx, elasticIP.AllocationId)
		waiter.Done(err)
		if err != nil {
			return err
		}
	}
	return nil
}

// ensureRecreateNATGateway checks if the EIPAllocationId has changed.
func (c *FlowContext) ensureRecreateNATGateway(zone *aws.Zone) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		child := c.getSubnetZoneChild(zone.Name)
		helper := c.zoneSuffixHelpers(zone.Name)
		desired := &awsclient.NATGateway{
			Tags:     c.commonTagsWithSuffix(helper.GetSuffixNATGateway()),
			SubnetId: *child.Get(IdentifierZoneSubnetPublic),
		}
		// no NAT was created yet
		if zone.ElasticIPAllocationID == nil && child.Get(IdentifierManagedZoneNATGWElasticIP) == nil {
			return nil
		}
		if zone.ElasticIPAllocationID != nil {
			desired.EIPAllocationId = *zone.ElasticIPAllocationID
		} else {
			desired.EIPAllocationId = *child.Get(IdentifierManagedZoneNATGWElasticIP)
		}
		current, err := FindExisting(ctx, child.Get(IdentifierZoneNATGateway), desired.Tags, c.client.GetNATGateway, c.client.FindNATGatewaysByTags,
			func(item *awsclient.NATGateway) bool {
				// a failed NAT will automatically be deleted by AWS
				return !isNATGatewayDeletingOrFailed(item) && c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}

		if current != nil && current.EIPAllocationId != desired.EIPAllocationId {
			log.Info("deleting NAT because of EIPAllocationID change detected", "current EIPAllocationId",
				current.EIPAllocationId, "desired EIPAllocationId", desired.EIPAllocationId)
			err := c.deleteNATGateway(zone.Name)(ctx)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *FlowContext) ensureNATGateway(zone *aws.Zone) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		child := c.getSubnetZoneChild(zone.Name)
		helper := c.zoneSuffixHelpers(zone.Name)
		desired := &awsclient.NATGateway{
			Tags:     c.commonTagsWithSuffix(helper.GetSuffixNATGateway()),
			SubnetId: *child.Get(IdentifierZoneSubnetPublic),
		}
		if zone.ElasticIPAllocationID != nil {
			desired.EIPAllocationId = *zone.ElasticIPAllocationID
		} else {
			desired.EIPAllocationId = *child.Get(IdentifierManagedZoneNATGWElasticIP)
		}
		current, err := FindExisting(ctx, child.Get(IdentifierZoneNATGateway), desired.Tags, c.client.GetNATGateway, c.client.FindNATGatewaysByTags,
			func(item *awsclient.NATGateway) bool {
				return !isNATGatewayDeletingOrFailed(item) && c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}

		if current != nil {
			child.Set(IdentifierZoneNATGateway, current.NATGatewayId)
			if _, err := c.updater.UpdateEC2Tags(ctx, current.NATGatewayId, desired.Tags, current.Tags); err != nil {
				return err
			}
			waiter := informOnWaiting(log, 10*time.Second, "waiting for NATGateway to become available...")
			err = c.client.WaitForNATGatewayAvailable(ctx, current.NATGatewayId)
			waiter.Done(err)
			if err != nil {
				return err
			}
		} else {
			child.Set(IdentifierZoneNATGateway, "")
			log.Info("creating...")
			waiter := informOnWaiting(log, 10*time.Second, "still creating...")
			created, err := c.client.CreateNATGateway(ctx, desired)
			if created != nil {
				waiter.UpdateMessage("waiting until available...")
				if perr := c.PersistState(ctx); perr != nil {
					log.Info("persisting state failed", "error", perr)
				}
				child.Set(IdentifierZoneNATGateway, created.NATGatewayId)
				err = c.client.WaitForNATGatewayAvailable(ctx, created.NATGatewayId)
			}
			waiter.Done(err)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *FlowContext) deleteNATGateway(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		child := c.getSubnetZoneChild(zoneName)
		if child.Get(IdentifierZoneNATGateway) == nil {
			return nil
		}
		log := LogFromContext(ctx)
		helper := c.zoneSuffixHelpers(zoneName)
		tags := c.commonTagsWithSuffix(helper.GetSuffixNATGateway())
		current, err := FindExisting(ctx, child.Get(IdentifierZoneNATGateway), tags, c.client.GetNATGateway, c.client.FindNATGatewaysByTags,
			func(item *awsclient.NATGateway) bool {
				// a failed NAT will automatically be deleted by AWS
				return !isNATGatewayDeletingOrFailed(item) && c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}
		if current != nil {
			log.Info("deleting...", "NATGatewayId", current.NATGatewayId)
			waiter := informOnWaiting(log, 10*time.Second, "still deleting...", "NATGatewayId", current.NATGatewayId)
			err := c.client.DeleteNATGateway(ctx, current.NATGatewayId)
			waiter.Done(err)
			if err != nil {
				return err
			}
		}
		child.Delete(IdentifierZoneNATGateway)
		return nil
	}
}

func (c *FlowContext) ensureEgressOnlyInternetGateway(ctx context.Context) error {
	if !ContainsIPv6(c.getIpFamilies()) {
		return nil
	}

	log := LogFromContext(ctx)
	desired := &awsclient.EgressOnlyInternetGateway{
		Tags:  c.commonTags,
		VpcId: c.state.Get(IdentifierVPC),
	}
	current, err := FindExisting(ctx, c.state.Get(IdentifierEgressOnlyInternetGateway), c.commonTags,
		c.client.GetEgressOnlyInternetGateway, c.client.FindEgressOnlyInternetGatewaysByTags,
		func(item *awsclient.EgressOnlyInternetGateway) bool {
			return c.isVpcMatchingState(item.VpcId)
		})
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(IdentifierEgressOnlyInternetGateway, current.EgressOnlyInternetGatewayId)
		if _, err := c.updater.UpdateEC2Tags(ctx, current.EgressOnlyInternetGatewayId, c.commonTags, current.Tags); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateEgressOnlyInternetGateway(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(IdentifierEgressOnlyInternetGateway, created.EgressOnlyInternetGatewayId)
	}
	return nil
}

func (c *FlowContext) ensurePrivateRoutingTable(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		child := c.getSubnetZoneChild(zoneName)
		id := child.Get(IdentifierZoneRouteTable)

		var routes []*awsclient.Route

		routes = append(routes, &awsclient.Route{
			DestinationCidrBlock: ptr.To(allIPv4),
			NatGatewayId:         child.Get(IdentifierZoneNATGateway),
		})

		if ContainsIPv6(c.getIpFamilies()) {
			routes = append(routes, &awsclient.Route{
				DestinationIpv6CidrBlock:    ptr.To(allIPv6),
				EgressOnlyInternetGatewayId: c.state.Get(IdentifierEgressOnlyInternetGateway),
			})
			routes = append(routes, &awsclient.Route{
				DestinationIpv6CidrBlock: ptr.To(nat64Prefix),
				NatGatewayId:             child.Get(IdentifierZoneNATGateway),
			})
		}

		// Merge custom routes: seed-level globalCustomRoutes first, then shoot-level customRoutes.
		routes = append(routes, c.mergeCustomRoutes()...)

		desired := &awsclient.RouteTable{
			Tags:   c.commonTagsWithSuffix(fmt.Sprintf("private-%s", zoneName)),
			VpcId:  c.state.Get(IdentifierVPC),
			Routes: routes,
		}

		current, err := FindExisting(ctx, id, desired.Tags, c.client.GetRouteTable, c.client.FindRouteTablesByTags,
			func(item *awsclient.RouteTable) bool {
				return c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}

		if current != nil {
			child.Set(IdentifierZoneRouteTable, current.RouteTableId)
			child.SetObject(ObjectZoneRouteTable, current)
			if _, err := c.updater.UpdateRouteTable(ctx, log, desired, current); err != nil {
				return err
			}
		} else {
			log.Info("creating...", "zone", zoneName)
			created, err := c.client.CreateRouteTable(ctx, desired)
			if err != nil {
				return err
			}
			child.Set(IdentifierZoneRouteTable, created.RouteTableId)
			child.SetObject(ObjectZoneRouteTable, created)
			if _, err := c.updater.UpdateRouteTable(ctx, log, desired, created); err != nil {
				return err
			}
		}

		return nil
	}
}

// mergeCustomRoutes merges seed-level globalCustomRoutes, globalVPC CIDR routes,
// seed VPC auto-route, and shoot-level customRoutes into awsclient.Route entries
// for private zone route tables.
// Order: seed VPC CIDR first, then globalVPC CIDRs, then global custom routes, then shoot custom routes.
func (c *FlowContext) mergeCustomRoutes() []*awsclient.Route {
	var routes []*awsclient.Route

	// TGW routes (seed VPC CIDR, globalVPC CIDRs) are NOT added here.
	// They are handled by ensureTGWRoutesInZones, which runs AFTER the VPC attachment
	// is created. This avoids CreateRoute failures when no attachment exists yet,
	// and ensures routes are always in sync regardless of DAG ordering.

	// Seed-level global custom routes
	if c.seedConfig != nil {
		for i := range c.seedConfig.GlobalCustomRoutes {
			if r := customRouteToClientRoute(&c.seedConfig.GlobalCustomRoutes[i]); r != nil {
				routes = append(routes, r)
			}
		}
	}

	// Shoot-level custom routes
	for i := range c.config.Networks.CustomRoutes {
		if r := customRouteToClientRoute(&c.config.Networks.CustomRoutes[i]); r != nil {
			routes = append(routes, r)
		}
	}

	return routes
}

// buildTGWRoutes generates TGW-specific routes (seed VPC CIDR, globalVPC CIDRs)
// for injection into zone route tables. Called by ensureTGWRoutesInZones.
func (c *FlowContext) buildTGWRoutes() []*awsclient.Route {
	var routes []*awsclient.Route
	tgwID := c.resolvedTGWID
	if tgwID == "" {
		return nil
	}

	// Seed VPC auto-route: shoot workers need to reach the seed VPC.
	if c.shouldAttachSeedVPC() {
		seedCIDR := c.seedNodesCIDR
		routes = append(routes, &awsclient.Route{
			DestinationCidrBlock: &seedCIDR,
			TransitGatewayId:     &tgwID,
		})
	}

	// GlobalVPC CIDR auto-routes.
	if c.isSeedTGWEnabled() && c.seedConfig != nil && c.seedConfig.TransitGateway != nil {
		for _, gvpc := range c.resolvedEffectiveGlobalVPCs {
			for _, cidr := range gvpc.CIDRs {
				cidrCopy := cidr
				routes = append(routes, &awsclient.Route{
					DestinationCidrBlock: &cidrCopy,
					TransitGatewayId:     &tgwID,
				})
			}
		}
	}

	// Shared mode: peer shoot VPC CIDR routes so shoots can reach each other via TGW.
	// Without these, traffic to a peer shoot CIDR hits the default route (NAT/IGW)
	// instead of the TGW, even though the TGW shared RT has propagated routes.
	if c.isSharedIsolationMode() {
		for _, cidr := range c.peerShootCIDRs {
			cidrCopy := cidr
			routes = append(routes, &awsclient.Route{
				DestinationCidrBlock: &cidrCopy,
				TransitGatewayId:     &tgwID,
			})
		}
	}

	return routes
}

// customRouteToClientRoute converts an API CustomRoute to an awsclient.Route.
func customRouteToClientRoute(cr *aws.CustomRoute) *awsclient.Route {
	r := &awsclient.Route{
		DestinationCidrBlock:    cr.DestinationCidrBlock,
		DestinationPrefixListId: cr.DestinationPrefixListId,
		TransitGatewayId:        cr.TransitGatewayId,
		VpcPeeringConnectionId:  cr.VpcPeeringConnectionId,
		NetworkInterfaceId:      cr.NetworkInterfaceId,
	}
	// A route must have at least one destination
	if r.DestinationCidrBlock == nil && r.DestinationPrefixListId == nil {
		return nil
	}
	return r
}

// ensureTransitGateway ensures the Transit Gateway exists (referenced or auto-created),
// along with its hub and spoke route tables.
func (c *FlowContext) ensureTransitGateway(ctx context.Context) error {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil {
		return fmt.Errorf("internal error: ensureTransitGateway called without seed TGW config")
	}
	log := LogFromContext(ctx)
	tgwConfig := c.seedConfig.TransitGateway

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	// Resolve TGW ID: referenced (ID set) or auto-create (ID nil).
	// Follows the standard Gardener pattern: nil ID = managed, non-nil = referenced.
	var tgwID string
	if tgwConfig.ID != nil {
		// Referenced TGW — just verify it exists.
		tgwID = *tgwConfig.ID
		existing, err := tgwClient.GetTransitGateway(ctx, tgwID)
		if err != nil {
			return fmt.Errorf("failed to get referenced transit gateway %s: %w", tgwID, err)
		}
		if existing == nil {
			return fmt.Errorf("referenced transit gateway %s not found", tgwID)
		}
		log.Info("using referenced transit gateway", "tgwId", tgwID, "state", existing.State)
		c.event(corev1.EventTypeNormal, "TGWResolved", "Using referenced Transit Gateway %s", tgwID)
		// Referenced — not managed, never deleted by us.
		c.state.Delete(IdentifierTransitGatewayManaged)
	} else {
		// Managed mode: find the managed TGW by seed shoot tags or create it.
		// by looking it up from state (previous reconcile) or by searching
		// for TGWs tagged by the seed shoot.
		// Child shoots never create, modify, or own the TGW.
		// Try state first, but verify the TGW is actually the managed TGW
		// (tagged with seed shoot namespace). State may contain a stale reference
		// to a different TGW (e.g., ref TGW from a previous mode).
		stateID := c.state.Get(IdentifierTransitGatewayID)
		seedShootNS := c.seedShootNamespace
		if stateID != nil {
			existing, err := tgwClient.GetTransitGateway(ctx, *stateID)
			if err != nil {
				return fmt.Errorf("failed to get managed TGW %s from state: %w", *stateID, err)
			}
			if existing != nil {
				// Verify this TGW belongs to our seed (has seed shoot tags).
				expectedTag := fmt.Sprintf(TagKeyClusterTemplate, seedShootNS)
				if existing.Tags[expectedTag] == TagValueCluster {
					tgwID = *stateID
					log.Info("child shoot using managed TGW from state (tag verified)", "tgwId", tgwID)
				} else {
					log.Info("TGW from state is not the managed TGW (wrong tags, likely ref TGW from previous mode) — falling through to tag discovery",
						"staleTgwId", *stateID, "expectedTag", expectedTag)
					c.state.Delete(IdentifierTransitGatewayID)
					c.state.Delete(IdentifierTransitGatewayManaged)
				}
			} else {
				log.Info("managed TGW from state no longer exists, falling through to tag discovery", "staleTgwId", *stateID)
				c.state.Delete(IdentifierTransitGatewayManaged)
			}
		}
		if tgwID == "" {
			// First reconcile or stale state: find TGW by seed shoot tags.
			seedTags := awsclient.Tags{
				fmt.Sprintf(TagKeyClusterTemplate, seedShootNS): TagValueCluster,
			}
			found, err := tgwClient.FindTransitGatewaysByTags(ctx, seedTags)
			if err != nil {
				return fmt.Errorf("failed to find seed's managed TGW by tags: %w", err)
			}
			if len(found) == 0 {
				// Managed TGW not found by tags. In managed mode, the TGW must be
				// created. The seed shoot's infra is reconciled by the parent seed
				// (which uses referenced mode), so child shoot reconcile is the first
				// time the managed seed's extension runs. Create the TGW here.
				if c.seedConfig == nil || c.seedConfig.TransitGateway == nil || !c.seedConfig.TransitGateway.Enabled {
					// TGW disabled or config missing — skip gracefully (deletion path).
					log.Info("managed TGW not found and TGW not enabled — skipping TGW operations")
					return nil
				}
				log.Info("managed TGW not found — creating it (first child shoot on managed seed)")
				tags := awsclient.Tags{
					fmt.Sprintf(TagKeyClusterTemplate, seedShootNS): TagValueCluster,
				}
				tgwDesired := &awsclient.TransitGateway{Tags: tags}
				if c.seedConfig.TransitGateway.CreateConfig != nil {
					tgwDesired.CreateOptions = &awsclient.TransitGatewayCreateOptions{
						AmazonSideAsn:               c.seedConfig.TransitGateway.CreateConfig.AmazonSideAsn,
						EnableDefaultAssociation:    c.seedConfig.TransitGateway.CreateConfig.EnableDefaultAssociation,
						EnableDefaultPropagation:    c.seedConfig.TransitGateway.CreateConfig.EnableDefaultPropagation,
						AutoAcceptSharedAttachments: c.seedConfig.TransitGateway.CreateConfig.AutoAcceptSharedAttachments,
					}
				}
				created, createErr := tgwClient.CreateTransitGateway(ctx, tgwDesired)
				if createErr != nil {
					return fmt.Errorf("failed to create managed TGW: %w", createErr)
				}
				tgwID = created.TransitGatewayId
				log.Info("created managed TGW", "tgwId", tgwID)
				c.event(corev1.EventTypeNormal, "TGWCreated", "Created managed Transit Gateway %s (first child shoot on seed)", tgwID)
				if err := tgwClient.WaitForTransitGatewayAvailable(ctx, tgwID); err != nil {
					return fmt.Errorf("failed waiting for managed TGW to become available: %w", err)
				}
				c.state.Set(IdentifierTransitGatewayManaged, "true")
			} else {
				tgwID = found[0].TransitGatewayId
				log.Info("child shoot discovered seed's managed TGW by tags", "tgwId", tgwID, "seedShoot", seedShootNS)
			}
		}
		// Child shoots never own the TGW — don't set IdentifierTransitGatewayManaged.
	}
	// Defense-in-depth: record current TGW in ownership history BEFORE
	// reconcileTGWState (which records again in Phase 0). If reconcileTGWState
	// crashes between this point and Phase 0, we still recorded once. The
	// idempotent Set on a sets-style state child makes the duplicate write a
	// no-op. See IdentifierPreviousTGWs godoc for the full rationale.
	c.recordTGWInHistory(log, tgwID)

	// Drop history entries whose underlying TGW is gone from AWS. Best-effort.
	// See #112.
	if tgwClient, gtErr := c.getTGWClient(ctx); gtErr == nil {
		c.pruneGhostTGWHistory(ctx, log, tgwClient)
	}

	// Reconcile TGW state: discovery-based cleanup of wrong-TGW attachments,
	// orphaned RTs, stale routes, and old managed TGWs. Also resets all state
	// keys when TGW ID changes. See tgw_reconcile.go.
	driftDetected, err := c.reconcileTGWState(ctx, log, tgwID)
	if err != nil {
		return err
	}
	c.tgwDriftDetected = driftDetected
	// Always persist TGW ID in state — needed for deletion even if config is removed.
	c.state.Set(IdentifierTransitGatewayID, tgwID)

	// Runtime CIDR overlap check: warn if this shoot's VPC CIDR overlaps with reserved CIDRs.
	// The admission webhook catches this at creation time, but config changes (globalVPCs,
	// seed conversion) can introduce overlaps after the fact.
	if c.networking != nil && c.networking.Nodes != nil && c.seedConfig != nil && c.seedConfig.TransitGateway != nil {
		shootCIDR := *c.networking.Nodes
		for _, gvpc := range c.seedConfig.TransitGateway.GlobalVPCs {
			for _, gcidr := range gvpc.CIDRs {
				if cidrsOverlap(shootCIDR, gcidr) {
					log.Info("WARNING: shoot VPC CIDR overlaps with globalVPC — routing conflicts expected",
						"shootCIDR", shootCIDR, "globalVPC", gvpc.Name, "globalVPCCIDR", gcidr)
					c.event(corev1.EventTypeWarning, "TGWCIDROverlap",
						"Shoot VPC CIDR %s overlaps with globalVPC %q (%s) — routing conflicts expected. Recreate shoot with a non-overlapping CIDR.",
						shootCIDR, gvpc.Name, gcidr)
				}
			}
		}
		if c.seedNodesCIDR != "" && cidrsOverlap(shootCIDR, c.seedNodesCIDR) {
			log.Info("WARNING: shoot VPC CIDR overlaps with seed nodes CIDR — routing conflicts expected",
				"shootCIDR", shootCIDR, "seedNodesCIDR", c.seedNodesCIDR)
			c.event(corev1.EventTypeWarning, "TGWCIDROverlap",
				"Shoot VPC CIDR %s overlaps with seed nodes CIDR %s — routing conflicts expected. Recreate shoot with a non-overlapping CIDR.",
				shootCIDR, c.seedNodesCIDR)
		}
	}

	// Warn if TGW has default propagation or association enabled — our code manages all
	// associations/propagations explicitly, so AWS defaults cause confusion.
	tgwInfo, err := tgwClient.GetTransitGateway(ctx, tgwID)
	if err != nil {
		log.Info("warning: could not check TGW default settings", "tgwId", tgwID, "error", err)
	} else if tgwInfo != nil {
		if strings.EqualFold(tgwInfo.DefaultRouteTablePropagation, "enable") {
			if c.isSharedIsolationMode() {
				log.Info("WARNING: TGW has DefaultRouteTablePropagation enabled — redundant in shared mode, our code handles propagation explicitly", "tgwId", tgwID)
			} else {
				log.Info("WARNING: TGW has DefaultRouteTablePropagation enabled — all attachments will auto-propagate to the default route table, breaking spoke isolation. Disable via ModifyTransitGateway or Terraform.", "tgwId", tgwID)
			}
		}
		if strings.EqualFold(tgwInfo.DefaultRouteTableAssociation, "enable") {
			log.Info("WARNING: TGW has DefaultRouteTableAssociation enabled — new attachments will auto-associate with the default route table instead of our managed tables.", "tgwId", tgwID)
		}
	}

	c.resolvedTGWID = tgwID

	// Fix #107: pre-emptive duplicate-RT cleanup. When the seed config flips
	// isolation modes (e.g. shared → hub-spoke), the seed shoot AND each child
	// shoot's reconcile may concurrently call ensureTransitGatewayRouteTable
	// for the new mode. Each does a tag-search → not-found (because AWS tag
	// indexing is eventually consistent) → creates a new RT. The post-creation
	// duplicate check at line ~2355 also misses the concurrent peer because
	// of the same tag-index lag. Result: 2+ duplicate RTs with the same
	// `<seedShootNS>-tgw-rt-<purpose>` Name tag.
	//
	// This pass lists ALL RTs on the TGW (tgw-id is a non-tag attribute, no
	// index lag) and dedupes groups with the same Name tag, keeping the
	// alphabetically lowest ID and disassociating + deleting the rest.
	// Runs once per reconcile, BEFORE any new RT creation, so any duplicates
	// from prior concurrent reconciles get reaped before new work begins.
	if c.isManagedTGWMode() {
		if err := c.cleanDuplicateManagedRouteTables(ctx, log, tgwClient, tgwID); err != nil {
			log.Info("duplicate-RT cleanup failed (continuing — will retry on next reconcile)",
				"error", err.Error())
		}
	}

	if c.isSharedIsolationMode() {
		// Shared mode: single route table for all VPCs.
		sharedRT, err := c.ensureTransitGatewayRouteTable(ctx, tgwID, tgwConfig.RouteTableID,
			IdentifierTransitGatewaySharedRouteTable, "shared")
		if err != nil {
			return err
		}
		c.resolvedSharedRouteTableID = sharedRT
		// In shared mode, also resolve hub/spoke RTs if provided (for cross-RT propagation).
		// Child shoots on the shared RT must propagate to hub+spoke so that the seed VPC
		// (which may be on spoke from the parent seed) can route return traffic.
		if tgwConfig.HubRouteTableID != nil {
			c.resolvedHubRouteTableID = *tgwConfig.HubRouteTableID
		}
		if tgwConfig.SpokeRouteTableID != nil {
			c.resolvedSpokeRouteTableID = *tgwConfig.SpokeRouteTableID
		}
		log.Info("shared isolation mode: using shared route table", "sharedRT", sharedRT,
			"hubRT", c.resolvedHubRouteTableID, "spokeRT", c.resolvedSpokeRouteTableID)
	} else {
		// Hub-spoke mode (default): two route tables.
		hubRT, err := c.ensureTransitGatewayRouteTable(ctx, tgwID, tgwConfig.HubRouteTableID,
			IdentifierTransitGatewayHubRouteTable, "hub")
		if err != nil {
			return err
		}
		spokeRT, err := c.ensureTransitGatewayRouteTable(ctx, tgwID, tgwConfig.SpokeRouteTableID,
			IdentifierTransitGatewaySpokeRouteTable, "spoke")
		if err != nil {
			return err
		}
		c.resolvedHubRouteTableID = hubRT
		c.resolvedSpokeRouteTableID = spokeRT
	}

	// Initialize effective globalVPCs from config.
	// Runtime VPC routes are handled automatically from seedNodesCIDR (no config needed).
	c.initEffectiveGlobalVPCs()
	log.Info("effective globalVPCs initialized", "count", len(c.resolvedEffectiveGlobalVPCs))

	// Discover CIDRs for globalVPCs that don't have them specified.
	// Must happen here (before zones) so mergeCustomRoutes can generate routes.
	if err := c.discoverGlobalVPCCIDRs(ctx, log); err != nil {
		return err
	}

	// Topology invariant: now that hub/spoke/shared RT IDs are resolved,
	// verify seed VPC, runtime VPC, and managed globalVPC attachments are
	// associated with the RT that matches the current isolation mode. If
	// drifted, the canonical-owner (seed shoot) reconcile moves them via
	// the safe pre-propagate → disassociate → associate sequence. Other
	// reconciles emit the event + metric only and rely on the seed shoot's
	// own reconcile to do the move. Runs AFTER RT resolution because the
	// helper needs c.resolvedHubRouteTableID / resolvedSharedRouteTableID
	// populated.
	if err := c.assertSeedSideAssociations(ctx, log, tgwID); err != nil {
		log.Info("warning: topology-invariant check returned an error — proceeding", "error", err)
	}

	return nil
}

// ensureTransitGatewayRouteTable ensures a TGW route table exists (referenced or auto-created).
// Always persists the resolved ID in state so deletion works even if config is removed.
func (c *FlowContext) ensureTransitGatewayRouteTable(ctx context.Context, tgwID string, configID *string, stateKey, purpose string) (string, error) {
	log := LogFromContext(ctx)

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get TGW client: %w", err)
	}

	managedKey := stateKey + "Managed"
	if configID != nil {
		// Referenced route table — verify it exists.
		existing, err := tgwClient.GetTransitGatewayRouteTable(ctx, *configID)
		if err != nil {
			return "", fmt.Errorf("failed to get referenced TGW %s route table %s: %w", purpose, *configID, err)
		}
		if existing == nil {
			return "", fmt.Errorf("referenced TGW %s route table %s not found", purpose, *configID)
		}
		log.Info("using referenced TGW route table", "purpose", purpose, "routeTableId", *configID, "state", existing.State)
		// Persist referenced ID in state — needed for deletion if config is removed later.
		c.state.Set(stateKey, *configID)
		c.state.Delete(managedKey) // Referenced — not managed.
		return *configID, nil
	}

	// Auto-create: check state first, verify it still exists and is on the correct TGW.
	if stateVal := c.state.Get(stateKey); stateVal != nil {
		existing, err := tgwClient.GetTransitGatewayRouteTable(ctx, *stateVal)
		if err != nil {
			return "", fmt.Errorf("failed to verify TGW %s route table %s from state: %w", purpose, *stateVal, err)
		}
		if existing != nil && existing.TransitGatewayId == tgwID {
			log.Info("found existing TGW route table in state", "purpose", purpose, "routeTableId", *stateVal)
			return *stateVal, nil
		}
		log.Info("TGW route table from state is stale (missing or wrong TGW), will rediscover",
			"purpose", purpose, "staleId", *stateVal)
		c.state.Delete(stateKey)
		c.state.Delete(managedKey)
	}

	// Find route tables by seed shoot tags on the TGW.
	seedShootNS := c.seedShootNamespace
	seedTags := awsclient.Tags{
		fmt.Sprintf(TagKeyClusterTemplate, seedShootNS): TagValueCluster,
		"Name": fmt.Sprintf("%s-tgw-rt-%s", seedShootNS, purpose),
	}
	found, err := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, seedTags)
	if err != nil {
		return "", fmt.Errorf("failed to find seed's TGW %s route table by tags: %w", purpose, err)
	}
	for _, rt := range found {
		if rt.TransitGatewayId == tgwID {
			log.Info("child shoot discovered seed's TGW route table by tags", "purpose", purpose, "routeTableId", rt.TransitGatewayRouteTableId)
			c.state.Set(stateKey, rt.TransitGatewayRouteTableId)
			return rt.TransitGatewayRouteTableId, nil
		}
	}
	// Not found by tags — in managed mode, the child shoot creates RTs
	// (seed shoot infra is reconciled by the parent seed, not this extension).
	if !c.isManagedTGWMode() {
		return "", fmt.Errorf("seed's TGW %s route table not found by tags — seed shoot %s must be reconciled first", purpose, seedShootNS)
	}
	log.Info("TGW route table not found — creating (managed mode, first child shoot)", "purpose", purpose)

	// Create new route table. Use seed shoot tags so other child shoots can discover it.
	// But first, do a final check for concurrent creation — another shoot may have created
	// the RT between our tag discovery and now.
	var tags awsclient.Tags
	if c.isManagedTGWMode() {
		seedShootNS := c.seedShootNamespace
		tags = awsclient.Tags{
			fmt.Sprintf(TagKeyClusterTemplate, seedShootNS): TagValueCluster,
			"Name": fmt.Sprintf("%s-tgw-rt-%s", seedShootNS, purpose),
		}
		// Re-check by tags right before creation to handle concurrent reconciles.
		recheck, _ := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, tags)
		for _, rt := range recheck {
			if rt.TransitGatewayId == tgwID {
				log.Info("RT found on recheck (concurrent creation)", "purpose", purpose, "routeTableId", rt.TransitGatewayRouteTableId)
				c.state.Set(stateKey, rt.TransitGatewayRouteTableId)
				return rt.TransitGatewayRouteTableId, nil
			}
		}
	} else {
		tags = c.commonTagsWithSuffix(fmt.Sprintf("tgw-rt-%s", purpose))
	}
	log.Info("creating TGW route table", "purpose", purpose)
	created, err := tgwClient.CreateTransitGatewayRouteTable(ctx, tgwID, tags)
	if err != nil {
		return "", fmt.Errorf("failed to create TGW %s route table: %w", purpose, err)
	}

	// Post-creation duplicate check: if another shoot concurrently created the same RT,
	// delete ours and use the earlier one (lowest ID wins).
	if c.isManagedTGWMode() {
		postCheck, _ := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, tags)
		var candidates []string
		for _, rt := range postCheck {
			if rt.TransitGatewayId == tgwID {
				candidates = append(candidates, rt.TransitGatewayRouteTableId)
			}
		}
		if len(candidates) > 1 {
			// Multiple RTs — keep the first (alphabetically), delete the rest.
			sort.Strings(candidates)
			winner := candidates[0]
			for _, dup := range candidates[1:] {
				log.Info("deleting duplicate RT (concurrent creation)", "keeping", winner, "deleting", dup)
				_ = tgwClient.DeleteTransitGatewayRouteTable(ctx, dup)
			}
			c.state.Set(stateKey, winner)
			c.state.Set(managedKey, "true")
			log.Info("created TGW route table (resolved duplicate)", "purpose", purpose, "routeTableId", winner)
			return winner, nil
		}
	}

	c.state.Set(stateKey, created.TransitGatewayRouteTableId)
	c.state.Set(managedKey, "true") // Mark as managed — will be deleted on disable.
	log.Info("created TGW route table", "purpose", purpose, "routeTableId", created.TransitGatewayRouteTableId)
	return created.TransitGatewayRouteTableId, nil
}

// cleanDuplicateManagedRouteTables reaps duplicate managed TGW route tables
// that share the same Name tag. The producer/dedup at ensureTransitGateway
// RouteTable can race when seed shoot + child shoots concurrently call
// CreateTransitGatewayRouteTable: AWS tag indexing is eventually consistent,
// so the post-creation tag-search misses concurrent siblings.
//
// This helper bypasses the tag index by listing ALL RTs on the TGW
// (transit-gateway-id is a non-tag attribute, no index lag) and grouping by
// Name tag value. For each group with > 1 RT, keep the alphabetically lowest
// ID (matches the existing tie-break in ensureTransitGatewayRouteTable) and
// disassociate + delete the rest.
//
// Best-effort: errors are logged and swallowed. Connectivity isn't impacted
// by leftover duplicates (just costs an extra RT and may confuse the
// healthcheck's canonical-RT lookup) — the next reconcile retries.
func (c *FlowContext) cleanDuplicateManagedRouteTables(
	ctx context.Context, log logr.Logger, tgwClient awsclient.Interface, tgwID string,
) error {
	if tgwID == "" {
		return nil
	}
	allRTs, err := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, nil)
	if err != nil {
		return fmt.Errorf("list TGW RTs for dedup: %w", err)
	}
	byName := map[string][]*awsclient.TransitGatewayRouteTableInfo{}
	for _, rt := range allRTs {
		if rt.TransitGatewayId != tgwID {
			continue
		}
		name := rt.Tags["Name"]
		if name == "" {
			// Untagged RTs (e.g., AWS-default RT) — skip dedup for safety.
			continue
		}
		byName[name] = append(byName[name], rt)
	}
	if len(byName) == 0 {
		return nil
	}
	// To dedup we may need to disassociate attachments. Build a map of all
	// VPC attachments on this TGW and the RT each is associated with, then
	// check duplicates against that map. Avoids per-RT association listing
	// (no client method for it) and avoids per-attachment lookups.
	attsOnTGW, err := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgwID)
	if err != nil {
		return fmt.Errorf("list VPC attachments on TGW for dedup: %w", err)
	}
	attachmentRT := map[string]string{}
	for _, att := range attsOnTGW {
		if isAttachmentTerminal(att.State) {
			continue
		}
		assocRT, err := tgwClient.GetTransitGatewayAttachmentAssociation(ctx, att.TransitGatewayAttachmentId)
		if err != nil {
			// Single attachment lookup failure: skip; if it was associated with a
			// duplicate we'd-be-deleting, the disassociate-before-delete on the
			// duplicate's attempt will surface the error.
			log.Info("failed to read attachment association for dedup — skipping attachment",
				"attachmentId", att.TransitGatewayAttachmentId, "error", err.Error())
			continue
		}
		if assocRT != "" {
			attachmentRT[att.TransitGatewayAttachmentId] = assocRT
		}
	}
	for name, group := range byName {
		if len(group) < 2 {
			continue
		}
		ids := make([]string, 0, len(group))
		for _, rt := range group {
			ids = append(ids, rt.TransitGatewayRouteTableId)
		}
		sort.Strings(ids)
		winner := ids[0]
		log.Info("found duplicate TGW route tables — deduping",
			"nameTag", name, "winner", winner, "duplicates", ids[1:])
		for _, dup := range ids[1:] {
			// Disassociate any attachments associated with the duplicate before deletion.
			associationDrained := true
			for attID, rt := range attachmentRT {
				if rt != dup {
					continue
				}
				if err := tgwClient.DisassociateTransitGatewayRouteTable(ctx, dup, attID); err != nil {
					log.Info("disassociate from duplicate RT failed — skipping deletion (will retry next reconcile)",
						"duplicateId", dup, "attachmentId", attID, "error", err.Error())
					associationDrained = false
				}
			}
			if !associationDrained {
				continue
			}
			if err := tgwClient.DeleteTransitGatewayRouteTable(ctx, dup); err != nil {
				log.Info("delete duplicate RT failed — will retry next reconcile",
					"duplicateId", dup, "error", err.Error())
			}
		}
	}
	return nil
}

// ensureTransitGatewayAttachment creates or finds the TGW VPC attachment for this shoot,
// then configures route table association (spoke) and propagation (hub).
// Prerequisite: ensureTransitGateway must have run first (separate DAG task) to populate
// resolvedTGWID, resolvedHubRouteTableID, and resolvedSpokeRouteTableID.
func (c *FlowContext) ensureTransitGatewayAttachment(ctx context.Context) error {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil {
		return fmt.Errorf("internal error: ensureTransitGatewayAttachment called without seed TGW config")
	}
	log := LogFromContext(ctx)

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	tgwID := c.resolvedTGWID
	hubRT := c.resolvedHubRouteTableID
	spokeRT := c.resolvedSpokeRouteTableID

	// Debug: log shoot attachment context
	log.Info("ensureTransitGatewayAttachment: context",
		"shoot", c.namespace,
		"seedName", c.seedName,
		"isolationMode", func() string {
			if c.isSharedIsolationMode() {
				return "shared"
			}
			return "hub-spoke"
		}(),
		"tgwID", tgwID,
		"hubRT", hubRT,
		"spokeRT", spokeRT,
		"sharedRT", c.resolvedSharedRouteTableID,
	)

	if tgwID == "" {
		log.Info("TGW ID not resolved — skipping shoot TGW attachment (managed TGW may be missing)")
		return nil
	}

	vpcID := c.state.Get(IdentifierVPC)
	if vpcID == nil {
		return fmt.Errorf("VPC not yet available for TGW attachment")
	}

	// Collect worker subnet IDs from all zones for the attachment.
	var subnetIDs []string
	zones := c.state.GetChild(ChildIdZones)
	for _, zoneKey := range zones.GetChildrenKeys() {
		zoneChild := zones.GetChild(zoneKey)
		if id := zoneChild.Get(IdentifierZoneSubnetWorkers); id != nil {
			subnetIDs = append(subnetIDs, *id)
		}
	}
	if len(subnetIDs) == 0 {
		return fmt.Errorf("no worker subnets found for TGW attachment")
	}

	tags := c.commonTagsWithSuffix("tgw-attachment")

	// Find or create the attachment with in-place self-heal: if the attachment from state
	// is stale (missing, terminal, wrong TGW), clear state and retry once in the same pass.
	// This avoids the error → gardenlet backoff → retry cycle that disrupts apiserver watches.
	var createdAttachmentID string
	for attempt := 0; attempt < 2; attempt++ {
		attachmentID := c.state.Get(IdentifierTransitGatewayAttachment)

		current, err := FindExisting(ctx, attachmentID, tags,
			tgwClient.GetTransitGatewayVPCAttachment,
			tgwClient.FindTransitGatewayVPCAttachmentsByTags,
			func(item *awsclient.TransitGatewayVPCAttachment) bool {
				return item.VpcId == *vpcID && item.TransitGatewayId == tgwID &&
					!isAttachmentTerminal(item.State)
			})
		if err != nil {
			return err
		}

		if current != nil {
			log.Info("transit gateway VPC attachment already exists", "attachmentId", current.TransitGatewayAttachmentId)
			c.state.Set(IdentifierTransitGatewayAttachment, current.TransitGatewayAttachmentId)
		} else {
			log.Info("creating transit gateway VPC attachment", "tgwId", tgwID, "vpcId", *vpcID)
			c.event(corev1.EventTypeNormal, "TGWAttachmentCreating", "Creating VPC attachment to Transit Gateway %s", tgwID)
			created, err := c.client.CreateTransitGatewayVPCAttachment(ctx, &awsclient.TransitGatewayVPCAttachment{
				TransitGatewayId: tgwID,
				VpcId:            *vpcID,
				SubnetIds:        subnetIDs,
				Tags:             tags,
			})
			if err != nil {
				code := awsclient.GetAWSAPIErrorCode(err)
				if code != "DuplicateTransitGatewayAttachment" {
					return fmt.Errorf("failed to create TGW VPC attachment: %w", err)
				}
				log.Info("TGW VPC attachment already exists (duplicate), looking up by VPC ID")
				allAtts, listErr := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgwID)
				if listErr != nil {
					return fmt.Errorf("failed to list TGW attachments after duplicate: %w", listErr)
				}
				for _, att := range allAtts {
					if att.VpcId == *vpcID {
						c.state.Set(IdentifierTransitGatewayAttachment, att.TransitGatewayAttachmentId)
						log.Info("found existing VPC attachment", "attachmentId", att.TransitGatewayAttachmentId)
						break
					}
				}
				if c.state.Get(IdentifierTransitGatewayAttachment) == nil {
					return fmt.Errorf("DuplicateTransitGatewayAttachment but could not find attachment for VPC %s", *vpcID)
				}
			} else {
				log.Info("created transit gateway VPC attachment", "attachmentId", created.TransitGatewayAttachmentId)
				c.event(corev1.EventTypeNormal, "TGWAttachmentCreated", "VPC attachment %s created on Transit Gateway %s", created.TransitGatewayAttachmentId, tgwID)
				c.state.Set(IdentifierTransitGatewayAttachment, created.TransitGatewayAttachmentId)
				if err := tgwClient.WaitForTransitGatewayVPCAttachmentAvailable(ctx, created.TransitGatewayAttachmentId); err != nil {
					return fmt.Errorf("failed waiting for TGW VPC attachment to become available: %w", err)
				}
			}
		}

		v := c.state.Get(IdentifierTransitGatewayAttachment)
		if v == nil {
			return fmt.Errorf("internal error: TGW attachment ID not in state after create/find")
		}
		createdAttachmentID = *v

		// Verify the attachment still exists, is usable, and is on the correct TGW.
		verifyAtt, verifyErr := tgwClient.GetTransitGatewayVPCAttachment(ctx, createdAttachmentID)
		if verifyErr != nil || verifyAtt == nil || isAttachmentTerminal(verifyAtt.State) || verifyAtt.TransitGatewayId != tgwID {
			if attempt == 0 {
				log.Info("shoot VPC TGW attachment is stale — clearing state and retrying in-place",
					"attachmentId", createdAttachmentID, "attempt", attempt+1)
				c.clearStaleAttachmentState(log, IdentifierTransitGatewayAttachment, createdAttachmentID)
				continue // retry once
			}
			c.clearStaleAttachmentState(log, IdentifierTransitGatewayAttachment, createdAttachmentID)
			return fmt.Errorf("shoot VPC TGW attachment %s is stale after retry — cleared state", createdAttachmentID)
		}
		break // verified OK
	}

	// Determine the target RT for this attachment based on isolation mode.
	currentAssocRT, _ := tgwClient.GetTransitGatewayAttachmentAssociation(ctx, createdAttachmentID)
	targetRT := c.resolvedSpokeRouteTableID
	if c.isSharedIsolationMode() {
		targetRT = c.resolvedSharedRouteTableID
	} else if c.isManagedSeedShoot {
		// ManagedSeed shoots: use hub RT (not spoke). The seed VPC is the hub — it must
		// see all child shoot VPCs via propagation. On spoke, it would only see hub-propagated
		// routes (runtime, mgmt) and miss child shoot CIDRs.
		targetRT = c.resolvedHubRouteTableID
	}

	// Handle RT association: two-phase isolation mode switch.
	//
	// CRITICAL: Never disassociate a live attachment from its current RT in a single
	// reconcile pass. The window between disassociate and re-associate has ZERO TGW
	// routing, which breaks VPN, kills the gardenlet, and triggers DWD cascades.
	//
	// Two-phase approach:
	//   Phase 1 (this reconcile): target RT differs from current RT.
	//     - Keep current association for connectivity.
	//     - Add propagation to target RT (so routes appear there).
	//     - Store target RT ID in state as IdentifierTGWIsolationSwitchTargetRT.
	//     - Signal drift → triggers requeue after 30s.
	//
	//   Phase 2 (next reconcile): state has IdentifierTGWIsolationSwitchTargetRT.
	//     - Verify target RT has active propagated routes (≥1).
	//     - Disassociate from old RT.
	//     - Wait for disassociation.
	//     - Associate with target RT.
	//     - Clear the state key.
	//
	//   If Phase 2 fails (target RT empty, disassociate error), the attachment
	//   stays on its current RT — safe. The state key persists and Phase 2
	//   retries on the next reconcile.
	pendingSwitch := c.state.Get(IdentifierTGWIsolationSwitchTargetRT)

	if currentAssocRT == "" && targetRT != "" {
		// No current association — associate directly (fresh attachment or recovery from null).
		log.Info("attachment has no RT association — associating with target RT",
			"attachmentId", createdAttachmentID, "targetRT", targetRT)
		// Clear any pending switch — direct association handles it.
		c.state.Delete(IdentifierTGWIsolationSwitchTargetRT)
	} else if pendingSwitch != nil && *pendingSwitch == targetRT && currentAssocRT != targetRT {
		// Phase 2: pending switch to target RT. Verify target RT has routes, then switch.
		// Cap retries to avoid infinite requeue if Phase 2 keeps failing.
		attempts := getIsolationSwitchAttempts(c, IdentifierTGWIsolationSwitchAttempts)
		if attempts >= maxIsolationSwitchAttempts {
			log.Info("Phase 2: max attempts reached — clearing pending switch and giving up",
				"attachmentId", createdAttachmentID, "attempts", attempts, "max", maxIsolationSwitchAttempts)
			c.event(corev1.EventTypeWarning, "TGWIsolationSwitchFailed",
				"Phase 2 gave up after %d attempts for attachment %s — attachment remains on RT %s, target was %s",
				attempts, createdAttachmentID, currentAssocRT, targetRT)
			c.state.Delete(IdentifierTGWIsolationSwitchTargetRT)
			c.state.Delete(IdentifierTGWIsolationSwitchAttempts)
			return nil
		}
		incrementIsolationSwitchAttempts(c, IdentifierTGWIsolationSwitchAttempts)
		log.Info("Phase 2: completing isolation mode switch",
			"attachmentId", createdAttachmentID, "currentRT", currentAssocRT, "targetRT", targetRT,
			"attempt", attempts+1, "max", maxIsolationSwitchAttempts)
		// Verify target RT exists and is available before switching.
		// Propagation was enabled in Phase 1, and the 30s requeue delay gives AWS
		// time to populate routes. We verify the RT itself exists (not individual routes)
		// because route propagation is near-instant after the RT is available.
		targetRTInfo, rtErr := tgwClient.GetTransitGatewayRouteTable(ctx, targetRT)
		if rtErr != nil || targetRTInfo == nil {
			log.Info("Phase 2: target RT not found or error — deferring switch",
				"targetRT", targetRT, "error", rtErr)
			c.tgwDriftDetected = true // requeue to retry
		} else if targetRTInfo.State != "available" {
			log.Info("Phase 2: target RT not yet available — deferring switch",
				"targetRT", targetRT, "state", targetRTInfo.State)
			c.tgwDriftDetected = true
		} else {
			// Target RT exists and is available — safe to switch.
			// Re-add propagation idempotently. If the call returns Duplicate, propagation
			// was already enabled in Phase 1 and routes have had at least 30s to populate.
			// If it succeeds (not Duplicate), propagation was missing — wait briefly for
			// AWS to populate routes before switching.
			propErr := tgwClient.EnableTransitGatewayRouteTablePropagation(ctx, targetRT, createdAttachmentID)
			if propErr != nil {
				code := awsclient.GetAWSAPIErrorCode(propErr)
				if code != "TransitGatewayRouteTablePropagation.Duplicate" {
					log.Info("Phase 2: failed to confirm propagation — deferring switch",
						"targetRT", targetRT, "error", propErr)
					c.tgwDriftDetected = true
					return nil
				}
				log.Info("Phase 2: propagation to target RT confirmed (was set in Phase 1)")
			} else {
				log.Info("Phase 2: propagation was missing — re-enabled, waiting 15s for routes")
				select {
				case <-ctx.Done():
					return fmt.Errorf("context cancelled waiting for Phase 2 route propagation: %w", ctx.Err())
				case <-time.After(15 * time.Second):
				}
			}
			log.Info("Phase 2: target RT verified available, performing RT switch",
				"targetRT", targetRT)
			c.event(corev1.EventTypeNormal, "TGWIsolationSwitch",
				"Phase 2: switching attachment %s from RT %s to RT %s",
				createdAttachmentID, currentAssocRT, targetRT)

			// Disassociate from current RT.
			if err := tgwClient.DisassociateTransitGatewayRouteTable(ctx, currentAssocRT, createdAttachmentID); err != nil {
				if code := awsclient.GetAWSAPIErrorCode(err); code != "InvalidAssociation.NotFound" {
					log.Info("Phase 2: disassociation failed — deferring switch", "error", err)
					c.tgwDriftDetected = true
				}
			} else {
				// Wait for disassociation.
				for i := 0; i < 30; i++ {
					stillAssocRT, _ := tgwClient.GetTransitGatewayAttachmentAssociation(ctx, createdAttachmentID)
					if stillAssocRT == "" || stillAssocRT == targetRT {
						break
					}
					select {
					case <-ctx.Done():
						return fmt.Errorf("context cancelled waiting for Phase 2 disassociation: %w", ctx.Err())
					case <-time.After(2 * time.Second):
					}
				}
				// Eagerly associate with target RT and verify before clearing state.
				// The fall-through association blocks below also handle this, but if their
				// associate silently swallows AlreadyAssociated for the wrong RT, we'd
				// clear state and leave the attachment unassociated.
				associateErr := tgwClient.AssociateTransitGatewayRouteTable(ctx, targetRT, createdAttachmentID)
				associateBlocked := false
				if associateErr != nil {
					if code := awsclient.GetAWSAPIErrorCode(associateErr); code != "Resource.AlreadyAssociated" {
						log.Info("Phase 2: re-association failed — keeping pending switch for retry",
							"targetRT", targetRT, "error", associateErr)
						c.tgwDriftDetected = true
						associateBlocked = true
					}
					// AlreadyAssociated — fall through to verify polling
				}
				if !associateBlocked {
					// Poll the association status — AWS eventual consistency: AssociateRT
					// returns success even when the association hasn't yet propagated to the
					// describe API. Polling with retries replaces a previous single-shot
					// check that misread "" as a failed associate, leaving attachments
					// unassociated forever because the verify always saw actualRT="" right
					// after Associate.
					var checkRT string
					for poll := 0; poll < 15; poll++ {
						checkRT, _ = tgwClient.GetTransitGatewayAttachmentAssociation(ctx, createdAttachmentID)
						if checkRT == targetRT {
							break
						}
						select {
						case <-ctx.Done():
							return fmt.Errorf("context cancelled waiting for Phase 2 association to materialize: %w", ctx.Err())
						case <-time.After(2 * time.Second):
						}
					}
					if checkRT == targetRT {
						c.state.Delete(IdentifierTGWIsolationSwitchTargetRT)
						c.state.Delete(IdentifierTGWIsolationSwitchAttempts)
						c.disableOldRTPropagationIfUnneeded(ctx, log, tgwClient, currentAssocRT, createdAttachmentID, c.shootAttachmentRole())
						c.recordSwitchTimestamp(IdentifierTGWLastSwitchedAt)
						log.Info("Phase 2: switch complete", "targetRT", targetRT)
					} else {
						log.Info("Phase 2: association did not materialize after 30s polling — keeping pending switch for retry",
							"actualRT", checkRT, "targetRT", targetRT)
						c.tgwDriftDetected = true
					}
				}
			}
		}
	} else if currentAssocRT != "" && targetRT != "" && currentAssocRT != targetRT {
		// Cross-extension fight detection: if we just completed a Phase 2 switch on
		// this attachment within pingPongCooldownPeriod, another writer (e.g. another
		// extension instance reconciling the same attachment in a different mode)
		// has reverted us. Defer instead of fighting back.
		if c.shouldDeferPingPongSwitch(log, IdentifierTGWLastSwitchedAt, IdentifierTGWPingPongDefers, createdAttachmentID, currentAssocRT, targetRT) {
			// Helper has either set drift to requeue or emitted Warning event + abandoned.
		} else {
		// Phase 1: mismatch detected, start two-phase switch.
		log.Info("Phase 1: isolation mode switch detected — preparing target RT",
			"attachmentId", createdAttachmentID, "currentRT", currentAssocRT, "targetRT", targetRT)
		c.event(corev1.EventTypeNormal, "TGWIsolationSwitch",
			"Phase 1: preparing isolation switch for attachment %s: current RT %s → target RT %s",
			createdAttachmentID, currentAssocRT, targetRT)

		// Add propagation to target RT so routes appear there before we switch.
		log.Info("Phase 1: adding propagation to target RT", "targetRT", targetRT)
		if err := c.enableTGWPropagation(ctx, log, tgwClient, targetRT, createdAttachmentID, "Phase 1 target"); err != nil {
			return err
		}

		// Store pending switch and signal requeue.
		c.state.Set(IdentifierTGWIsolationSwitchTargetRT, targetRT)
		c.tgwDriftDetected = true // triggers 30s requeue via actuator
		log.Info("Phase 1: propagation added, requeue scheduled for Phase 2",
			"targetRT", targetRT)
		}
	} else if pendingSwitch != nil && currentAssocRT == targetRT {
		// Switch completed (possibly by another reconcile or manual fix). Clean up state.
		log.Info("isolation switch already completed — clearing pending state",
			"attachmentId", createdAttachmentID, "currentRT", currentAssocRT)
		c.state.Delete(IdentifierTGWIsolationSwitchTargetRT)
	}

	if c.isSharedIsolationMode() {
		// Shared mode: associate with shared RT, propagate to shared + hub.
		// Propagation to hub is needed so the seed VPC (on hub or spoke) can route
		// return traffic to this shoot. Hub propagation ensures the route appears
		// in spoke RT too (spoke inherits hub propagations).
		sharedRT := c.resolvedSharedRouteTableID
		if err := c.associateTGWRouteTable(ctx, log, tgwClient, sharedRT, createdAttachmentID, "shoot (shared mode)"); err != nil {
			return err
		}
		if err := c.enableTGWPropagation(ctx, log, tgwClient, sharedRT, createdAttachmentID, "shared (shoot)"); err != nil {
			return err
		}
		// Also propagate to hub + spoke RTs so the seed VPC (which may be on
		// spoke from the parent seed's hub-spoke config) can route return traffic.
		if err := c.enableTGWPropagation(ctx, log, tgwClient, hubRT, createdAttachmentID, "hub (shared mode cross-RT)"); err != nil {
			return err
		}
		if err := c.enableTGWPropagation(ctx, log, tgwClient, spokeRT, createdAttachmentID, "spoke (shared mode cross-RT)"); err != nil {
			return err
		}
	} else {
		// Hub-spoke mode.
		//
		// Association uses the targetRT computed at line 2207-2215, which already
		// accounts for c.isManagedSeedShoot (managed seed shoots associate with hub,
		// regular shoots with spoke). Hardcoding spokeRT here would always pull a
		// managed seed shoot's attachment back to spoke after the two-phase switch
		// moved it to hub, causing endless ping-pong.
		//
		// AWS eventual consistency means even an erroneous AssociateRT call against
		// a different RT can override a recent successful association before the
		// AlreadyAssociated check triggers — so the call MUST target the correct RT.
		if err := c.associateTGWRouteTable(ctx, log, tgwClient, targetRT, createdAttachmentID, "shoot (hub-spoke target)"); err != nil {
			return err
		}
		if err := c.enableTGWPropagation(ctx, log, tgwClient, hubRT, createdAttachmentID, "hub (shoot hub-spoke)"); err != nil {
			return err
		}
		// Spoke propagation:
		//   Managed seed shoots: ENABLE (child shoots on spoke need routes to the seed VPC).
		//   Regular child shoots: DISABLE (propagation to spoke would break shoot isolation).
		if spokeRT != "" {
			if c.isManagedSeedShoot {
				if err := c.enableTGWPropagation(ctx, log, tgwClient, spokeRT, createdAttachmentID, "spoke (ManagedSeed)"); err != nil {
					return err
				}
			} else {
				if err := c.disableTGWPropagation(ctx, log, tgwClient, spokeRT, createdAttachmentID, "spoke (child shoot isolation)"); err != nil {
					return err
				}
			}
		}
	}

	// Ensure globalVPC associations and propagations.
	if err := c.ensureGlobalVPCAssociations(ctx, log); err != nil {
		return err
	}

	return nil
}

// ensureTGWRoutesInZones adds TGW routes (seed VPC CIDR, globalVPC CIDRs, and
// in shared mode peer shoot CIDRs) to every zone's private route table, and
// removes any stale TGW routes that should no longer exist for the current mode.
//
// Runs AFTER ensureTransitGatewayAttachment so the VPC attachment exists and
// CreateRoute won't fail with InvalidTransitGatewayID.NotFound.
//
// Cleanup pass: routes that target our managed TGW but whose CIDR is not in
// the desired set get deleted. This catches peer shoot routes added in shared
// mode that should be removed when transitioning back to hub-spoke (otherwise
// pods send traffic into the TGW for a CIDR the spoke RT can't route, dropping
// the packet — the symptom that surfaced after S0/S1 mode flips).
func (c *FlowContext) ensureTGWRoutesInZones(ctx context.Context) error {
	log := LogFromContext(ctx)
	tgwRoutes := c.buildTGWRoutes()

	// Build the set of CIDRs we expect to see pointing at our TGW. Anything
	// pointing at our TGW with a CIDR NOT in this set is stale and must go.
	desiredCIDRs := sets.New[string]()
	for _, r := range tgwRoutes {
		if r.DestinationCidrBlock != nil {
			desiredCIDRs.Insert(*r.DestinationCidrBlock)
		}
	}
	// User-defined custom routes targeting our TGW also belong to the desired set.
	if c.config != nil && c.config.Networks.CustomRoutes != nil {
		for i := range c.config.Networks.CustomRoutes {
			cr := &c.config.Networks.CustomRoutes[i]
			if cr.TransitGatewayId != nil && cr.DestinationCidrBlock != nil {
				desiredCIDRs.Insert(*cr.DestinationCidrBlock)
			}
		}
	}

	tgwID := c.resolvedTGWID

	zones := c.state.GetChild(ChildIdZones)
	for _, zoneKey := range zones.GetChildrenKeys() {
		zoneChild := zones.GetChild(zoneKey)
		rtID := zoneChild.Get(IdentifierZoneRouteTable)
		if rtID == nil {
			continue
		}
		current, err := c.client.GetRouteTable(ctx, *rtID)
		if err != nil {
			return fmt.Errorf("failed to get zone route table %s: %w", *rtID, err)
		}
		if current == nil {
			continue
		}

		// Add / replace routes that should exist.
		for _, route := range tgwRoutes {
			if route.DestinationCidrBlock == nil || route.TransitGatewayId == nil {
				continue
			}
			exists := false
			stale := false
			for _, r := range current.Routes {
				if r.DestinationCidrBlock != nil && *r.DestinationCidrBlock == *route.DestinationCidrBlock {
					if r.TransitGatewayId != nil && *r.TransitGatewayId == *route.TransitGatewayId {
						exists = true
					} else {
						// Route exists but points to wrong TGW (or is blackhole) — must replace.
						stale = true
					}
					break
				}
			}
			if exists {
				continue
			}
			if stale {
				// Atomically retarget the existing route (e.g. TGW switch) using
				// ReplaceRoute. Delete+Create would have a brief routing gap during
				// which the destination CIDR is unreachable — long enough to break
				// gardenlet → garden API connectivity during a TGW change. ReplaceRoute
				// is a single AWS API call with no observable gap.
				log.Info("replacing stale TGW route in zone route table",
					"routeTableId", *rtID, "cidr", *route.DestinationCidrBlock, "newTgwId", *route.TransitGatewayId)
				if err := c.client.ReplaceRoute(ctx, *rtID, route); err != nil {
					return fmt.Errorf("failed to replace stale TGW route %s in zone RT %s: %w", *route.DestinationCidrBlock, *rtID, err)
				}
				continue
			}
			log.Info("adding TGW route to zone route table", "routeTableId", *rtID, "cidr", *route.DestinationCidrBlock, "tgwId", *route.TransitGatewayId)
			if err := c.client.CreateRoute(ctx, *rtID, route); err != nil {
				if code := awsclient.GetAWSAPIErrorCode(err); code != "RouteAlreadyExists" {
					return fmt.Errorf("failed to add TGW route %s to zone RT %s: %w", *route.DestinationCidrBlock, *rtID, err)
				}
			}
		}

		// Remove stale routes that target OUR TGW with a CIDR no longer desired.
		// Only act on routes whose TGW matches our resolved TGW — never touch
		// routes pointing at unrelated TGWs (that's outside our concern).
		//
		// SKIP on the managed seed shoot: its zone RTs ARE the seed VPC RTs,
		// which contain child shoot return routes (e.g. 10.X.Y.0/20 → TGW) added
		// by each child shoot's ensureSeedVPCRoute. Those CIDRs are NOT in the
		// seed shoot's buildTGWRoutes (correctly — the seed doesn't initiate
		// connections to child shoot CIDRs), but they ARE legitimate routes
		// owned by child shoot reconciles. Without this guard, every seed shoot
		// reconcile deletes them, breaking apiserver→worker return path → DWD
		// cascade. Genuine staleness in the seed VPC is cleaned up by each
		// child shoot's deletion handler (cleanupSeedVPCRoutes in MigrateTGW /
		// reconcileTGWDeleteState).
		if tgwID != "" && !c.isManagedSeedShoot {
			for _, r := range current.Routes {
				if r.TransitGatewayId == nil || *r.TransitGatewayId != tgwID || r.DestinationCidrBlock == nil {
					continue
				}
				if desiredCIDRs.Has(*r.DestinationCidrBlock) {
					continue
				}
				log.Info("deleting stale auto-managed TGW route in zone route table (CIDR no longer in desired set for current mode)",
					"routeTableId", *rtID, "cidr", *r.DestinationCidrBlock, "tgwId", tgwID)
				c.event(corev1.EventTypeNormal, "TGWRouteCleanup",
					"Removed stale TGW route %s from zone RT %s (no longer needed in current isolation mode)",
					*r.DestinationCidrBlock, *rtID)
				if err := c.client.DeleteRoute(ctx, *rtID, &awsclient.Route{
					DestinationCidrBlock: r.DestinationCidrBlock,
				}); err != nil {
					log.Info("warning: failed to delete stale TGW route — will retry next reconcile",
						"routeTableId", *rtID, "cidr", *r.DestinationCidrBlock, "error", err)
				}
			}
		}
	}
	return nil
}

// ensureSeedVPCAttachment ensures the seed's own VPC is attached to the TGW.
// This is required for internal NLBs: shoot workers in spoke VPCs need to reach
// the seed VPC where shoot API server NLBs live.
//
// Auto-discovery: the seed VPC is discovered from the Seed's node CIDR
// (Seed.spec.networks.nodes). Worker subnets are found by Gardener tags on the VPC.
// No explicit VPC ID or subnet IDs are needed in the config.
//
// The seed VPC attachment is a shared, seed-level resource:
//   - Created during the first shoot reconciliation on this seed
//   - NOT deleted when individual shoots are deleted
//   - Only cleaned up when TGW is disabled on the seed (cleanupDisabledTransitGateway)
//
// Route table configuration:
//   - Associate with hub route table (seed is the hub — sees all VPCs)
//   - Propagate to both hub AND spoke route tables (all shoots can reach seed)
func (c *FlowContext) ensureSeedVPCAttachment(ctx context.Context) error {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil {
		return fmt.Errorf("internal error: ensureSeedVPCAttachment called without seed TGW config")
	}
	if c.seedNodesCIDR == "" {
		return fmt.Errorf("internal error: ensureSeedVPCAttachment called without seed nodes CIDR")
	}
	log := LogFromContext(ctx)

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	tgwID := c.resolvedTGWID
	hubRT := c.resolvedHubRouteTableID
	spokeRT := c.resolvedSpokeRouteTableID

	// Debug: log the full TGW context for this reconcile
	globalVPCNames := make([]string, 0)
	if c.seedConfig.TransitGateway != nil {
		for _, gvpc := range c.resolvedEffectiveGlobalVPCs {
			globalVPCNames = append(globalVPCNames, fmt.Sprintf("%s(%s)", gvpc.Name, strings.Join(gvpc.CIDRs, ",")))
		}
	}
	log.Info("ensureSeedVPCAttachment: TGW context",
		"shoot", c.namespace,
		"seedName", c.seedName,
		"seedNodesCIDR", c.seedNodesCIDR,
		"isolationMode", func() string {
			if c.isSharedIsolationMode() {
				return "shared"
			}
			return "hub-spoke"
		}(),
		"tgwID", tgwID,
		"hubRT", hubRT,
		"spokeRT", spokeRT,
		"sharedRT", c.resolvedSharedRouteTableID,
		"globalVPCs", globalVPCNames,
	)

	if tgwID == "" {
		log.Info("TGW ID not resolved — skipping seed VPC attachment (managed TGW may be missing)")
		return nil
	}

	// Step 1: Discover the seed VPC from its node CIDR.
	seedVpcID, seedSubnetIDs, err := c.discoverSeedVPC(ctx, log)
	if err != nil {
		return err
	}

	// Step 2: Create or find the TGW VPC attachment for the seed VPC.
	// The seed VPC attachment is a shared resource — it may have been created by the seed
	// shoot or by another child shoot, with different tags. Always search by VPC+TGW first.
	// Self-heals in-place: if state has a stale attachment, clears and retries once.
	// Tags use the seed shoot's namespace (canonical owner) so the attachment is
	// attributable to the seed regardless of which child shoot writes them.
	tags := c.seedCanonicalTags("seed-vpc-tgw-attachment")
	var seedAttachmentID string
	// attachmentJustCreated is true only when THIS reconcile created the seed VPC
	// attachment (not when we found a pre-existing one). Used by the RT association
	// phase below to distinguish "bootstrap a new attachment" from "the canonical
	// owner is already managing this one — don't fight."
	var attachmentJustCreated bool
	for attempt := 0; attempt < 2; attempt++ {
		attachmentJustCreated = false
		attachmentID := c.state.Get(IdentifierSeedVPCTransitGatewayAttachment)
		var current *awsclient.TransitGatewayVPCAttachment

		// Primary search: by VPC+TGW (the natural unique key for an attachment).
		//
		// This MUST happen before any tag-based search. The seed VPC attachment is
		// shared across every shoot reconcile in the seed and may have been created
		// by a different shoot than the one currently reconciling — its tags will
		// then carry that other shoot's cluster identifier, and a tag-based finder
		// will return nothing. Result: each child shoot creates a NEW attachment
		// for the same VPC, and AWS ends up with N parallel duplicates that all
		// fight over the same RT.
		//
		// VPC+TGW is the AWS-side uniqueness constraint anyway; let's match on it.
		allOnTGW, listErr := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgwID)
		if listErr != nil {
			return fmt.Errorf("failed to list TGW attachments for seed VPC discovery: %w", listErr)
		}
		for _, att := range allOnTGW {
			if att.VpcId == seedVpcID && !isAttachmentTerminal(att.State) {
				current = att
				log.Info("found seed VPC TGW attachment by VPC+TGW",
					"attachmentId", att.TransitGatewayAttachmentId, "seedVpcId", seedVpcID)
				break
			}
		}

		// Secondary search: state ID + own tags. Only used as a sanity check or
		// recovery if VPC+TGW didn't find anything (shouldn't normally happen).
		if current == nil {
			current, err = FindExisting(ctx, attachmentID, tags,
				tgwClient.GetTransitGatewayVPCAttachment,
				tgwClient.FindTransitGatewayVPCAttachmentsByTags,
				func(item *awsclient.TransitGatewayVPCAttachment) bool {
					return item.VpcId == seedVpcID && item.TransitGatewayId == tgwID &&
						!isAttachmentTerminal(item.State)
				})
			if err != nil {
				return err
			}
		}

		if current != nil {
			log.Info("seed VPC TGW attachment already exists", "attachmentId", current.TransitGatewayAttachmentId, "seedVpcId", seedVpcID)
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, current.TransitGatewayAttachmentId)
			// Migrate legacy tags (pre-fix-#1) to seed-canonical pattern.
			c.retagToSeedCanonical(ctx, log, tgwClient, current.TransitGatewayAttachmentId, current.Tags, tags)
		} else {
			seedVPCClient, clientErr := c.getSeedVPCClient(ctx)
			if clientErr != nil {
				return fmt.Errorf("failed to get seed VPC client for attachment creation: %w", clientErr)
			}
			log.Info("creating seed VPC TGW attachment", "tgwId", tgwID, "seedVpcId", seedVpcID, "subnetIds", seedSubnetIDs, "crossAccount", seedVPCClient != c.client)
			created, createErr := seedVPCClient.CreateTransitGatewayVPCAttachment(ctx, &awsclient.TransitGatewayVPCAttachment{
				TransitGatewayId: tgwID,
				VpcId:            seedVpcID,
				SubnetIds:        seedSubnetIDs,
				Tags:             tags,
			})
			if createErr != nil {
				code := awsclient.GetAWSAPIErrorCode(createErr)
				if code != "DuplicateTransitGatewayAttachment" {
					return fmt.Errorf("failed to create seed VPC TGW attachment: %w", createErr)
				}
				log.Info("seed VPC TGW attachment already exists (duplicate error), looking up by VPC ID")
				allAttachments, listErr := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgwID)
				if listErr != nil {
					return fmt.Errorf("failed to list TGW attachments after duplicate error: %w", listErr)
				}
				found := false
				for _, att := range allAttachments {
					if att.VpcId == seedVpcID {
						log.Info("found existing seed VPC TGW attachment", "attachmentId", att.TransitGatewayAttachmentId)
						c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, att.TransitGatewayAttachmentId)
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("DuplicateTransitGatewayAttachment but could not find attachment for VPC %s on TGW %s", seedVpcID, tgwID)
				}
			} else {
				log.Info("created seed VPC TGW attachment", "attachmentId", created.TransitGatewayAttachmentId)
				c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, created.TransitGatewayAttachmentId)
				if waitErr := tgwClient.WaitForTransitGatewayVPCAttachmentAvailable(ctx, created.TransitGatewayAttachmentId); waitErr != nil {
					return fmt.Errorf("failed waiting for seed VPC TGW attachment to become available: %w", waitErr)
				}
				attachmentJustCreated = true
			}
		}

		v := c.state.Get(IdentifierSeedVPCTransitGatewayAttachment)
		if v == nil {
			return fmt.Errorf("internal error: seed VPC TGW attachment ID not in state after create/find")
		}
		seedAttachmentID = *v

		// Verify the seed VPC attachment still exists, is usable, and is on the correct TGW.
		verifySeedAtt, verifySeedErr := tgwClient.GetTransitGatewayVPCAttachment(ctx, seedAttachmentID)
		if verifySeedErr != nil || verifySeedAtt == nil || isAttachmentTerminal(verifySeedAtt.State) || verifySeedAtt.TransitGatewayId != tgwID {
			if attempt == 0 {
				log.Info("seed VPC TGW attachment is stale — clearing state and retrying in-place",
					"attachmentId", seedAttachmentID, "attempt", attempt+1)
				c.clearStaleAttachmentState(log, IdentifierSeedVPCTransitGatewayAttachment, seedAttachmentID)
				continue
			}
			c.clearStaleAttachmentState(log, IdentifierSeedVPCTransitGatewayAttachment, seedAttachmentID)
			return fmt.Errorf("seed VPC TGW attachment %s is stale after retry — cleared state", seedAttachmentID)
		}
		break
	}

	// RT association phase — single canonical owner principle.
	//
	// ensureSeedVPCAttachment runs from EVERY shoot reconcile that has a seed VPC,
	// including child shoots reconciled by a *different* extension instance from
	// the one reconciling the seed shoot itself. Two extensions calling
	// AssociateTransitGatewayRouteTable on the same attachment in close succession
	// (or while one is mid-Phase-2) race in AWS: one wins, the other gets reported
	// success but is silently overwritten — and the loser retries forever.
	//
	// Canonical mover: ensureTransitGatewayAttachment (with isManagedSeedShoot=true)
	// running in the seed shoot's own reconcile is the SOLE owner of associate /
	// disassociate calls for the seed VPC attachment.
	//
	// This function only:
	//   1. Bootstraps the association if WE just created the attachment (no canonical
	//      owner has run yet — first child shoot can race ahead of the seed shoot).
	//   2. Enables propagation to canonical RTs (idempotent, safe from any reconcile).
	//
	// History: an earlier iteration added active switching here, which produced
	// cross-extension ping-pong during version upgrades. The intermediate form
	// still associated when currentRT was empty (mid Phase-2 of the canonical
	// owner) — that race caused a cascade in early testing. The current
	// implementation removes even that path: a missing association is the
	// canonical owner's problem, not ours.
	canonicalRT := hubRT
	if c.isSharedIsolationMode() {
		canonicalRT = c.resolvedSharedRouteTableID
	}

	log.Info("ensureSeedVPCAttachment: RT association phase",
		"seedAttachmentID", seedAttachmentID,
		"isSharedMode", c.isSharedIsolationMode(),
		"canonicalRT", canonicalRT,
		"attachmentJustCreated", attachmentJustCreated,
	)

	currentRT, lookupErr := tgwClient.GetTransitGatewayAttachmentAssociation(ctx, seedAttachmentID)
	if lookupErr != nil {
		return fmt.Errorf("failed to look up current seed VPC TGW association: %w", lookupErr)
	}

	// Bootstrap-associate when:
	//   (a) WE just created the attachment in this reconcile (always — first
	//       child shoot can race ahead of the seed shoot), OR
	//   (b) c.isManagedSeedShoot is true: this reconcile IS the canonical owner.
	//       Without this branch, the seed shoot's reconcile would defer to a
	//       non-existent "next reconcile of the canonical owner", leaving the
	//       seed VPC attachment unassociated when ensureTransitGatewayAttachment
	//       earlier in the same reconcile happened to defer (e.g., transient).
	//       Observed in earlier testing: the gardenlet→garden-API path broke
	//       until the attachment was manually associated.
	canonicalOwnerHere := attachmentJustCreated || c.isManagedSeedShoot

	if canonicalOwnerHere && currentRT == "" && canonicalRT != "" {
		log.Info("seed VPC attachment unassociated — associating with canonical RT (canonical-owner reconcile)",
			"canonicalRT", canonicalRT,
			"isManagedSeedShoot", c.isManagedSeedShoot,
			"attachmentJustCreated", attachmentJustCreated)
		if err := tgwClient.AssociateTransitGatewayRouteTable(ctx, canonicalRT, seedAttachmentID); err != nil {
			code := awsclient.GetAWSAPIErrorCode(err)
			switch code {
			case "Resource.AlreadyAssociated":
				// already done — fine
			case "IncorrectState", "InvalidRouteTableID.NotFound":
				// canonical RT is mid-create or hasn't propagated yet — transient.
				// Signal drift so the next reconcile retries.
				log.Info("seed VPC associate hit transient RT state — deferring",
					"canonicalRT", canonicalRT, "code", code)
				c.tgwDriftDetected = true
			default:
				return fmt.Errorf("failed to associate seed VPC attachment with canonical RT: %w", err)
			}
		}
	} else if currentRT == "" {
		// Child shoot reconcile observing an unassociated seed VPC attachment.
		// We're NOT the canonical owner — defer to the seed shoot's reconcile.
		log.Info("seed VPC attachment has no RT association — canonical owner (seed shoot reconcile) must associate; not touching to avoid cross-extension fight",
			"expectedCanonicalRT", canonicalRT)
		c.event(corev1.EventTypeWarning, "SeedVPCUnassociated",
			"Seed VPC attachment %s has no RT association; waiting for canonical owner to associate. Expected RT for current mode: %s",
			seedAttachmentID, canonicalRT)
	} else if currentRT != canonicalRT && c.isManagedSeedShoot {
		// Seed shoot reconcile observing the seed VPC attachment on a wrong RT
		// (e.g. left over from a prior isolation mode). We are the canonical
		// owner; switch it. Use the existing two-phase isolation switch helper
		// (switchAttachmentRT) only if available — otherwise log + defer.
		log.Info("seed VPC attachment on wrong RT — canonical-owner reconcile will rely on ensureTransitGatewayAttachment to switch",
			"currentRT", currentRT, "expectedCanonicalRT", canonicalRT)
	} else if currentRT != canonicalRT {
		log.Info("seed VPC attachment is on a different RT than canonical for current mode — canonical owner will switch on its next reconcile; only ensuring propagation",
			"currentRT", currentRT, "expectedCanonicalRT", canonicalRT)
	}

	// Always enable propagation to the canonical RT so routes exist regardless of
	// which RT the attachment is currently associated with. Propagation is fully
	// idempotent and never causes cross-extension contention.
	enableProp := func(rtID, role string) error {
		if rtID == "" {
			return nil
		}
		if err := tgwClient.EnableTransitGatewayRouteTablePropagation(ctx, rtID, seedAttachmentID); err != nil {
			code := awsclient.GetAWSAPIErrorCode(err)
			switch code {
			case "TransitGatewayRouteTablePropagation.Duplicate":
				// already enabled — fine
			case "IncorrectState", "InvalidRouteTableID.NotFound":
				// RT is mid-create / mid-delete or otherwise transiently unavailable.
				// Signal drift so the next reconcile retries; do NOT error.
				log.Info("seed VPC propagation hit transient RT state — deferring",
					"rt", rtID, "role", role, "code", code)
				c.tgwDriftDetected = true
			default:
				return fmt.Errorf("failed to enable seed VPC TGW propagation to %s RT %s: %w", role, rtID, err)
			}
		}
		return nil
	}
	if err := enableProp(canonicalRT, "canonical"); err != nil {
		return err
	}
	// In hub-spoke mode, also propagate to spoke RT so all shoot attachments can
	// reach the seed VPC via TGW. Skip in shared mode (no spoke RT in use).
	if !c.isSharedIsolationMode() {
		if err := enableProp(spokeRT, "spoke"); err != nil {
			return err
		}
	}

	// Step 6: Add routes in seed VPC private route tables for:
	//   a) Shoot VPC CIDR → TGW (return traffic from seed to shoot workers)
	//   b) GlobalVPC CIDRs → TGW (seed needs to reach utility/runtime VPCs)
	//
	// Skip the shoot CIDR for the seed shoot (same VPC — would conflict with local route).
	// Always inject globalVPC CIDRs, even for the seed shoot.

	// Use cross-account client for seed VPC route operations if configured.
	seedVPCRouteClient, seedClientErr := c.getSeedVPCClient(ctx)
	if seedClientErr != nil {
		return fmt.Errorf("failed to get seed VPC client for route injection: %w", seedClientErr)
	}

	// Discover seed VPC route tables (shared across all steps).
	seedRTs, err := seedVPCRouteClient.FindRouteTablesByFilters(ctx, []ec2types.Filter{
		{Name: ptr.To("vpc-id"), Values: []string{seedVpcID}},
	})
	if err != nil {
		return fmt.Errorf("failed to list route tables for seed VPC route injection: %w", err)
	}
	// Filter to private zone route tables (by name convention *-private-*).
	var privateSeedRTs []*awsclient.RouteTable
	for _, rt := range seedRTs {
		if strings.Contains(rt.Tags["Name"], "-private-") {
			privateSeedRTs = append(privateSeedRTs, rt)
		}
	}

	// Step 6a: Shoot VPC CIDR route.
	shootVPCCIDR := c.config.Networks.VPC.CIDR
	// Persist shoot VPC CIDR in state for cleanup during deletion (P1 #6).
	if shootVPCCIDR != nil {
		c.state.Set(IdentifierShootVPCCIDR, *shootVPCCIDR)
	}
	if shootVPCCIDR != nil {
		cidrStr := *shootVPCCIDR
		if err := c.ensureSeedVPCRoute(ctx, log, seedVPCRouteClient, privateSeedRTs, cidrStr, tgwID, "shoot VPC"); err != nil {
			return err
		}
	}

	// Step 6b: REMOVED — globalVPC CIDR routes are NOT added to the seed VPC.
	//
	// GlobalVPC connectivity (runtime VPC, mgmt VPC) is handled by TGW route table
	// propagation — the runtime/mgmt VPCs are propagated to the TGW's RTs, so child
	// shoots can reach them through the TGW without explicit routes in the seed VPC.
	//
	// Adding explicit globalVPC routes here is harmful in managed mode: the seed VPC
	// has routes to runtime/mgmt via the ref TGW (for the seed shoot's own connectivity),
	// and overwriting them with managed TGW routes breaks the seed shoot. AWS route
	// tables allow only one route per CIDR, so both can't coexist.
	//
	// This applies to both referenced and managed modes — TGW propagation handles it.

	// Step 6c: Add shoot VPC CIDR route in each globalVPC's route tables.
	// This enables return traffic from globalVPCs (e.g., harbor on mgmt VPC)
	// back to shoots with a VPC CIDR.
	if c.config.Networks.VPC.CIDR != nil {
		shootCIDR := *c.config.Networks.VPC.CIDR
		for _, gvpc := range c.resolvedEffectiveGlobalVPCs {
			// Skip route-only globalVPCs (auto-discovered runtime VPC — no vpcId/attachmentId).
			hasVpcID := gvpc.VpcID != nil && *gvpc.VpcID != ""
			hasAttID := gvpc.AttachmentID != nil && *gvpc.AttachmentID != ""
			if !hasVpcID && !hasAttID {
				continue
			}

			// Determine the globalVPC's VPC ID for route table lookup.
			var gvpcVpcID string
			if hasVpcID {
				gvpcVpcID = *gvpc.VpcID
			} else if hasAttID {
				att, attErr := tgwClient.GetTransitGatewayVPCAttachment(ctx, *gvpc.AttachmentID)
				if attErr != nil || att == nil {
					log.Info("skipping globalVPC route injection — attachment lookup failed", "name", gvpc.Name, "error", attErr)
					continue
				}
				gvpcVpcID = att.VpcId
			}

			// Skip if the globalVPC's CIDR matches the shoot CIDR (same VPC).
			if gvpcVpcID == "" {
				continue
			}

			// Get client for this globalVPC (may be cross-account).
			gvpcClient, clientErr := c.getGlobalVPCClient(ctx, &gvpc)
			if clientErr != nil {
				log.Info("skipping globalVPC route injection — client error", "name", gvpc.Name, "error", clientErr)
				continue
			}

			gvpcRTs, rtErr := gvpcClient.FindRouteTablesByFilters(ctx, []ec2types.Filter{
				{Name: ptr.To("vpc-id"), Values: []string{gvpcVpcID}},
			})
			if rtErr != nil {
				log.Info("skipping globalVPC route injection — RT lookup failed", "name", gvpc.Name, "error", rtErr)
				continue
			}

			var privateGvpcRTs []*awsclient.RouteTable
			for _, rt := range gvpcRTs {
				if strings.Contains(rt.Tags["Name"], "private") {
					privateGvpcRTs = append(privateGvpcRTs, rt)
				}
			}

			if len(privateGvpcRTs) > 0 {
				log.Info("adding child shoot CIDR route in globalVPC", "globalVPC", gvpc.Name, "vpcId", gvpcVpcID, "shootCIDR", shootCIDR)
				if err := c.ensureSeedVPCRoute(ctx, log, gvpcClient, privateGvpcRTs, shootCIDR, tgwID, fmt.Sprintf("child shoot (return traffic via globalVPC %s)", gvpc.Name)); err != nil {
					log.Info("warning: failed to add child shoot route in globalVPC — continuing", "name", gvpc.Name, "error", err)
				}

				// Step 6d: Cross-globalVPC mesh routes. Each globalVPC (e.g. mgmt) needs
				// routes to OTHER globalVPCs (e.g. auto-discovered runtime VPC) so traffic
				// can cross between them via TGW. Without this, mgmt VPC has no route for
				// runtime VPC CIDR — VPN client → mgmt → garden API path is broken.
				//
				// Previously this relied on an externally-managed summary route to the
				// TGW in the mgmt VPC, which got deleted during a TGW switch and was
				// never re-created. The extension now owns this concern.
				for _, otherGVPC := range c.resolvedEffectiveGlobalVPCs {
					if otherGVPC.Name == gvpc.Name {
						continue
					}
					for _, otherCIDR := range otherGVPC.CIDRs {
						otherCIDRCopy := otherCIDR
						log.Info("adding cross-globalVPC mesh route", "fromGVPC", gvpc.Name, "toGVPC", otherGVPC.Name, "cidr", otherCIDRCopy)
						if err := c.ensureSeedVPCRoute(ctx, log, gvpcClient, privateGvpcRTs, otherCIDRCopy, tgwID,
							fmt.Sprintf("cross-globalVPC mesh: %s → %s", gvpc.Name, otherGVPC.Name)); err != nil {
							log.Info("warning: failed to add cross-globalVPC mesh route — continuing",
								"fromGVPC", gvpc.Name, "toGVPC", otherGVPC.Name, "cidr", otherCIDRCopy, "error", err)
						}
					}
				}
			}
		}
	}

	return nil
}

// deleteAndWaitForTransitGatewayVPCAttachment deletes a TGW VPC attachment and waits
// for AWS to fully release the ENIs (state transitions to "deleted"). This prevents
// DependencyViolation errors when subnets are subsequently deleted.
func (c *FlowContext) deleteAndWaitForTransitGatewayVPCAttachment(ctx context.Context, log logr.Logger, awsClient awsclient.Interface, attachmentID string) error {
	log.Info("deleting transit gateway VPC attachment and waiting for ENI release", "attachmentId", attachmentID)
	if err := awsClient.DeleteTransitGatewayVPCAttachment(ctx, attachmentID); err != nil {
		return fmt.Errorf("failed to delete TGW VPC attachment %s: %w", attachmentID, err)
	}
	if err := awsClient.WaitForTransitGatewayVPCAttachmentDeleted(ctx, attachmentID); err != nil {
		return fmt.Errorf("timed out waiting for TGW VPC attachment %s to be deleted: %w", attachmentID, err)
	}
	log.Info("TGW VPC attachment deleted and ENIs released", "attachmentId", attachmentID)
	return nil
}

// ensureSeedVPCRoute adds a TGW route in private route tables of a target VPC.
// Used for seed VPC (Step 6a/6c), runtime VPC (Step 5b/5c), and globalVPC routes.
// Behavior:
//   - No existing route: creates cidr → tgwID.
//   - Existing route with same TGW: no-op.
//   - Existing route in blackhole state: deletes and recreates with correct TGW.
//   - Existing route with different active TGW: replaces (route is owned by this
//     shoot's reconcile and should point to the current TGW).
func (c *FlowContext) ensureSeedVPCRoute(ctx context.Context, log logr.Logger, seedVPCClient awsclient.Interface, seedRTs []*awsclient.RouteTable, cidr, tgwID, description string) error {
	for _, rt := range seedRTs {
		existingTGW := ""
		routeState := ""
		hasRoute := false
		for _, r := range rt.Routes {
			if r.DestinationCidrBlock != nil && *r.DestinationCidrBlock == cidr {
				if r.TransitGatewayId != nil {
					existingTGW = *r.TransitGatewayId
					if r.State != nil {
						routeState = *r.State
					}
					hasRoute = true
				}
				break
			}
		}
		if hasRoute {
			if existingTGW == tgwID {
				log.Info("seed VPC route already exists", "routeTableId", rt.RouteTableId, "cidr", cidr, "for", description)
				continue
			}
			// Check if the route is a blackhole (old TGW deleted). Replace it
			// atomically via ReplaceRoute (no routing gap).
			if routeState != "" && routeState == "blackhole" {
				log.Info("replacing blackhole route in seed VPC",
					"routeTableId", rt.RouteTableId, "cidr", cidr, "oldTGW", existingTGW, "newTGW", tgwID, "for", description)
				if err := seedVPCClient.ReplaceRoute(ctx, rt.RouteTableId, &awsclient.Route{
					DestinationCidrBlock: &cidr,
					TransitGatewayId:     &tgwID,
				}); err != nil {
					return fmt.Errorf("failed to replace blackhole route in seed VPC %s for %s (%s): %w", rt.RouteTableId, description, cidr, err)
				}
				continue
			}
			// Route points to a different TGW. Atomically retarget via ReplaceRoute
			// (no routing gap) — Delete+Create here would break gardenlet → garden API
			// connectivity during a TGW switch.
			log.Info("replacing wrong-TGW route in seed VPC (child shoot CIDR or runtime route)",
				"routeTableId", rt.RouteTableId, "cidr", cidr, "oldTGW", existingTGW, "newTGW", tgwID, "for", description)
			if err := seedVPCClient.ReplaceRoute(ctx, rt.RouteTableId, &awsclient.Route{
				DestinationCidrBlock: &cidr,
				TransitGatewayId:     &tgwID,
			}); err != nil {
				return fmt.Errorf("failed to replace route in seed VPC %s for %s (%s): %w", rt.RouteTableId, description, cidr, err)
			}
			continue
		}
		// No existing TGW route — add it.
		log.Info("adding seed VPC route", "routeTableId", rt.RouteTableId, "cidr", cidr, "tgwId", tgwID, "for", description)
		if err := seedVPCClient.CreateRoute(ctx, rt.RouteTableId, &awsclient.Route{
			DestinationCidrBlock: &cidr,
			TransitGatewayId:     &tgwID,
		}); err != nil {
			if code := awsclient.GetAWSAPIErrorCode(err); code != "RouteAlreadyExists" {
				return fmt.Errorf("failed to add route to seed VPC route table %s for %s (%s): %w", rt.RouteTableId, description, cidr, err)
			}
		}
	}
	return nil
}

// discoverSeedVPC finds the seed's VPC ID and worker subnet IDs by searching
// for a VPC whose CIDR matches the Seed's node network, then finding subnets
// in that VPC tagged as "nodes" (worker) subnets by Gardener.
func (c *FlowContext) discoverSeedVPC(ctx context.Context, log logr.Logger) (string, []string, error) {
	// Use cross-account client if SeedVPCCredentialsRef is configured.
	awsClient, err := c.getSeedVPCClient(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get seed VPC client: %w", err)
	}

	log.Info("discovering seed VPC from node CIDR", "cidr", c.seedNodesCIDR, "crossAccount", awsClient != c.client)

	// Find VPC by CIDR block (matches both primary and secondary CIDR associations).
	vpcs, err := awsClient.FindVpcsByFilters(ctx, []ec2types.Filter{
		{Name: ptr.To("cidr-block-association.cidr-block"), Values: []string{c.seedNodesCIDR}},
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to find VPC for seed VPC discovery (CIDR %s): %w", c.seedNodesCIDR, err)
	}

	if len(vpcs) == 0 {
		return "", nil, fmt.Errorf("could not find VPC with CIDR %s for seed VPC discovery", c.seedNodesCIDR)
	}
	seedVpcID := vpcs[0].VpcId
	log.Info("discovered seed VPC", "vpcId", seedVpcID, "cidr", c.seedNodesCIDR)

	// Find worker (nodes) subnets in the seed VPC.
	// Gardener tags subnets with "kubernetes.io/role/node" = "1" for worker subnets,
	// or we can filter by the VPC ID and look for "nodes" purpose subnets.
	subnets, err := awsClient.FindSubnets(ctx, []ec2types.Filter{
		{Name: ptr.To("vpc-id"), Values: []string{seedVpcID}},
		{Name: ptr.To("tag:kubernetes.io/role/node"), Values: []string{"1"}},
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to find worker subnets in seed VPC %s: %w", seedVpcID, err)
	}

	// If no subnets found with the kubernetes.io/role/node tag, fall back to
	// finding private node subnets by Gardener's naming convention (*-nodes-z*).
	if len(subnets) == 0 {
		log.Info("no subnets found with kubernetes.io/role/node tag, trying name-based discovery")
		subnets, err = awsClient.FindSubnets(ctx, []ec2types.Filter{
			{Name: ptr.To("vpc-id"), Values: []string{seedVpcID}},
		})
		if err != nil {
			return "", nil, fmt.Errorf("failed to find subnets in seed VPC %s: %w", seedVpcID, err)
		}
		// Filter to node subnets using Gardener's naming convention (*-nodes-z*).
		var nodeSubnets []*awsclient.Subnet
		for _, s := range subnets {
			if name := s.Tags["Name"]; strings.Contains(name, "-nodes-") {
				nodeSubnets = append(nodeSubnets, s)
			}
		}
		if len(nodeSubnets) > 0 {
			subnets = nodeSubnets
		} else {
			// Last resort: exclude public and utility subnets.
			var privateSubnets []*awsclient.Subnet
			for _, s := range subnets {
				name := s.Tags["Name"]
				if !strings.Contains(name, "utility") && !strings.Contains(name, "public") {
					privateSubnets = append(privateSubnets, s)
				}
			}
			subnets = privateSubnets
		}
	}

	if len(subnets) == 0 {
		return "", nil, fmt.Errorf("no worker subnets found in seed VPC %s", seedVpcID)
	}

	// TGW attachment allows only one subnet per AZ. Deduplicate by picking the first per zone.
	seenZones := map[string]bool{}
	var subnetIDs []string
	for _, s := range subnets {
		if seenZones[s.AvailabilityZone] {
			log.Info("skipping duplicate subnet in same AZ", "subnetId", s.SubnetId, "zone", s.AvailabilityZone)
			continue
		}
		seenZones[s.AvailabilityZone] = true
		subnetIDs = append(subnetIDs, s.SubnetId)
		log.Info("discovered seed worker subnet", "subnetId", s.SubnetId, "zone", s.AvailabilityZone)
	}

	return seedVpcID, subnetIDs, nil
}

// cleanupSeedVPCRoutes removes TGW-pointed routes from the seed VPC's private route tables.
// Used during shoot deletion (removes specific shootCIDR route) and TGW disable (removes all TGW routes).
// If shootCIDR is non-empty, only that route is removed; if empty, all routes pointing to the given TGW are removed.
func (c *FlowContext) cleanupSeedVPCRoutes(ctx context.Context, log logr.Logger, shootCIDR string, tgwID string) {
	if c.seedNodesCIDR == "" {
		return
	}

	// Use cross-account client for seed VPC operations if configured.
	seedVPCClient, clientErr := c.getSeedVPCClient(ctx)
	if clientErr != nil {
		log.Error(clientErr, "failed to get seed VPC client for route cleanup")
		return
	}

	// Discover seed VPC by CIDR match.
	vpcs, err := seedVPCClient.FindVpcsByFilters(ctx, []ec2types.Filter{
		{Name: ptr.To("cidr-block-association.cidr-block"), Values: []string{c.seedNodesCIDR}},
	})
	if err != nil {
		log.Error(err, "failed to find seed VPC for route cleanup")
		return
	}
	if len(vpcs) == 0 {
		log.Info("seed VPC not found for route cleanup, skipping", "cidr", c.seedNodesCIDR)
		return
	}
	seedVpcID := vpcs[0].VpcId

	// Find seed VPC route tables.
	seedRTs, err := seedVPCClient.FindRouteTablesByFilters(ctx, []ec2types.Filter{
		{Name: ptr.To("vpc-id"), Values: []string{seedVpcID}},
	})
	if err != nil {
		log.Error(err, "failed to list seed VPC route tables for cleanup")
		return
	}

	for _, rt := range seedRTs {
		if !strings.Contains(rt.Tags["Name"], "-private-") {
			continue
		}
		for _, r := range rt.Routes {
			if r.TransitGatewayId == nil {
				continue
			}
			if tgwID != "" && *r.TransitGatewayId != tgwID {
				continue
			}
			if shootCIDR != "" {
				// Only delete the specific shoot CIDR route.
				if r.DestinationCidrBlock == nil || *r.DestinationCidrBlock != shootCIDR {
					continue
				}
			}
			cidr := "<unknown>"
			if r.DestinationCidrBlock != nil {
				cidr = *r.DestinationCidrBlock
			}
			log.Info("removing TGW route from seed VPC", "routeTableId", rt.RouteTableId, "cidr", cidr, "tgwId", *r.TransitGatewayId)
			if err := seedVPCClient.DeleteRoute(ctx, rt.RouteTableId, &awsclient.Route{
				DestinationCidrBlock: r.DestinationCidrBlock,
			}); err != nil {
				if code := awsclient.GetAWSAPIErrorCode(err); code != "InvalidRoute.NotFound" {
					log.Error(err, "failed to delete seed VPC route — continuing", "routeTableId", rt.RouteTableId)
				}
			}
		}
	}
}

// ensureGlobalVPCAssociations verifies each globalVPC attachment exists and configures
// its TGW route table association (spoke) and propagation (hub + spoke).
// GlobalVPCs are shared utility VPCs — they must propagate to both hub AND spoke
// so that all shoots can reach them.
//
// These are SEED-LEVEL shared resources — they are NOT cleaned up when individual
// shoots are deleted. All shoots on the seed share the same globalVPC associations.
// The idempotent AWS API calls (AlreadyAssociated, Duplicate) make this safe to
// call from every shoot's reconcile without conflict.
func (c *FlowContext) ensureGlobalVPCAssociations(ctx context.Context, log logr.Logger) error {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil || !c.seedConfig.TransitGateway.Enabled || len(c.resolvedEffectiveGlobalVPCs) == 0 {
		return nil
	}

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	tgwID := c.resolvedTGWID
	if tgwID == "" {
		return nil // TGW not resolved — skip globalVPC associations
	}
	hubRT := c.resolvedHubRouteTableID
	spokeRT := c.resolvedSpokeRouteTableID
	sharedRT := c.resolvedSharedRouteTableID

	for i := range c.resolvedEffectiveGlobalVPCs {
		gvpc := &c.resolvedEffectiveGlobalVPCs[i]

		// Only process globalVPCs that came from the seed config. Auto-synthesized
		// entries (e.g., runtime VPC from ensureRuntimeVPCAttachment) have their RT
		// association managed by their own DAG task — processing them here would
		// conflict (e.g., associating runtime VPC with spoke RT when it should be on hub).
		isFromConfig := false
		for _, configGVPC := range c.seedConfig.TransitGateway.GlobalVPCs {
			if configGVPC.Name == gvpc.Name {
				isFromConfig = true
				break
			}
		}
		if !isFromConfig {
			log.Info("skipping auto-synthesized globalVPC (RT managed elsewhere)", "name", gvpc.Name)
			continue
		}

		// Skip route-only entries (no attachmentId/vpcId) — they're only in the list
		// so buildTGWRoutes adds routes to shoot VPC route tables.
		hasAttachment := gvpc.AttachmentID != nil && *gvpc.AttachmentID != ""
		hasVpcID := gvpc.VpcID != nil && *gvpc.VpcID != ""
		if !hasAttachment && !hasVpcID {
			log.Info("skipping route-only globalVPC (no attachmentId/vpcId)", "name", gvpc.Name)
			continue
		}

		// Resolve the attachment ID — either from config (referenced) or from managed creation.
		attachmentID, err := c.resolveGlobalVPCAttachment(ctx, log, gvpc, tgwID)
		if err != nil {
			return err
		}

		// Verify the attachment exists and is usable.
		existing, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, attachmentID)
		if err != nil {
			return fmt.Errorf("failed to verify globalVPC %q attachment %s: %w", gvpc.Name, attachmentID, err)
		}
		if existing == nil {
			return fmt.Errorf("globalVPC %q attachment %s not found or deleted", gvpc.Name, attachmentID)
		}

		gvpcRole := "globalVPC " + gvpc.Name
		if c.isSharedIsolationMode() {
			// Shared mode: associate AND propagate to the single shared RT.
			// AlreadyAssociated is swallowed by the helper because the globalVPC may
			// legitimately remain on its previous RT (hub or spoke); routing works
			// either way since we propagate to shared regardless. We do NOT actively
			// move the attachment from one RT to another here, because globalVPCs are
			// also touched by other reconciles and a forced switch creates
			// cross-extension ping-pong (see tgw-cross-extension-todos.md).
			if err := c.associateTGWRouteTable(ctx, log, tgwClient, sharedRT, attachmentID, gvpcRole+" (shared)"); err != nil {
				return err
			}
			if err := c.enableTGWPropagation(ctx, log, tgwClient, sharedRT, attachmentID, gvpcRole+" (shared)"); err != nil {
				return err
			}
		} else {
			// Hub-spoke mode: associate with HUB (globalVPCs are hub-side resources,
			// like the seed and runtime VPCs — they all "see" everything via hub
			// propagations). Propagate to BOTH hub and spoke so that routes to the
			// globalVPC exist regardless of which RT a given peer attachment uses.
			//
			// AlreadyAssociated is swallowed by the helper: this attachment may still
			// be on its previous RT, and routing still works either way because of the
			// dual propagation. We don't actively switch the association — that's the
			// canonical-mover principle (only the canonical owner switches RTs).
			if err := c.associateTGWRouteTable(ctx, log, tgwClient, hubRT, attachmentID, gvpcRole+" (hub-spoke)"); err != nil {
				return err
			}
			if err := c.enableTGWPropagation(ctx, log, tgwClient, hubRT, attachmentID, gvpcRole+" (hub)"); err != nil {
				return err
			}
			if err := c.enableTGWPropagation(ctx, log, tgwClient, spokeRT, attachmentID, gvpcRole+" (spoke)"); err != nil {
				return err
			}
		}

		log.Info("globalVPC association/propagation complete", "name", gvpc.Name, "attachmentId", attachmentID)
	}

	return nil
}

// discoverRuntimeVPC resolves the Garden API hostname to find the runtime VPC.
// This is used in managed TGW mode to auto-discover the runtime VPC without any
// YAML config. The Garden API hostname is constructed from Seed.spec.dns.defaults[0].domain.
// findPrivateSubnetsForTGW finds one private subnet per AZ in the given VPC.
// Uses a layered detection approach:
//  1. Tag: kubernetes.io/role/internal-elb=1 (Gardener/EKS standard)
//  2. Name tag contains "private" (common convention)
//  3. Fallback: any subnet (TGW attachments work with any subnet type)
func (c *FlowContext) findPrivateSubnetsForTGW(ctx context.Context, log logr.Logger, awsClient awsclient.Interface, vpcID, description string) ([]string, error) {
	allSubnets, err := awsClient.FindSubnets(ctx, []ec2types.Filter{
		{Name: ptr.To("vpc-id"), Values: []string{vpcID}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find subnets in %s VPC %s: %w", description, vpcID, err)
	}
	if len(allSubnets) == 0 {
		return nil, fmt.Errorf("no subnets found in %s VPC %s", description, vpcID)
	}

	// Layer 1: kubernetes.io/role/internal-elb=1 tag (most reliable).
	var subnetIDs []string
	seenAZs := map[string]bool{}
	for _, sub := range allSubnets {
		if sub.Tags["kubernetes.io/role/internal-elb"] == "1" {
			if !seenAZs[sub.AvailabilityZone] {
				seenAZs[sub.AvailabilityZone] = true
				subnetIDs = append(subnetIDs, sub.SubnetId)
			}
		}
	}
	if len(subnetIDs) > 0 {
		log.Info("found private subnets by internal-elb tag", "description", description, "subnetIds", subnetIDs)
		return subnetIDs, nil
	}

	// Layer 2: Name tag contains "private".
	seenAZs = map[string]bool{}
	for _, sub := range allSubnets {
		if strings.Contains(sub.Tags["Name"], "private") {
			if !seenAZs[sub.AvailabilityZone] {
				seenAZs[sub.AvailabilityZone] = true
				subnetIDs = append(subnetIDs, sub.SubnetId)
			}
		}
	}
	if len(subnetIDs) > 0 {
		log.Info("found private subnets by name tag", "description", description, "subnetIds", subnetIDs)
		return subnetIDs, nil
	}

	// Layer 3: Fallback — use any subnet (one per AZ).
	// TGW attachments work with any subnet type. Warn but don't fail.
	seenAZs = map[string]bool{}
	for _, sub := range allSubnets {
		if !seenAZs[sub.AvailabilityZone] {
			seenAZs[sub.AvailabilityZone] = true
			subnetIDs = append(subnetIDs, sub.SubnetId)
		}
	}
	log.Info("WARNING: no private subnets identified by tag or name — using all subnets as fallback",
		"description", description, "subnetIds", subnetIDs)
	return subnetIDs, nil
}

func (c *FlowContext) discoverRuntimeVPC(ctx context.Context, log logr.Logger) (vpcID string, cidr string, subnetIDs []string, err error) {
	if c.gardenAPIDomain == "" {
		return "", "", nil, fmt.Errorf("cannot discover runtime VPC: Seed.spec.dns.defaults[0].domain is not set")
	}

	// Step 1: Resolve Garden API hostname to IPs.
	log.Info("resolving Garden API hostname for runtime VPC discovery", "hostname", c.gardenAPIDomain)
	ips, lookupErr := net.LookupHost(c.gardenAPIDomain)
	if lookupErr != nil {
		return "", "", nil, fmt.Errorf("failed to resolve Garden API hostname %s: %w", c.gardenAPIDomain, lookupErr)
	}
	if len(ips) == 0 {
		return "", "", nil, fmt.Errorf("garden API hostname %s resolved to zero IPs", c.gardenAPIDomain)
	}
	log.Info("Garden API resolved", "hostname", c.gardenAPIDomain, "ips", ips)

	// Step 2: Find the VPC containing these IPs.
	// Get all VPCs and check which one's CIDR contains the resolved IP.
	runtimeClient, clientErr := c.getSeedVPCClient(ctx)
	if clientErr != nil {
		return "", "", nil, fmt.Errorf("failed to get client for runtime VPC discovery: %w", clientErr)
	}

	targetIP := net.ParseIP(ips[0])
	if targetIP == nil {
		return "", "", nil, fmt.Errorf("failed to parse Garden API IP %s", ips[0])
	}

	allVPCs, vpcErr := runtimeClient.FindVpcsByFilters(ctx, nil)
	if vpcErr != nil {
		return "", "", nil, fmt.Errorf("failed to list VPCs for runtime VPC discovery: %w", vpcErr)
	}

	for _, vpc := range allVPCs {
		_, ipNet, parseErr := net.ParseCIDR(vpc.CidrBlock)
		if parseErr != nil {
			continue
		}
		if ipNet.Contains(targetIP) {
			vpcID = vpc.VpcId
			cidr = vpc.CidrBlock
			break
		}
	}
	if vpcID == "" {
		return "", "", nil, fmt.Errorf("no VPC found containing Garden API IP %s", ips[0])
	}
	log.Info("discovered runtime VPC", "vpcId", vpcID, "cidr", cidr, "gardenIP", ips[0])

	// Step 4: Find private subnets for TGW attachment (one per AZ).
	subnetIDs, subnetErr := c.findPrivateSubnetsForTGW(ctx, log, runtimeClient, vpcID, "runtime VPC")
	if subnetErr != nil {
		return "", "", nil, subnetErr
	}

	return vpcID, cidr, subnetIDs, nil
}

// ensureRuntimeVPCAttachment attaches the runtime VPC (where Garden API lives) to the
// managed TGW. This enables the managed seed's gardenlet and child shoots to reach the
// Garden API via TGW. Only runs in managed TGW mode (isManagedTGWMode).
//
// The runtime VPC is auto-discovered from the Garden API DNS hostname — no config needed.
// The attachment is a shared resource: created by the seed shoot, not deleted when
// individual shoots are deleted. Only cleaned up when the managed TGW is deleted.
func (c *FlowContext) ensureRuntimeVPCAttachment(ctx context.Context) error {
	if !c.isManagedTGWMode() {
		return nil
	}

	log := LogFromContext(ctx)

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	tgwID := c.resolvedTGWID
	if tgwID == "" {
		log.Info("TGW ID not resolved — skipping runtime VPC attachment")
		return nil
	}

	// Step 1: Discover runtime VPC.
	runtimeVPCID, runtimeVPCCIDR, runtimeSubnets, err := c.discoverRuntimeVPC(ctx, log)
	if err != nil {
		return err
	}

	// Persist for use by initEffectiveGlobalVPCs and cleanup.
	c.state.Set(IdentifierRuntimeVPCID, runtimeVPCID)
	c.state.Set(IdentifierRuntimeVPCCIDR, runtimeVPCCIDR)

	// Step 2: Create or find the TGW attachment for the runtime VPC.
	runtimeClient, clientErr := c.getSeedVPCClient(ctx)
	if clientErr != nil {
		return fmt.Errorf("failed to get client for runtime VPC attachment: %w", clientErr)
	}

	// Runtime VPC is shared across all shoots on the seed — tag with the seed
	// shoot's namespace as the canonical owner, not the calling child shoot.
	tags := c.seedCanonicalTags("runtime-vpc-tgw-attachment")

	// Self-heal: if state has a stale runtime VPC attachment, clear and retry once in-place.
	var runtimeAttID string
	for attempt := 0; attempt < 2; attempt++ {
		attachmentID := c.state.Get(IdentifierRuntimeVPCTransitGatewayAttachment)

		current, findErr := FindExisting(ctx, attachmentID, tags,
			runtimeClient.GetTransitGatewayVPCAttachment,
			runtimeClient.FindTransitGatewayVPCAttachmentsByTags,
			func(item *awsclient.TransitGatewayVPCAttachment) bool {
				return item.VpcId == runtimeVPCID && item.TransitGatewayId == tgwID &&
					!isAttachmentTerminal(item.State)
			})
		if findErr != nil {
			return findErr
		}

		if current != nil {
			log.Info("runtime VPC TGW attachment already exists", "attachmentId", current.TransitGatewayAttachmentId)
			c.state.Set(IdentifierRuntimeVPCTransitGatewayAttachment, current.TransitGatewayAttachmentId)
			// Migrate legacy tags (pre-fix-#1) to seed-canonical pattern.
			c.retagToSeedCanonical(ctx, log, runtimeClient, current.TransitGatewayAttachmentId, current.Tags, tags)
		} else {
			log.Info("creating runtime VPC TGW attachment", "tgwId", tgwID, "runtimeVpcId", runtimeVPCID, "subnetIds", runtimeSubnets)
			created, createErr := runtimeClient.CreateTransitGatewayVPCAttachment(ctx, &awsclient.TransitGatewayVPCAttachment{
				TransitGatewayId: tgwID,
				VpcId:            runtimeVPCID,
				SubnetIds:        runtimeSubnets,
				Tags:             tags,
			})
			if createErr != nil {
				code := awsclient.GetAWSAPIErrorCode(createErr)
				if code != "DuplicateTransitGatewayAttachment" {
					return fmt.Errorf("failed to create runtime VPC TGW attachment: %w", createErr)
				}
				log.Info("runtime VPC TGW attachment already exists (duplicate), looking up by VPC ID")
				allAtts, listErr := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgwID)
				if listErr != nil {
					return fmt.Errorf("failed to list TGW attachments after runtime VPC duplicate: %w", listErr)
				}
				found := false
				for _, att := range allAtts {
					if att.VpcId == runtimeVPCID {
						log.Info("found existing runtime VPC attachment", "attachmentId", att.TransitGatewayAttachmentId)
						c.state.Set(IdentifierRuntimeVPCTransitGatewayAttachment, att.TransitGatewayAttachmentId)
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("DuplicateTransitGatewayAttachment but could not find runtime VPC attachment for %s", runtimeVPCID)
				}
			} else {
				log.Info("created runtime VPC TGW attachment", "attachmentId", created.TransitGatewayAttachmentId)
				c.state.Set(IdentifierRuntimeVPCTransitGatewayAttachment, created.TransitGatewayAttachmentId)
				if waitErr := tgwClient.WaitForTransitGatewayVPCAttachmentAvailable(ctx, created.TransitGatewayAttachmentId); waitErr != nil {
					return fmt.Errorf("failed waiting for runtime VPC TGW attachment: %w", waitErr)
				}
			}
		}

		v := c.state.Get(IdentifierRuntimeVPCTransitGatewayAttachment)
		if v == nil {
			return fmt.Errorf("internal error: runtime VPC TGW attachment ID not in state after create/find")
		}
		runtimeAttID = *v

		verifyRuntimeAtt, verifyRuntimeErr := tgwClient.GetTransitGatewayVPCAttachment(ctx, runtimeAttID)
		if verifyRuntimeErr != nil || verifyRuntimeAtt == nil || isAttachmentTerminal(verifyRuntimeAtt.State) || verifyRuntimeAtt.TransitGatewayId != tgwID {
			if attempt == 0 {
				log.Info("runtime VPC TGW attachment is stale — clearing state and retrying in-place",
					"attachmentId", runtimeAttID, "attempt", attempt+1)
				c.clearStaleAttachmentState(log, IdentifierRuntimeVPCTransitGatewayAttachment, runtimeAttID)
				continue
			}
			c.clearStaleAttachmentState(log, IdentifierRuntimeVPCTransitGatewayAttachment, runtimeAttID)
			return fmt.Errorf("runtime VPC TGW attachment %s is stale after retry — cleared state", runtimeAttID)
		}
		break
	}
	hubRT := c.resolvedHubRouteTableID

	// Step 3: Associate runtime VPC with the active canonical RT.
	// We do NOT actively switch on every mode change (creates cross-extension
	// ping-pong, see tgw-cross-extension-todos.md), but we MUST pick a non-empty
	// RT — otherwise associateTGWRouteTable short-circuits on rtID=="" and the
	// runtime VPC ends up unassociated, breaking outbound TGW routing from the
	// runtime VPC. Observed in earlier testing: managed/shared mode
	// has no hubRT, runtime VPC was never associated, gardenlet→garden-API
	// path broke.)
	//
	// Resolve the canonical RT for THIS reconcile's isolation mode:
	//   - shared mode: shared RT
	//   - hub-spoke mode: hub RT
	// Once chosen, associate idempotently. If the attachment is already on a
	// different (still-valid) RT and propagation is correct, the active switch
	// only happens on the FIRST reconcile after the RT comes online.
	canonicalRT := hubRT
	if c.isSharedIsolationMode() {
		canonicalRT = c.resolvedSharedRouteTableID
	}
	currentRT, _ := tgwClient.GetTransitGatewayAttachmentAssociation(ctx, runtimeAttID)
	if currentRT == "" && canonicalRT != "" {
		log.Info("runtime VPC attachment unassociated — associating with canonical RT",
			"canonicalRT", canonicalRT, "isSharedMode", c.isSharedIsolationMode())
		if err := c.associateTGWRouteTable(ctx, log, tgwClient, canonicalRT, runtimeAttID, "runtime VPC"); err != nil {
			return err
		}
	} else if currentRT != "" && currentRT != canonicalRT && canonicalRT != "" {
		// Already on a different RT (e.g., left over from a prior isolation mode).
		// Don't force a switch every reconcile — propagation in Step 4 covers all
		// RTs so traffic still flows. Log for visibility.
		log.Info("runtime VPC attachment is on a non-canonical RT for current mode — leaving in place (propagation covers all RTs)",
			"currentRT", currentRT, "canonicalRT", canonicalRT)
	}

	// Step 4: Propagate runtime VPC to all RTs (hub, spoke, shared).
	for _, rt := range []struct{ name, id string }{
		{"hub", c.resolvedHubRouteTableID},
		{"spoke", c.resolvedSpokeRouteTableID},
		{"shared", c.resolvedSharedRouteTableID},
	} {
		if rt.id == "" {
			continue
		}
		log.Info("enabling runtime VPC TGW propagation", "routeTable", rt.name, "routeTableId", rt.id)
		if err := c.enableTGWPropagation(ctx, log, tgwClient, rt.id, runtimeAttID, "runtime VPC "+rt.name); err != nil {
			return err
		}
	}

	// Step 5: Add routes in runtime VPC for the managed seed VPC and child shoot VPCs.
	// This enables return traffic from the runtime VPC (Garden API, discovery server,
	// dashboard) back to the managed seed and its child shoots.
	runtimeRTs, rtErr := runtimeClient.FindRouteTablesByFilters(ctx, []ec2types.Filter{
		{Name: ptr.To("vpc-id"), Values: []string{runtimeVPCID}},
	})
	if rtErr != nil {
		return fmt.Errorf("failed to find runtime VPC route tables: %w", rtErr)
	}
	var privateRuntimeRTs []*awsclient.RouteTable
	for _, rt := range runtimeRTs {
		if strings.Contains(rt.Tags["Name"], "private") {
			privateRuntimeRTs = append(privateRuntimeRTs, rt)
		}
	}

	// 5a: REMOVED — seed VPC CIDR route in runtime VPC is managed by the parent seed's
	// extension (which correctly points it to the ref TGW). The child shoot reconcile
	// must NOT overwrite it with the managed TGW, same as Step 6b removal.

	// 5b: Shoot VPC CIDR → managed TGW (for return traffic from runtime endpoints).
	if c.config.Networks.VPC.CIDR != nil {
		shootCIDR := *c.config.Networks.VPC.CIDR
		log.Info("adding route in runtime VPC for shoot", "runtimeVpcId", runtimeVPCID, "shootCIDR", shootCIDR, "tgwId", tgwID)
		if err := c.ensureSeedVPCRoute(ctx, log, runtimeClient, privateRuntimeRTs, shootCIDR, tgwID, "child shoot VPC (return traffic)"); err != nil {
			return err
		}
	}

	// 5c: GlobalVPC CIDRs → managed TGW in runtime VPC route tables.
	// Without these routes, traffic FROM runtime VPC TO globalVPCs (e.g., mgmt VPC
	// for VPN connectivity) has no return path — responses from NLBs/pods can't
	// reach back through the TGW to the globalVPC.
	for _, gvpc := range c.resolvedEffectiveGlobalVPCs {
		// Skip route-only globalVPCs (auto-discovered runtime VPC — can't route to self).
		hasVpcID := gvpc.VpcID != nil && *gvpc.VpcID != ""
		hasAttID := gvpc.AttachmentID != nil && *gvpc.AttachmentID != ""
		if !hasVpcID && !hasAttID {
			continue
		}
		for _, cidr := range gvpc.CIDRs {
			log.Info("adding globalVPC CIDR route in runtime VPC", "runtimeVpcId", runtimeVPCID, "globalVPC", gvpc.Name, "cidr", cidr, "tgwId", tgwID)
			if err := c.ensureSeedVPCRoute(ctx, log, runtimeClient, privateRuntimeRTs, cidr, tgwID, fmt.Sprintf("globalVPC %s (return traffic)", gvpc.Name)); err != nil {
				return err
			}
		}
	}

	// Step 6: Auto-synthesize runtime VPC as a globalVPC so buildTGWRoutes adds
	// the runtime VPC CIDR route in child shoot VPC route tables.
	c.resolvedEffectiveGlobalVPCs = append(c.resolvedEffectiveGlobalVPCs, aws.GlobalVPC{
		Name:         "runtime (auto-discovered)",
		AttachmentID: &runtimeAttID,
		CIDRs:        []string{runtimeVPCCIDR},
	})
	log.Info("runtime VPC added to effective globalVPCs", "cidr", runtimeVPCCIDR)

	log.Info("runtime VPC TGW attachment complete", "attachmentId", runtimeAttID, "runtimeVpcId", runtimeVPCID, "cidr", runtimeVPCCIDR)
	return nil
}

// resolveGlobalVPCAttachment returns the TGW attachment ID for a globalVPC.
// For referenced mode (AttachmentID set), returns the ID directly.
// For managed mode (VpcID set), creates the attachment if it doesn't exist.
func (c *FlowContext) resolveGlobalVPCAttachment(ctx context.Context, log logr.Logger, gvpc *aws.GlobalVPC, tgwID string) (string, error) {
	// Referenced mode — attachment already exists.
	if gvpc.AttachmentID != nil && *gvpc.AttachmentID != "" {
		return *gvpc.AttachmentID, nil
	}

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get TGW client: %w", err)
	}

	// Managed mode — VpcID must be set (validation ensures exactly-one-of).
	if gvpc.VpcID == nil || *gvpc.VpcID == "" {
		return "", fmt.Errorf("globalVPC %q has no attachmentId or vpcId (should have been rejected by validation)", gvpc.Name)
	}

	// Check if we already have this attachment in state. Use the helper because
	// the literal-slash key path (c.state.Get("GlobalVPCAttachment/<name>"))
	// silently returns nil after the state has been persisted+restored once,
	// since ImportFromFlatMap normalizes "/"-keys into a hierarchy. The helper
	// reads via the hierarchy first, falling back to the literal-slash key for
	// in-flight reconciles. See FlowContext.gvpcAttachmentChild godoc.
	if existingID := c.getGlobalVPCAttachmentID(gvpc.Name); existingID != nil {
		existing, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, *existingID)
		if err != nil {
			return "", fmt.Errorf("failed to get existing managed globalVPC attachment %s: %w", *existingID, err)
		}
		if existing != nil && !isAttachmentTerminal(existing.State) {
			log.Info("using existing managed globalVPC attachment", "name", gvpc.Name, "attachmentId", *existingID)
			// Migrate legacy tags (pre-fix-#1) to seed-canonical pattern.
			c.retagToSeedCanonical(ctx, log, tgwClient, *existingID, existing.Tags,
				c.seedCanonicalTags("gvpc-"+gvpc.Name))
			return *existingID, nil
		}
		// Attachment was deleted externally or is in a terminal state — recreate.
		log.Info("managed globalVPC attachment was deleted externally, recreating", "name", gvpc.Name, "previousId", *existingID)
	}

	// Get the client for this VPC (may be cross-account).
	vpcClient, err := c.getGlobalVPCClient(ctx, gvpc)
	if err != nil {
		return "", err
	}

	// Auto-discover subnets if not specified.
	subnetIDs := gvpc.SubnetIDs
	if len(subnetIDs) == 0 {
		var subErr error
		subnetIDs, subErr = c.findPrivateSubnetsForTGW(ctx, log, vpcClient, *gvpc.VpcID, fmt.Sprintf("globalVPC %s", gvpc.Name))
		if subErr != nil {
			return "", subErr
		}
	}

	// Create the TGW VPC attachment.
	// globalVPC attachments are shared across all shoots on the seed —
	// tag with the seed shoot's namespace (canonical owner), not the calling shoot.
	tags := c.seedCanonicalTags("gvpc-" + gvpc.Name)
	log.Info("creating managed globalVPC TGW attachment", "name", gvpc.Name, "vpcId", *gvpc.VpcID, "subnets", subnetIDs)
	created, err := vpcClient.CreateTransitGatewayVPCAttachment(ctx, &awsclient.TransitGatewayVPCAttachment{
		TransitGatewayId: tgwID,
		VpcId:            *gvpc.VpcID,
		SubnetIds:        subnetIDs,
		Tags:             tags,
	})
	if err != nil {
		// Handle DuplicateTransitGatewayAttachment: the attachment was created by a
		// previous reconcile attempt but state wasn't persisted. Look it up by VPC ID.
		code := awsclient.GetAWSAPIErrorCode(err)
		isDuplicate := code == "DuplicateTransitGatewayAttachment" || (code == "InvalidParameterValue" && strings.Contains(err.Error(), "already attached"))
		if isDuplicate {
			log.Info("globalVPC attachment already exists (duplicate), looking up by VPC ID", "name", gvpc.Name, "vpcId", *gvpc.VpcID, "awsError", code)
			allAtts, listErr := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgwID)
			if listErr != nil {
				return "", fmt.Errorf("failed to list TGW attachments after duplicate error for globalVPC %q: %w", gvpc.Name, listErr)
			}
			for _, att := range allAtts {
				if att.VpcId == *gvpc.VpcID {
					log.Info("found existing globalVPC attachment by VPC ID", "name", gvpc.Name, "attachmentId", att.TransitGatewayAttachmentId)
					c.setGlobalVPCAttachmentID(gvpc.Name, att.TransitGatewayAttachmentId)
					c.setGlobalVPCAttachmentManaged(gvpc.Name, true)
					return att.TransitGatewayAttachmentId, nil
				}
			}
			return "", fmt.Errorf("DuplicateTransitGatewayAttachment but could not find attachment for globalVPC %q VPC %s", gvpc.Name, *gvpc.VpcID)
		}
		return "", fmt.Errorf("failed to create managed globalVPC %q TGW attachment: %w", gvpc.Name, err)
	}
	attachmentID := created.TransitGatewayAttachmentId
	log.Info("created managed globalVPC TGW attachment", "name", gvpc.Name, "attachmentId", attachmentID)

	// Wait for attachment to become available.
	if err := tgwClient.WaitForTransitGatewayVPCAttachmentAvailable(ctx, attachmentID); err != nil {
		return "", fmt.Errorf("failed waiting for managed globalVPC %q attachment to become available: %w", gvpc.Name, err)
	}

	// Persist in state via the helper so the value lands in the hierarchy that
	// survives persist+restore. See gvpcAttachmentChild godoc.
	c.setGlobalVPCAttachmentID(gvpc.Name, attachmentID)
	c.setGlobalVPCAttachmentManaged(gvpc.Name, true)

	return attachmentID, nil
}

// ensureShootTransitGatewayAttachment creates a TGW VPC attachment for the shoot's own
// TGW (specified in InfrastructureConfig.Networks.TransitGateway). This is independent
// of and additive to the seed-level TGW attachment.
func (c *FlowContext) ensureShootTransitGatewayAttachment(ctx context.Context) error {
	log := LogFromContext(ctx)

	// Guard: if this is the seed shoot and ensureSeedVPCAttachment manages the VPC
	// attachment (via SeedProviderConfig), skip shoot-level TGW attachment entirely.
	// Running both causes the seed VPC to be re-associated from hub RT to spoke RT,
	// breaking the hub/spoke isolation model.
	if c.shouldAttachSeedVPC() {
		log.Info("skipping shoot-level TGW attachment — seed VPC attachment is managed by ensureSeedVPCAttachment")
		return nil
	}

	shootTGW := c.config.Networks.TransitGateway

	tgwID := *shootTGW.ID // Validation ensures ID is non-nil for shoot-level TGW.

	// Verify the referenced TGW exists.
	existing, err := c.client.GetTransitGateway(ctx, tgwID)
	if err != nil {
		return fmt.Errorf("failed to get shoot-level transit gateway %s: %w", tgwID, err)
	}
	if existing == nil {
		return fmt.Errorf("shoot-level transit gateway %s not found", tgwID)
	}
	log.Info("using shoot-level transit gateway", "tgwId", tgwID, "state", existing.State)

	vpcID := c.state.Get(IdentifierVPC)
	if vpcID == nil {
		return fmt.Errorf("VPC not yet available for shoot TGW attachment")
	}

	// Collect worker subnet IDs.
	var subnetIDs []string
	zones := c.state.GetChild(ChildIdZones)
	for _, zoneKey := range zones.GetChildrenKeys() {
		zoneChild := zones.GetChild(zoneKey)
		if id := zoneChild.Get(IdentifierZoneSubnetWorkers); id != nil {
			subnetIDs = append(subnetIDs, *id)
		}
	}
	if len(subnetIDs) == 0 {
		return fmt.Errorf("no worker subnets found for shoot TGW attachment")
	}

	tags := c.commonTagsWithSuffix("shoot-tgw-attachment")
	attachmentID := c.state.Get(IdentifierShootTransitGatewayAttachment)

	current, err := FindExisting(ctx, attachmentID, tags,
		c.client.GetTransitGatewayVPCAttachment,
		c.client.FindTransitGatewayVPCAttachmentsByTags,
		func(item *awsclient.TransitGatewayVPCAttachment) bool {
			return item.VpcId == *vpcID && item.TransitGatewayId == tgwID &&
				!isAttachmentTerminal(item.State)
		})
	if err != nil {
		return err
	}

	if current != nil {
		log.Info("shoot-level TGW VPC attachment already exists", "attachmentId", current.TransitGatewayAttachmentId)
		c.state.Set(IdentifierShootTransitGatewayAttachment, current.TransitGatewayAttachmentId)
	} else {
		log.Info("creating shoot-level TGW VPC attachment", "tgwId", tgwID, "vpcId", *vpcID)
		created, err := c.client.CreateTransitGatewayVPCAttachment(ctx, &awsclient.TransitGatewayVPCAttachment{
			TransitGatewayId: tgwID,
			VpcId:            *vpcID,
			SubnetIds:        subnetIDs,
			Tags:             tags,
		})
		if err != nil {
			code := awsclient.GetAWSAPIErrorCode(err)
			if code != "DuplicateTransitGatewayAttachment" {
				return fmt.Errorf("failed to create shoot-level TGW VPC attachment: %w", err)
			}
			log.Info("shoot-level TGW attachment already exists (duplicate), looking up by VPC ID")
			allAtts, listErr := c.client.ListTransitGatewayVPCAttachments(ctx, tgwID)
			if listErr != nil {
				return fmt.Errorf("failed to list TGW attachments after duplicate: %w", listErr)
			}
			for _, att := range allAtts {
				if att.VpcId == *vpcID {
					c.state.Set(IdentifierShootTransitGatewayAttachment, att.TransitGatewayAttachmentId)
					log.Info("found existing shoot VPC attachment", "attachmentId", att.TransitGatewayAttachmentId)
					break
				}
			}
			if c.state.Get(IdentifierShootTransitGatewayAttachment) == nil {
				return fmt.Errorf("DuplicateTransitGatewayAttachment but could not find shoot VPC attachment for %s", *vpcID)
			}
		} else {
			log.Info("created shoot-level TGW VPC attachment", "attachmentId", created.TransitGatewayAttachmentId)
			c.state.Set(IdentifierShootTransitGatewayAttachment, created.TransitGatewayAttachmentId)
		}
	}

	// Shoot-level TGW route table management (mode-dependent).
	createdID := *c.state.Get(IdentifierShootTransitGatewayAttachment)

	if shootTGW.IsolationMode == "shared" && shootTGW.RouteTableID != nil {
		// Shared mode: associate AND propagate to the single RT.
		if err := c.associateTGWRouteTable(ctx, log, c.client, *shootTGW.RouteTableID, createdID, "shoot-level TGW (shared)"); err != nil {
			return err
		}
		if err := c.enableTGWPropagation(ctx, log, c.client, *shootTGW.RouteTableID, createdID, "shoot-level TGW (shared)"); err != nil {
			return err
		}
	} else {
		// Hub-spoke mode (default): associate with spoke, propagate to hub.
		if shootTGW.SpokeRouteTableID != nil {
			if err := c.associateTGWRouteTable(ctx, log, c.client, *shootTGW.SpokeRouteTableID, createdID, "shoot-level TGW (spoke)"); err != nil {
				return err
			}
		}
		if shootTGW.HubRouteTableID != nil {
			if err := c.enableTGWPropagation(ctx, log, c.client, *shootTGW.HubRouteTableID, createdID, "shoot-level TGW (hub)"); err != nil {
				return err
			}
		}
		// NOTE: Shoot VPCs must NOT propagate to spoke RT — doing so breaks shoot isolation.
	}

	return nil
}

// discoverGlobalVPCCIDRs fills in CIDRs for any globalVPC that has an empty CIDRs list
// by looking up the VPC's primary CIDR via the attachment's VpcId.
func (c *FlowContext) discoverGlobalVPCCIDRs(ctx context.Context, log logr.Logger) error {
	if !c.isSeedTGWEnabled() {
		return nil
	}

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	for i := range c.resolvedEffectiveGlobalVPCs {
		gvpc := &c.resolvedEffectiveGlobalVPCs[i]
		if len(gvpc.CIDRs) > 0 {
			continue
		}

		// Determine VPC ID: either from managed config (VpcID) or by looking up the attachment.
		var vpcID string
		if gvpc.VpcID != nil && *gvpc.VpcID != "" {
			// Managed mode — VPC ID is directly in config.
			vpcID = *gvpc.VpcID
		} else if gvpc.AttachmentID != nil && *gvpc.AttachmentID != "" {
			// Referenced mode — look up attachment to get VpcId.
			attachment, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, *gvpc.AttachmentID)
			if err != nil {
				log.Error(err, "WARNING: failed to get globalVPC attachment for CIDR discovery — skipping", "name", gvpc.Name, "attachmentId", *gvpc.AttachmentID)
				continue
			}
			if attachment == nil {
				log.Info("WARNING: globalVPC attachment not found — skipping CIDR discovery (routes for this VPC will not be generated)", "name", gvpc.Name, "attachmentId", *gvpc.AttachmentID)
				continue
			}
			vpcID = attachment.VpcId
		} else {
			log.Info("WARNING: globalVPC has no attachmentId or vpcId — skipping CIDR discovery", "name", gvpc.Name)
			continue
		}

		// Look up the VPC to get primary CIDR.
		// Use the globalVPC's own client (may be cross-account via credentialsRef).
		vpcClient, clientErr := c.getGlobalVPCClient(ctx, gvpc)
		if clientErr != nil {
			log.Error(clientErr, "WARNING: failed to get client for globalVPC CIDR discovery — skipping", "name", gvpc.Name)
			continue
		}
		vpc, err := vpcClient.GetVpc(ctx, vpcID)
		if err != nil {
			log.Error(err, "WARNING: failed to get VPC for globalVPC CIDR discovery — skipping", "name", gvpc.Name, "vpcId", vpcID)
			continue
		}
		if vpc == nil {
			log.Info("WARNING: VPC not found for globalVPC — skipping CIDR discovery", "name", gvpc.Name, "vpcId", vpcID)
			continue
		}

		gvpc.CIDRs = []string{vpc.CidrBlock}
		log.Info("discovered globalVPC CIDR from VPC", "name", gvpc.Name, "vpcId", vpcID, "cidr", vpc.CidrBlock)
	}

	return nil
}

// cleanupDisabledShootTransitGateway handles the case where the shoot-level TGW
// (InfrastructureConfig.Networks.TransitGateway) was previously enabled but is now
// disabled or removed. This is independent of the seed-level TGW.
// It deletes the shoot's own TGW VPC attachment and clears the state key.
func (c *FlowContext) cleanupDisabledShootTransitGateway(ctx context.Context) error {
	log := LogFromContext(ctx)
	log.Info("shoot-level TGW was previously enabled but is now disabled — cleaning up")

	shootAttachmentID := c.state.Get(IdentifierShootTransitGatewayAttachment)
	if shootAttachmentID == nil {
		return nil
	}

	current, err := c.client.GetTransitGatewayVPCAttachment(ctx, *shootAttachmentID)
	if err != nil {
		return fmt.Errorf("failed to get shoot TGW attachment for cleanup: %w", err)
	}
	if current != nil {
		if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, c.client, *shootAttachmentID); err != nil {
			return err
		}
	}
	c.state.Delete(IdentifierShootTransitGatewayAttachment)
	return nil
}

// cleanupDisabledTransitGateway handles the case where TGW was previously enabled but
// is now disabled or removed from the seed config. It:
// 1. Cleans up the VPC attachment (disassociate, disable propagation, delete)
// 2. Optionally deletes auto-created TGW + route tables (if deleteManagedOnDisable is set)
// 3. Cleans all TGW state keys
//
// This task runs AFTER ensureZones so that TGW routes have already been removed from
// shoot VPC route tables (mergeCustomRoutes returns empty when TGW is disabled).
func (c *FlowContext) cleanupDisabledTransitGateway(ctx context.Context) error {
	log := LogFromContext(ctx)

	tgwClient, err := c.getTGWClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TGW client: %w", err)
	}

	log.Info("cleanupDisabledTransitGateway: starting",
		"shoot", c.namespace,
		"seedName", c.seedName,
		"hasTGWStateResources", c.hasTGWStateResources(),
		"hasTGWConfigResources", c.hasTGWConfigResources(),
		"seedNodesCIDR", c.seedNodesCIDR,
	)

	c.event(corev1.EventTypeNormal, "TGWDisabling", "Transit Gateway disabled — cleaning up attachments and routes")
	// Step 1: Clean up this shoot's own VPC attachment.
	// Discovery-first: check state, then discover from AWS if state is empty.
	attachmentID := c.state.Get(IdentifierTransitGatewayAttachment)
	if attachmentID == nil {
		// State empty — discover from AWS by VPC ID + TGW ID
		vpcID := c.state.Get(IdentifierVPC)
		tgwID := ""
		if c.seedConfig != nil && c.seedConfig.TransitGateway != nil && c.seedConfig.TransitGateway.ID != nil {
			tgwID = *c.seedConfig.TransitGateway.ID
		}
		if vpcID != nil && tgwID != "" {
			attachments, err := tgwClient.FindTransitGatewayVPCAttachments(ctx, tgwID, *vpcID)
			if err == nil && len(attachments) > 0 {
				discovered := attachments[0].TransitGatewayAttachmentId
				log.Info("discovered shoot VPC TGW attachment from AWS", "attachmentId", discovered, "vpcId", *vpcID)
				attachmentID = &discovered
			}
		}
	}
	if attachmentID != nil {
		current, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, *attachmentID)
		if err != nil {
			return fmt.Errorf("failed to get TGW attachment for cleanup: %w", err)
		}
		if current != nil {
			spokeRT := c.state.Get(IdentifierTransitGatewaySpokeRouteTable)
			hubRT := c.state.Get(IdentifierTransitGatewayHubRouteTable)
			sharedRT := c.state.Get(IdentifierTransitGatewaySharedRouteTable)

			// Clean up shared RT associations/propagations if present.
			if sharedRT != nil {
				log.Info("disassociating TGW attachment from shared route table", "routeTableId", *sharedRT)
				if err := tgwClient.DisassociateTransitGatewayRouteTable(ctx, *sharedRT, *attachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "InvalidAssociation.NotFound" {
						return fmt.Errorf("failed to disassociate TGW attachment from shared RT: %w", err)
					}
				}
				if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, *sharedRT, *attachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
						return fmt.Errorf("failed to disable TGW shared RT propagation: %w", err)
					}
				}
			}
			// Clean up hub-spoke RT associations/propagations if present.
			if spokeRT != nil {
				log.Info("disassociating TGW attachment from spoke route table", "routeTableId", *spokeRT)
				if err := tgwClient.DisassociateTransitGatewayRouteTable(ctx, *spokeRT, *attachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "InvalidAssociation.NotFound" {
						return fmt.Errorf("failed to disassociate TGW attachment: %w", err)
					}
				}
			}
			if hubRT != nil {
				log.Info("disabling TGW propagation from hub route table", "routeTableId", *hubRT)
				if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, *hubRT, *attachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
						return fmt.Errorf("failed to disable TGW propagation: %w", err)
					}
				}
			}
			if spokeRT != nil {
				if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, *spokeRT, *attachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
						return fmt.Errorf("failed to disable TGW spoke propagation: %w", err)
					}
				}
			}

			if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, *attachmentID); err != nil {
				return err
			}
		}
		c.state.Delete(IdentifierTransitGatewayAttachment)
	}

	// Step 1b: Clean up seed VPC TGW attachment if present.
	// The state key may be nil if this is the seed shoot (state is stored in child shoot's
	// Infrastructure status, not the seed shoot's). In that case, discover the attachment
	// by searching for a TGW VPC attachment matching the seed VPC on the configured TGW.
	seedVPCAttachmentID := c.state.Get(IdentifierSeedVPCTransitGatewayAttachment)
	if seedVPCAttachmentID == nil && c.seedNodesCIDR != "" {
		log.Info("seed VPC TGW attachment not in state — attempting discovery", "seedNodesCIDR", c.seedNodesCIDR)
		tgwID := ""
		if c.seedConfig != nil && c.seedConfig.TransitGateway != nil && c.seedConfig.TransitGateway.ID != nil {
			tgwID = *c.seedConfig.TransitGateway.ID
		}
		if tgwID != "" {
			seedVpcID, _, err := c.discoverSeedVPC(ctx, log)
			if err == nil && seedVpcID != "" {
				attachments, err := tgwClient.FindTransitGatewayVPCAttachments(ctx, tgwID, seedVpcID)
				if err == nil && len(attachments) > 0 {
					discovered := attachments[0].TransitGatewayAttachmentId
					log.Info("discovered seed VPC TGW attachment from AWS", "attachmentId", discovered, "seedVpcId", seedVpcID)
					seedVPCAttachmentID = &discovered
				}
			}
		}
	}
	if seedVPCAttachmentID != nil {
		current, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, *seedVPCAttachmentID)
		if err != nil {
			return fmt.Errorf("failed to get seed VPC TGW attachment for cleanup: %w", err)
		}
		if current != nil {
			// Get RT IDs from state, falling back to config if state is empty
			// (state may be empty for seed shoot — see Step 1b discovery comment).
			spokeRT := c.state.Get(IdentifierTransitGatewaySpokeRouteTable)
			hubRT := c.state.Get(IdentifierTransitGatewayHubRouteTable)
			sharedRT := c.state.Get(IdentifierTransitGatewaySharedRouteTable)
			if c.seedConfig != nil && c.seedConfig.TransitGateway != nil {
				tgw := c.seedConfig.TransitGateway
				if spokeRT == nil && tgw.SpokeRouteTableID != nil {
					spokeRT = tgw.SpokeRouteTableID
				}
				if hubRT == nil && tgw.HubRouteTableID != nil {
					hubRT = tgw.HubRouteTableID
				}
				if sharedRT == nil && tgw.RouteTableID != nil {
					sharedRT = tgw.RouteTableID
				}
			}

			// Clean up shared RT if present.
			if sharedRT != nil {
				log.Info("disassociating seed VPC TGW attachment from shared route table", "routeTableId", *sharedRT)
				if err := tgwClient.DisassociateTransitGatewayRouteTable(ctx, *sharedRT, *seedVPCAttachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "InvalidAssociation.NotFound" {
						return fmt.Errorf("failed to disassociate seed VPC TGW from shared RT: %w", err)
					}
				}
				if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, *sharedRT, *seedVPCAttachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
						return fmt.Errorf("failed to disable seed VPC shared RT propagation: %w", err)
					}
				}
			}
			// Clean up hub-spoke RTs if present.
			if hubRT != nil {
				log.Info("disassociating seed VPC TGW attachment from hub route table", "routeTableId", *hubRT)
				if err := tgwClient.DisassociateTransitGatewayRouteTable(ctx, *hubRT, *seedVPCAttachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "InvalidAssociation.NotFound" {
						return fmt.Errorf("failed to disassociate seed VPC TGW attachment: %w", err)
					}
				}
			}
			if hubRT != nil {
				if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, *hubRT, *seedVPCAttachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
						return fmt.Errorf("failed to disable seed VPC hub propagation: %w", err)
					}
				}
			}
			if spokeRT != nil {
				if err := tgwClient.DisableTransitGatewayRouteTablePropagation(ctx, *spokeRT, *seedVPCAttachmentID); err != nil {
					if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.NotFound" {
						return fmt.Errorf("failed to disable seed VPC spoke propagation: %w", err)
					}
				}
			}

			// Clean up all TGW routes in seed VPC route tables.
			tgwIDForCleanup := ""
			if tgwIDVal := c.state.Get(IdentifierTransitGatewayID); tgwIDVal != nil {
				tgwIDForCleanup = *tgwIDVal
			}
			// Fall back to config for TGW ID when state is empty.
			if tgwIDForCleanup == "" && c.seedConfig != nil && c.seedConfig.TransitGateway != nil && c.seedConfig.TransitGateway.ID != nil {
				tgwIDForCleanup = *c.seedConfig.TransitGateway.ID
			}
			c.cleanupSeedVPCRoutes(ctx, log, "", tgwIDForCleanup)

			if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, *seedVPCAttachmentID); err != nil {
				return err
			}
		}
		c.state.Delete(IdentifierSeedVPCTransitGatewayAttachment)
	}

	// Step 1c: Clean up runtime VPC TGW attachment if present (managed TGW mode only).
	// This removes the runtime VPC attachment from the managed TGW and cleans up routes
	// in the runtime VPC that pointed to this managed TGW.
	runtimeVPCAttachmentID := c.state.Get(IdentifierRuntimeVPCTransitGatewayAttachment)
	if runtimeVPCAttachmentID != nil {
		current, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, *runtimeVPCAttachmentID)
		if err != nil {
			log.Error(err, "failed to get runtime VPC TGW attachment for cleanup — continuing", "attachmentId", *runtimeVPCAttachmentID)
		}
		if current != nil {
			// Clean up routes in runtime VPC before deleting attachment.
			runtimeVPCID := c.state.Get(IdentifierRuntimeVPCID)
			tgwIDForCleanup := ""
			if tgwIDVal := c.state.Get(IdentifierTransitGatewayID); tgwIDVal != nil {
				tgwIDForCleanup = *tgwIDVal
			}
			if runtimeVPCID != nil && tgwIDForCleanup != "" {
				runtimeClient, clientErr := c.getSeedVPCClient(ctx)
				if clientErr == nil {
					runtimeRTs, rtErr := runtimeClient.FindRouteTablesByFilters(ctx, []ec2types.Filter{
						{Name: ptr.To("vpc-id"), Values: []string{*runtimeVPCID}},
					})
					if rtErr == nil {
						for _, rt := range runtimeRTs {
							if !strings.Contains(rt.Tags["Name"], "private") {
								continue
							}
							for _, r := range rt.Routes {
								if r.TransitGatewayId != nil && *r.TransitGatewayId == tgwIDForCleanup {
									cidr := "<unknown>"
									if r.DestinationCidrBlock != nil {
										cidr = *r.DestinationCidrBlock
									}
									log.Info("removing managed TGW route from runtime VPC", "routeTableId", rt.RouteTableId, "cidr", cidr)
									_ = runtimeClient.DeleteRoute(ctx, rt.RouteTableId, &awsclient.Route{
										DestinationCidrBlock: r.DestinationCidrBlock,
									})
								}
							}
						}
					}
				}
			}

			log.Info("deleting runtime VPC TGW attachment", "attachmentId", *runtimeVPCAttachmentID)
			if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, *runtimeVPCAttachmentID); err != nil {
				log.Error(err, "failed to delete runtime VPC TGW attachment — continuing")
			}
		}
		c.state.Delete(IdentifierRuntimeVPCTransitGatewayAttachment)
		c.state.Delete(IdentifierRuntimeVPCID)
		c.state.Delete(IdentifierRuntimeVPCCIDR)
	}

	// Step 1d: Clean up shoot-level TGW attachment if present.
	shootAttachmentID := c.state.Get(IdentifierShootTransitGatewayAttachment)
	if shootAttachmentID != nil {
		current, err := tgwClient.GetTransitGatewayVPCAttachment(ctx, *shootAttachmentID)
		if err != nil {
			return fmt.Errorf("failed to get shoot TGW attachment for cleanup: %w", err)
		}
		if current != nil {
			if err := c.deleteAndWaitForTransitGatewayVPCAttachment(ctx, log, tgwClient, *shootAttachmentID); err != nil {
				return err
			}
		}
		c.state.Delete(IdentifierShootTransitGatewayAttachment)
	}

	// Step 2: Determine whether to delete managed TGW + route tables.
	deleteManagedResources := c.shouldDeleteManagedOnDisable()
	tgwManaged := c.state.Get(IdentifierTransitGatewayManaged)
	tgwID := c.state.Get(IdentifierTransitGatewayID)

	if !deleteManagedResources {
		log.Info("deleteManagedOnDisable is false (or config removed) — keeping TGW and route tables")
		// Clean attachment state only, keep TGW/RT state for reference.
		c.state.Delete(IdentifierTransitGatewayAttachment)
		return nil
	}

	if tgwManaged == nil || *tgwManaged != "true" {
		log.Info("TGW is referenced (not managed) — skipping TGW/route table deletion, cleaning state")
		c.cleanupTGWState()
		return nil
	}

	if tgwID == nil {
		log.Info("no TGW ID in state — nothing to delete")
		c.cleanupTGWState()
		return nil
	}

	// Check for remaining attachments on this TGW before deleting it.
	remainingAttachments, err := tgwClient.ListTransitGatewayVPCAttachments(ctx, *tgwID)
	if err != nil {
		return fmt.Errorf("failed to list TGW attachments: %w", err)
	}
	if len(remainingAttachments) > 0 {
		log.Info("WARNING: TGW still has active VPC attachments from other shoots/VPCs — skipping TGW deletion",
			"tgwId", *tgwID, "remainingAttachments", len(remainingAttachments))
		// Clean our state but leave TGW alive for other consumers.
		c.cleanupTGWState()
		return nil
	}

	// Step 3: Delete managed route tables, then TGW.
	// Delete shared RT if present (shared mode).
	sharedRT := c.state.Get(IdentifierTransitGatewaySharedRouteTable)
	sharedRTManaged := c.state.Get(IdentifierTransitGatewaySharedRouteTableManaged)
	if sharedRT != nil && sharedRTManaged != nil && *sharedRTManaged == "true" {
		log.Info("deleting managed shared route table", "routeTableId", *sharedRT)
		if err := tgwClient.DeleteTransitGatewayRouteTable(ctx, *sharedRT); err != nil {
			return fmt.Errorf("failed to delete shared route table: %w", err)
		}
	}
	// Delete hub/spoke RTs if present (hub-spoke mode).
	spokeRT := c.state.Get(IdentifierTransitGatewaySpokeRouteTable)
	hubRT := c.state.Get(IdentifierTransitGatewayHubRouteTable)
	spokeRTManaged := c.state.Get(IdentifierTransitGatewaySpokeRouteTableManaged)
	hubRTManaged := c.state.Get(IdentifierTransitGatewayHubRouteTableManaged)

	if spokeRT != nil && spokeRTManaged != nil && *spokeRTManaged == "true" {
		log.Info("deleting managed spoke route table", "routeTableId", *spokeRT)
		if err := tgwClient.DeleteTransitGatewayRouteTable(ctx, *spokeRT); err != nil {
			return fmt.Errorf("failed to delete spoke route table: %w", err)
		}
	}
	if hubRT != nil && hubRTManaged != nil && *hubRTManaged == "true" {
		log.Info("deleting managed hub route table", "routeTableId", *hubRT)
		if err := tgwClient.DeleteTransitGatewayRouteTable(ctx, *hubRT); err != nil {
			return fmt.Errorf("failed to delete hub route table: %w", err)
		}
	}

	log.Info("deleting managed transit gateway", "tgwId", *tgwID)
	if err := tgwClient.DeleteTransitGateway(ctx, *tgwID); err != nil {
		return fmt.Errorf("failed to delete transit gateway: %w", err)
	}

	c.cleanupTGWState()
	log.Info("TGW cleanup complete — all managed resources deleted")
	return nil
}

// cleanupTGWState removes all TGW-related keys from infrastructure state.
func (c *FlowContext) cleanupTGWState() {
	c.state.Delete(IdentifierTransitGatewayID)
	c.state.Delete(IdentifierTransitGatewayHubRouteTable)
	c.state.Delete(IdentifierTransitGatewaySpokeRouteTable)
	c.state.Delete(IdentifierTransitGatewayAttachment)
	c.state.Delete(IdentifierShootTransitGatewayAttachment)
	c.state.Delete(IdentifierSeedVPCTransitGatewayAttachment)
	c.state.Delete(IdentifierTransitGatewayManaged)
	c.state.Delete(IdentifierTransitGatewayHubRouteTableManaged)
	c.state.Delete(IdentifierTransitGatewaySpokeRouteTableManaged)
	c.state.Delete(IdentifierTransitGatewaySharedRouteTable)
	c.state.Delete(IdentifierTransitGatewaySharedRouteTableManaged)
	c.state.Delete(IdentifierShootVPCCIDR)
	c.state.Delete(IdentifierRuntimeVPCTransitGatewayAttachment)
	c.state.Delete(IdentifierRuntimeVPCID)
	c.state.Delete(IdentifierRuntimeVPCCIDR)
	// Clean up managed globalVPC attachment state keys. Use the helper to hit
	// both the hierarchical child and any legacy literal-slash root entries.
	for _, name := range c.listGlobalVPCAttachmentNames() {
		c.deleteGlobalVPCAttachmentState(name)
	}
}

func (c *FlowContext) deletePrivateRoutingTable(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		log := LogFromContext(ctx)
		child := c.getSubnetZoneChild(zoneName)
		if child.Get(IdentifierZoneRouteTable) == nil {
			return nil
		}
		tags := c.commonTagsWithSuffix(fmt.Sprintf("private-%s", zoneName))
		current, err := FindExisting(ctx, child.Get(IdentifierZoneRouteTable), tags, c.client.GetRouteTable,
			c.client.FindRouteTablesByTags, func(item *awsclient.RouteTable) bool {
				return c.isVpcMatchingState(item.VpcId)
			})
		if err != nil {
			return err
		}
		if current != nil {
			log.Info("deleting...", "RouteTableId", current.RouteTableId)
			if err := c.client.DeleteRouteTable(ctx, current.RouteTableId); err != nil {
				return err
			}
		}
		child.Delete(IdentifierZoneRouteTable)
		return nil
	}
}

func (c *FlowContext) routingAssociationSpecs() []routeTableAssociationSpec {
	return []routeTableAssociationSpec{
		{IdentifierZoneSubnetPublic, IdentifierZoneSubnetPublicRouteTableAssoc, false},
		{IdentifierZoneSubnetPrivate, IdentifierZoneSubnetPrivateRouteTableAssoc, true},
		{IdentifierZoneSubnetWorkers, IdentifierZoneSubnetWorkersRouteTableAssoc, true},
	}
}

// validateAndPruneRoutingTableAssocState checks whether the routing table associations stored in the state
// still exist in AWS. If not, it removes them from the state.
func (c *FlowContext) validateAndPruneRoutingTableAssocState(ctx context.Context, zoneName string, specs []routeTableAssociationSpec) error {
	child := c.getSubnetZoneChild(zoneName)
	log := LogFromContext(ctx)

	// should validate only if at least one association ID is present in state
	if !hasRouteTableAssociationInState(child.Get, specs) {
		return nil
	}

	subnetIDs := make([]string, 0, len(specs))
	for _, spec := range specs {
		id := child.Get(spec.subnetKey)
		if id == nil {
			return fmt.Errorf("missing subnet id for key %s", spec.subnetKey)
		}
		subnetIDs = append(subnetIDs, *id)
	}

	vpc := c.state.Get(IdentifierVPC)
	if vpc == nil {
		return fmt.Errorf("VPC ID not found in state")
	}

	routeTableAssociations, err := c.client.GetRouteTableAssociationIDs(ctx, *vpc, subnetIDs)
	if err != nil {
		return err
	}

	for _, spec := range specs {
		if assocID := child.Get(spec.assocKey); assocID != nil && !slices.Contains(routeTableAssociations, *assocID) {
			log.Info("route table association not found in AWS, removing from state",
				"AssociationID", *assocID)
			child.Delete(spec.assocKey)
		}
	}
	return nil
}

func (c *FlowContext) ensureRoutingTableAssociations(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		specs := c.routingAssociationSpecs()

		err := c.validateAndPruneRoutingTableAssocState(ctx, zoneName, specs)
		if err != nil {
			return err
		}

		for _, spec := range specs {
			err := c.ensureZoneRoutingTableAssociation(ctx, zoneName, spec.zoneRouteTable, spec.subnetKey, spec.assocKey)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *FlowContext) ensureZoneRoutingTableAssociation(ctx context.Context, zoneName string,
	zoneRouteTable bool, subnetKey, assocKey string) error {
	child := c.getSubnetZoneChild(zoneName)
	assocID := child.Get(assocKey)
	if assocID != nil {
		return nil
	}
	subnetID := child.Get(subnetKey)
	if subnetID == nil {
		return fmt.Errorf("missing subnet id")
	}
	var obj any
	if zoneRouteTable {
		obj = child.GetObject(ObjectZoneRouteTable)
	} else {
		obj = c.state.GetObject(ObjectMainRouteTable)
	}
	if obj == nil {
		return fmt.Errorf("missing route table object")
	}
	routeTable := obj.(*awsclient.RouteTable)
	for _, assoc := range routeTable.Associations {
		if reflect.DeepEqual(assoc.SubnetId, subnetID) {
			child.Set(assocKey, assoc.RouteTableAssociationId)
			return nil
		}
	}
	log := LogFromContext(ctx)
	log.Info("creating...")
	assocID, err := c.client.CreateRouteTableAssociation(ctx, routeTable.RouteTableId, *subnetID)
	if err != nil {
		return err
	}
	child.Set(assocKey, *assocID)
	return nil
}

func (c *FlowContext) ensureVPCEndpointsRoutingTableAssociations(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		for _, endpoint := range c.config.Networks.VPC.GatewayEndpoints {
			if err := c.ensureVPCEndpointZoneRoutingTableAssociation(ctx, zoneName, endpoint); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *FlowContext) ensureVPCEndpointZoneRoutingTableAssociation(ctx context.Context, zoneName, endpointName string) error {
	child := c.getSubnetZoneChild(zoneName)
	subnetID := child.Get(IdentifierZoneSubnetWorkers)
	if subnetID == nil {
		return fmt.Errorf("missing subnet id")
	}
	vpcEndpointID := c.state.GetChild(ChildIdVPCEndpoints).Get(endpointName)
	if vpcEndpointID == nil {
		return fmt.Errorf("missing VPC endpoint: %s", endpointName)
	}
	obj := child.GetObject(ObjectZoneRouteTable)
	if obj == nil {
		return fmt.Errorf("missing route table object")
	}
	routeTable := obj.(*awsclient.RouteTable)
	for _, route := range routeTable.Routes {
		if reflect.DeepEqual(route.GatewayId, vpcEndpointID) {
			return nil
		}
	}
	log := LogFromContext(ctx)
	log.Info("creating...", "endpoint", endpointName)

	return c.client.CreateVpcEndpointRouteTableAssociation(ctx, routeTable.RouteTableId, *vpcEndpointID)
}

func (c *FlowContext) deleteRoutingTableAssociations(zoneName string) flow.TaskFn {
	return func(ctx context.Context) error {
		specs := c.routingAssociationSpecs()

		for _, spec := range specs {
			err := c.deleteZoneRoutingTableAssociation(ctx, zoneName, spec.zoneRouteTable, spec.subnetKey, spec.assocKey)
			if err != nil {
				return err
			}
		}

		return nil
	}
}

func (c *FlowContext) deleteZoneRoutingTableAssociation(ctx context.Context, zoneName string,
	zoneRouteTable bool, subnetKey, assocKey string) error {
	child := c.getSubnetZoneChild(zoneName)
	subnetID := child.Get(subnetKey)
	assocID := child.Get(assocKey)

	if assocID == nil && subnetID != nil {
		// unclear situation: load route table to search for association
		var routeTableID *string
		if zoneRouteTable {
			routeTableID = child.Get(IdentifierZoneRouteTable)
		} else {
			routeTableID = c.state.Get(IdentifierMainRouteTable)
		}
		if routeTableID != nil {
			routeTable, err := c.client.GetRouteTable(ctx, *routeTableID)
			if err != nil {
				return err
			}
			// if not found routeTable might be nil
			if routeTable != nil {
				for _, assoc := range routeTable.Associations {
					if reflect.DeepEqual(subnetID, assoc.SubnetId) {
						assocID = &assoc.RouteTableAssociationId
						break
					}
				}
			}
		}
	}

	log := LogFromContext(ctx)
	if assocID == nil {
		log.Info("No association ID found, nothing to delete", "SubnetID", subnetID)
		return nil
	}
	log.Info("deleting...", "RouteTableAssociationId", *assocID)
	if err := c.client.DeleteRouteTableAssociation(ctx, *assocID); err != nil {
		return err
	}
	child.Delete(assocKey)
	return nil
}

func (c *FlowContext) ensureIAMRole(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := &awsclient.IAMRole{
		RoleName: fmt.Sprintf("%s-nodes", c.namespace),
		Path:     "/",
		AssumeRolePolicyDocument: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`,
	}
	current, err := c.client.GetIAMRole(ctx, desired.RoleName)
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(NameIAMRole, current.RoleName)
		c.state.Set(ARNIAMRole, current.ARN)
		if _, err := c.updater.UpdateIAMRole(ctx, desired, current); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateIAMRole(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(NameIAMRole, created.RoleName)
		c.state.Set(ARNIAMRole, created.ARN)
	}

	return nil
}

func (c *FlowContext) ensureIAMInstanceProfile(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := &awsclient.IAMInstanceProfile{
		InstanceProfileName: fmt.Sprintf("%s-nodes", c.namespace),
		Path:                "/",
		RoleName:            fmt.Sprintf("%s-nodes", c.namespace),
	}
	current, err := c.client.GetIAMInstanceProfile(ctx, desired.InstanceProfileName)
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(NameIAMInstanceProfile, current.InstanceProfileName)
		if _, err := c.updater.UpdateIAMInstanceProfile(ctx, desired, current); err != nil {
			return err
		}
	} else {
		log.Info("creating...")
		created, err := c.client.CreateIAMInstanceProfile(ctx, desired)
		if err != nil {
			return err
		}
		c.state.Set(NameIAMInstanceProfile, created.InstanceProfileName)
		if _, err := c.updater.UpdateIAMInstanceProfile(ctx, desired, created); err != nil {
			return err
		}
	}

	return nil
}

const iamRolePolicyTemplate = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Resource": [
        "*"
      ]
    }{{ if .enableEfsAccess }},
	{
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:CreateAccessPoint",
        "elasticfilesystem:DeleteAccessPoint",
        "elasticfilesystem:TagResource",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": [
        "*"
      ]
	}{{ end }}{{ if .enableECRAccess }},
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:BatchGetImage"
      ],
      "Resource": [
        "*"
      ]
    }{{ end }}
  ]
}`

func (c *FlowContext) ensureIAMRolePolicy(ctx context.Context) error {
	log := LogFromContext(ctx)
	t, err := template.New("policyDocument").Parse(iamRolePolicyTemplate)
	if err != nil {
		return fmt.Errorf("parsing policyDocument template failed: %s", err)
	}
	var buffer bytes.Buffer
	templateData := map[string]any{
		"enableECRAccess": ptr.Deref(c.config.EnableECRAccess, true),
		"enableEfsAccess": ptr.Deref(c.config.ElasticFileSystem, aws.ElasticFileSystemConfig{}).Enabled,
	}
	if err := t.Execute(&buffer, templateData); err != nil {
		return fmt.Errorf("executing policyDocument template failed: %s", err)
	}

	name := fmt.Sprintf("%s-nodes", c.namespace)
	desired := &awsclient.IAMRolePolicy{
		PolicyName:     name,
		RoleName:       name,
		PolicyDocument: buffer.String(),
	}
	current, err := c.client.GetIAMRolePolicy(ctx, desired.PolicyName, desired.RoleName)
	if err != nil {
		return err
	}

	if current != nil {
		c.state.Set(NameIAMRolePolicy, name)
		if current.PolicyDocument != desired.PolicyDocument {
			if err := c.client.PutIAMRolePolicy(ctx, desired); err != nil {
				return err
			}
		}
	} else {
		log.Info("creating...")
		if err := c.client.PutIAMRolePolicy(ctx, desired); err != nil {
			return err
		}
		c.state.Set(NameIAMRolePolicy, name)
	}

	return nil
}

func (c *FlowContext) ensureKeyPair(ctx context.Context) error {
	log := LogFromContext(ctx)
	desired := &awsclient.KeyPairInfo{
		Tags:    c.commonTags,
		KeyName: fmt.Sprintf("%s-ssh-publickey", c.namespace),
	}
	current, err := c.client.GetKeyPair(ctx, desired.KeyName)
	if err != nil {
		return err
	}

	if len(c.infraSpec.SSHPublicKey) == 0 {
		return c.deleteKeyPair(ctx)
	}

	specFingerprint := fmt.Sprintf("%x", md5.Sum(c.infraSpec.SSHPublicKey)) // #nosec G401 -- No cryptographic context.
	if current != nil {
		// check for foreign key replacement
		if fingerprint := c.state.Get(KeyPairFingerprint); fingerprint == nil || *fingerprint != current.KeyFingerprint {
			log.Info("deleting as modified by unknown")
			if err := c.client.DeleteKeyPair(ctx, current.KeyName); err != nil {
				return err
			}
			current = nil
		}
	}
	if current != nil {
		// check for key replacement in spec
		if fingerprint := c.state.Get(KeyPairSpecFingerprint); fingerprint == nil || *fingerprint != specFingerprint {
			log.Info("deleting as replaced in spec")
			if err := c.client.DeleteKeyPair(ctx, current.KeyName); err != nil {
				return err
			}
			current = nil
		}
	}

	if current != nil {
		c.state.Set(NameKeyPair, desired.KeyName)
	} else {
		log.Info("creating")
		info, err := c.client.ImportKeyPair(ctx, desired.KeyName, c.infraSpec.SSHPublicKey, c.commonTags)
		if err != nil {
			return err
		}
		c.state.Set(NameKeyPair, info.KeyName)
		c.state.Set(KeyPairFingerprint, info.KeyFingerprint)
		c.state.Set(KeyPairSpecFingerprint, specFingerprint)
	}

	return nil
}

func (c *FlowContext) ensureEfs(ctx context.Context) error {
	err := c.ensureEfsCreateFileSystem(ctx)
	if err != nil {
		return err
	}

	return c.ensureEfsMountTargets(ctx)
}

func (c *FlowContext) ensureEfsCreateFileSystem(ctx context.Context) error {
	log := LogFromContext(ctx)

	current, err := FindExisting(ctx, c.state.Get(IdentifierManagedEfsID), c.commonTags.AddManagedTag(),
		c.client.GetFileSystem, c.client.FindFileSystemsByTags)
	if err != nil {
		return fmt.Errorf("failed to find managed EFS file system: %w", err)
	}

	// check for user provided EFS file system
	if c.config.ElasticFileSystem.ID != nil && current != nil {
		if err := c.deleteEfs(ctx); err != nil {
			return fmt.Errorf("failed to delete managed EFS file system: %w", err)
		}
		c.state.Delete(IdentifierManagedEfsID)
	}
	if c.config.ElasticFileSystem.ID != nil {
		return nil
	}

	// check if we already created an EFS file system
	if current != nil {
		c.state.Set(IdentifierManagedEfsID, current.FileSystemId)
		return nil
	}

	desired := awsclient.ElasticFileSystem{
		Tags:      c.commonTags.AddManagedTag(),
		Encrypted: true,
	}

	fileSystemID, err := c.client.CreateFileSystem(ctx, desired, c.shootUUID)
	if err != nil {
		return err
	}

	c.state.Set(IdentifierManagedEfsID, fileSystemID)
	log.Info("created file system", "id", fileSystemID)
	return nil
}

func (c *FlowContext) ensureEfsMountTargets(ctx context.Context) error {
	log := LogFromContext(ctx)

	var efsID string
	switch {
	case c.config.ElasticFileSystem.ID != nil:
		efsID = *c.config.ElasticFileSystem.ID
	case c.state.Get(IdentifierManagedEfsID) != nil:
		efsID = *c.state.Get(IdentifierManagedEfsID)
	default:
		return fmt.Errorf("trying to ensure efs mount targets, but efs id is not set")
	}

	securityGroupID := c.state.Get(IdentifierNodesSecurityGroup)
	if securityGroupID == nil {
		return fmt.Errorf("security group not found in state")
	}

	mountTargetsToCreate := make(map[string]awsclient.MountTargetEFS)
	childMountTargets := c.state.GetChild(ChildEfsMountTargets)
	existingMountTargetKeys := childMountTargets.Keys()
	childZones := c.state.GetChild(ChildIdZones)

	for _, zoneKey := range childZones.GetChildrenKeys() {
		zoneChild := childZones.GetChild(zoneKey)
		// every zone must have a subnet for workers, we use this subnet for the mount target
		subnetID := zoneChild.Get(IdentifierZoneSubnetWorkers)
		if subnetID == nil {
			return fmt.Errorf("subnet not found in state")
		}

		mountInput := awsclient.MountTargetEFS{
			FileSystemID:     efsID,
			SubnetID:         *subnetID,
			SecurityGroupIDs: []string{*securityGroupID},
			IpAddressType:    string(toEfsIpAddressType(c.getIpFamilies())),
		}
		mountKey := fmt.Sprintf("%s_%s_%s", efsID, *subnetID, *securityGroupID)
		mountTargetsToCreate[mountKey] = mountInput

		if slices.Contains(existingMountTargetKeys, mountKey) {
			continue
		}

		// check if mount target already exists but was not in state
		mountTargetOutput, err := c.client.GetMountTargetsEfs(ctx, efsID)
		if err != nil {
			return fmt.Errorf("failed to describe mount targets for EFS %s: %w", efsID, err)
		}
		if mountTargetOutput != nil && len(mountTargetOutput.MountTargets) > 0 {
			containsSubnet, mountTargetID := mountTargetsContainSubnet(mountTargetOutput.MountTargets, *subnetID)
			if containsSubnet {
				log.Info("found existing EFS mount target", "MountTargetId", mountTargetID, "SubnetId", *subnetID)
				childMountTargets.Set(mountKey, mountTargetID)
				continue
			}
		}

		log.Info("creating EFS mount target", "SubnetId", mountInput.SubnetID)
		mountTargetID, err := c.client.CreateMountTargetEfs(ctx, mountInput)
		if err != nil {
			return err
		}

		log.Info("created EFS mount target ID", "mountTargetID", mountTargetID)
		childMountTargets.Set(mountKey, mountTargetID)
	}

	// delete unused mount targets
	for _, existingMountTargetKey := range existingMountTargetKeys {
		if _, ok := mountTargetsToCreate[existingMountTargetKey]; ok {
			continue
		}

		// this mount target is not in the list of mount targets to create, so we delete it
		mountTargetID := childMountTargets.Get(existingMountTargetKey)
		if mountTargetID == nil {
			return fmt.Errorf("mount target id not found in state for key %s", existingMountTargetKey)
		}
		err := c.client.DeleteMountTargetEfs(ctx, *mountTargetID)
		if err != nil {
			return fmt.Errorf("failed to delete mount target id %s: %w", *mountTargetID, err)
		}
		childMountTargets.Delete(existingMountTargetKey)
	}

	return nil
}

func (c *FlowContext) getSubnetZoneChildByItem(item *awsclient.Subnet) Whiteboard {
	return c.getSubnetZoneChild(getZoneName(item))
}

func (c *FlowContext) getSubnetZoneChild(zoneName string) Whiteboard {
	return c.state.GetChild(ChildIdZones).GetChild(zoneName)
}

func (c *FlowContext) getSubnetKey(item *awsclient.Subnet) (string, string, error) {
	zone := c.getZone(item)
	// With IPv6 we don't have configuration for zone.Workers and zone.Internal.
	// In that case, we get the subnetKey comparing the name tag.
	if zone == nil || !containsIPv4(c.getIpFamilies()) {
		// zone may have been deleted from spec, need to find subnetKey on other ways
		zoneName := item.AvailabilityZone
		if item.SubnetId != "" {
			zoneChild := c.getSubnetZoneChild(zoneName)
			for _, key := range []string{IdentifierZoneSubnetWorkers, IdentifierZoneSubnetPublic, IdentifierZoneSubnetPrivate} {
				if s := zoneChild.Get(key); s != nil && *s == item.SubnetId {
					return zoneName, key, nil
				}
			}
		}
		if item.Tags != nil && item.Tags[TagKeyName] != "" {
			value := item.Tags[TagKeyName]
			helper := c.zoneSuffixHelpers(zoneName)
			for _, key := range []string{IdentifierZoneSubnetWorkers, IdentifierZoneSubnetPublic, IdentifierZoneSubnetPrivate} {
				switch key {
				case IdentifierZoneSubnetWorkers:
					if value == fmt.Sprintf("%s-%s", c.namespace, helper.GetSuffixSubnetWorkers()) {
						return zoneName, key, nil
					}
				case IdentifierZoneSubnetPublic:
					if value == fmt.Sprintf("%s-%s", c.namespace, helper.GetSuffixSubnetPublic()) {
						return zoneName, key, nil
					}
				case IdentifierZoneSubnetPrivate:
					if value == fmt.Sprintf("%s-%s", c.namespace, helper.GetSuffixSubnetPrivate()) {
						return zoneName, key, nil
					}
				}
			}
		}
		return "", "", fmt.Errorf("could not determine subnet key for subnet %s", item.SubnetId)
	}
	switch item.CidrBlock {
	case zone.Workers:
		return zone.Name, IdentifierZoneSubnetWorkers, nil
	case zone.Public:
		return zone.Name, IdentifierZoneSubnetPublic, nil
	case zone.Internal:
		return zone.Name, IdentifierZoneSubnetPrivate, nil
	}
	return "", "", fmt.Errorf("could not determine subnet key for subnet %s", item.SubnetId)
}

func (c *FlowContext) getZone(item *awsclient.Subnet) *aws.Zone {
	zoneName := getZoneName(item)
	for _, zone := range c.config.Networks.Zones {
		if zone.Name == zoneName {
			return &zone
		}
	}
	return nil
}

// isVpcMatchingState checks if the vpcID in the state matches the provided vpcID.
func (c *FlowContext) isVpcMatchingState(vpcID *string) bool {
	// panic if VPC ID is not set in state - all panics in reconcile are recovered and returned as an error
	if c.state.Get(IdentifierVPC) == nil {
		panic("VPC ID not set in state")
	}
	// we do not adopt resources that have no VPC ID specified
	if vpcID == nil {
		return false
	}
	return *c.state.Get(IdentifierVPC) == *vpcID
}

func getZoneName(item *awsclient.Subnet) string {
	return item.AvailabilityZone
}

func cidrSubnet(baseCIDR string, newPrefixLength int, index int) (string, error) {
	_, ipNet, err := net.ParseCIDR(baseCIDR)
	if err != nil {
		return "", err
	}

	baseIP := ipNet.IP
	maskSize, addrSize := ipNet.Mask.Size()

	if newPrefixLength <= maskSize || newPrefixLength > addrSize {
		return "", fmt.Errorf("invalid new prefix length")
	}

	// #nosec: G115
	offset := big.NewInt(0).Mul(big.NewInt(int64(index)), big.NewInt(0).Lsh(big.NewInt(1), uint(addrSize-newPrefixLength)))
	subnetIP := net.IP(big.NewInt(0).Add(big.NewInt(0).SetBytes(baseIP), offset).Bytes())
	return fmt.Sprintf("%s/%d", subnetIP.String(), newPrefixLength), nil
}

// calcNextIPv6CidrBlock returns the next IPv6 /64 subnet CIDR block within the same /56 VPC range.
// It increments the 8th byte of the IP address (index 7) to generate the next subnet.
// This is used to avoid subnet conflicts when creating IPv6 subnets.
// Returns an error if the maximum index (255) is reached or the input CIDR is invalid.
func calcNextIPv6CidrBlock(currentSubnetCIDR string) (string, error) {
	ip, _, err := net.ParseCIDR(currentSubnetCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse CIDR: %v", err)
	}

	currentIndex := int(ip[7])

	if currentIndex >= 255 {
		return "", fmt.Errorf("already at maximum index (255) within /56 range")
	}

	nextIndex := currentIndex + 1

	nextIP := make(net.IP, 16)
	copy(nextIP, ip)
	// #nosec G602 -- IPv6 addresses are always 16 bytes, index 7 is safe
	nextIP[7] = byte(nextIndex)

	nextCIDR := fmt.Sprintf("%s/64", nextIP.String())

	return nextCIDR, nil
}
