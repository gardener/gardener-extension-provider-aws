// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package healthcheck

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awspkg "github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// TGWNetworkHealthy is the condition type for TGW network health.
const TGWNetworkHealthy gardencorev1beta1.ConditionType = "TGWNetworkHealthy"

// autoReconcileInitialCooldown is the starting cooldown for auto-triggered infra reconciles.
// Grows with Fibonacci backoff (1m, 1m, 2m, 3m, 5m, 8m, 13m...) on consecutive failures.
// Resets to initial when a manual reconcile clears the issue.
const autoReconcileInitialCooldown = 1 * time.Minute

// autoReconcileMaxCooldown caps the backoff to prevent extremely long waits.
const autoReconcileMaxCooldown = 15 * time.Minute

// TGWHealthChecker verifies the health of TGW networking for a shoot:
//   - All TGW VPC attachments are in 'available' state
//   - VPC route tables have no blackhole routes pointing to TGW
//   - Route table associations exist for the shoot's attachment
//
// Reports detailed diagnostic messages when unhealthy, helping operators
// identify the root cause of connectivity issues (e.g., "machines pending"
// caused by a blackhole route to a deleted managed TGW).
//
// When definitive failures are detected (blackhole routes, missing attachments),
// automatically triggers an Infrastructure reconcile with a 5-minute cooldown
// to prevent infinite loops.
// autoReconcileState tracks the backoff state for a single Infrastructure resource.
type autoReconcileState struct {
	lastTrigger time.Time
	prevDelay   time.Duration // previous Fibonacci delay
	currDelay   time.Duration // current Fibonacci delay
}

// TGWHealthChecker performs TGW network health checks for Infrastructure resources.
type TGWHealthChecker struct {
	seedClient   client.Client
	infraClient  client.Client // for annotating Infrastructure resources
	gardenReader client.Reader // for ManagedSeed detection (lookup Seed by shoot name)
	logger       logr.Logger
	backoff      map[string]*autoReconcileState // namespace/name -> backoff state
	backoffMu    sync.Mutex
}

var _ healthcheck.HealthCheck = (*TGWHealthChecker)(nil)
var _ healthcheck.SourceClient = (*TGWHealthChecker)(nil)

// NewTGWHealthChecker creates a new TGW health checker.
// The infraClient is used to annotate Infrastructure resources for auto-reconcile.
// The gardenReader (may be nil) is used to detect whether the calling shoot is a
// ManagedSeed by looking up a Seed object with the shoot's name. Same pattern as
// actuator_reconcile.go's isManagedSeedShoot detection.
func NewTGWHealthChecker(infraClient client.Client, gardenReader client.Reader) *TGWHealthChecker {
	return &TGWHealthChecker{
		infraClient:  infraClient,
		gardenReader: gardenReader,
		backoff:      make(map[string]*autoReconcileState),
	}
}

// InjectSourceClient injects the seed client.
func (h *TGWHealthChecker) InjectSourceClient(c client.Client) {
	h.seedClient = c
}

// SetLoggerSuffix sets the logger.
func (h *TGWHealthChecker) SetLoggerSuffix(provider, extension string) {
	h.logger = log.Log.WithName(fmt.Sprintf("%s-%s-healthcheck-tgw", provider, extension))
}

// Check performs the TGW network health check.
func (h *TGWHealthChecker) Check(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	// Read the Infrastructure resource.
	infra := &extensionsv1alpha1.Infrastructure{}
	if err := h.seedClient.Get(ctx, request, infra); err != nil {
		return nil, fmt.Errorf("failed to get Infrastructure: %w", err)
	}

	// Decode the infrastructure config to get VPC ID from status.
	if infra.Status.ProviderStatus == nil {
		// No status yet — infra hasn't been reconciled.
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionProgressing,
			Detail: "Infrastructure not yet reconciled — TGW health check pending",
		}, nil
	}

	// Get the seed config to check if TGW is enabled.
	// Read the Cluster resource for the seed config.
	cluster := &extensionsv1alpha1.Cluster{}
	if err := h.seedClient.Get(ctx, client.ObjectKey{Name: request.Namespace}, cluster); err != nil {
		return nil, fmt.Errorf("failed to get Cluster: %w", err)
	}

	seed, _ := extensions.SeedFromCluster(cluster)
	if seed == nil {
		// Can't read seed — skip TGW check.
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionTrue,
			Detail: "TGW not configured — health check not applicable",
		}, nil
	}

	seedConfig, _ := helper.SeedProviderConfigFromSeed(seed)
	if seedConfig == nil || seedConfig.TransitGateway == nil || !seedConfig.TransitGateway.Enabled {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionTrue,
			Detail: "TGW not enabled on this seed — health check not applicable",
		}, nil
	}

	// Create AWS client from cloudprovider secret.
	awsClient, err := awspkg.NewClientFromSecretRef(ctx, h.seedClient,
		infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: fmt.Sprintf("Failed to create AWS client for TGW health check: %v", err),
		}, nil
	}

	// Get the shoot's VPC ID from infrastructure state.
	infraState, _ := helper.InfrastructureStateFromRaw(infra.Status.State)
	if infraState == nil {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionProgressing,
			Detail: "Infrastructure state not available — TGW health check pending",
		}, nil
	}

	vpcID := ""
	for k, v := range infraState.Data {
		if k == "VPC" {
			vpcID = v
			break
		}
	}
	if vpcID == "" {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionProgressing,
			Detail: "VPC not yet created — TGW health check pending",
		}, nil
	}

	// Create TGW client for cross-account TGW operations (if TransitGatewayCredentialsRef is set).
	// Falls back to shoot client when nil (single-account).
	tgwClient := awsClient
	if seedConfig.TransitGateway.TransitGatewayCredentialsRef != nil {
		ref := seedConfig.TransitGateway.TransitGatewayCredentialsRef
		secretRef := corev1.SecretReference{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		}
		if crossClient, err := awspkg.NewClientFromSecretRef(ctx, h.seedClient, secretRef, infra.Spec.Region); err != nil {
			h.logger.Error(err, "Failed to create cross-account TGW client for health check — falling back to shoot client")
		} else {
			tgwClient = crossClient
		}
	}

	// --- Check 1: VPC attachments on the correct TGW ---
	var issues []string
	allAtts, err := tgwClient.FindTransitGatewayVPCAttachments(ctx, "", vpcID)
	if err != nil {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: fmt.Sprintf("Failed to query TGW VPC attachments: %v", err),
		}, nil
	}

	tgwID := ""
	if seedConfig.TransitGateway.ID != nil {
		tgwID = *seedConfig.TransitGateway.ID
	}

	for _, att := range allAtts {
		if att.State != "available" {
			issues = append(issues, fmt.Sprintf(
				"[Attachment Unavailable] TGW VPC attachment %s (VPC %s) is in state '%s' on TGW %s. "+
					"Impact: shoot workers may fail to connect to seed services until the attachment transitions to 'available'. "+
					"Action: reconcile Infrastructure %s/%s",
				att.TransitGatewayAttachmentId, att.VpcId, att.State, att.TransitGatewayId,
				request.Namespace, request.Name))
		}
		if tgwID != "" && att.TransitGatewayId != tgwID {
			// Only flag as "wrong TGW" if the attachment belongs to THIS shoot (tagged with
			// this shoot's namespace). The VPC may legitimately have attachments on other TGWs
			// (e.g., managed seed VPC attached to both ref TGW and managed TGW for child shoots).
			attName := att.Tags["Name"]
			shootPrefix := request.Name + "-tgw-attachment"
			if strings.Contains(attName, shootPrefix) {
				issues = append(issues, fmt.Sprintf(
					"[Wrong TGW] VPC %s has stale attachment %s on TGW %s (expected TGW %s). "+
						"Root cause: TGW mode was switched but the old attachment was not cleaned up. "+
						"Impact: shoot may be routed through the wrong TGW, causing connectivity failures or split-brain routing. "+
						"Action: reconcile Infrastructure %s/%s to remove stale attachment and create correct one",
					att.VpcId, att.TransitGatewayAttachmentId, att.TransitGatewayId, tgwID,
					request.Namespace, request.Name))
			}
		}
	}

	// Fix #106 — Managed-mode topology mismatch detection.
	//
	// In MANAGED mode (seedConfig.TransitGateway.ID == nil), the existing
	// "wrong TGW" check above is skipped because we have no explicit TGW ID
	// to compare against. That means: when a seed config flips from
	// referenced → managed (or vice versa) and the calling shoot's reconcile
	// hasn't re-attached to the new TGW yet, the shoot's attachment lingers
	// on the OLD TGW and the healthcheck silently reports healthy because
	// each shoot only inspects attachments on its own VPC. Without a
	// cross-shoot consistency check, a partial mode switch can leave child
	// shoots stuck on the previous TGW for hours.
	//
	// Detection: for each of the calling shoot's tagged attachments, check
	// the TGW it's on. The expected TGW is whichever managed TGW carries
	// the seed shoot's cluster tag (`kubernetes.io/cluster/<seedShootNS>`).
	// If the attachment's TGW lacks that tag, report drift. Skip if we
	// can't resolve a canonical managed TGW (bootstrap state, lookup
	// failure) — error on the side of silence rather than false-positives.
	if tgwID == "" {
		seedShootNS := findSeedShootNamespace(ctx, h.seedClient, seed.Name, request.Namespace)
		if seedShootNS != "" {
			canonicalTGWs := map[string]bool{}
			tgws, tgwErr := tgwClient.FindTransitGatewaysByTags(ctx,
				awsclient.Tags{fmt.Sprintf("kubernetes.io/cluster/%s", seedShootNS): "1"})
			if tgwErr == nil {
				for _, tgw := range tgws {
					canonicalTGWs[tgw.TransitGatewayId] = true
				}
			}
			if len(canonicalTGWs) > 0 {
				shootPrefix := request.Name + "-tgw-attachment"
				for _, att := range allAtts {
					if att.State != "available" {
						continue
					}
					attName := att.Tags["Name"]
					if !strings.Contains(attName, shootPrefix) {
						continue
					}
					if canonicalTGWs[att.TransitGatewayId] {
						continue
					}
					canonicalIDs := make([]string, 0, len(canonicalTGWs))
					for id := range canonicalTGWs {
						canonicalIDs = append(canonicalIDs, id)
					}
					issues = append(issues, fmt.Sprintf(
						"[Wrong TGW (managed)] VPC %s has shoot attachment %s on TGW %s but seed config is in MANAGED mode and the canonical managed TGW for this seed is one of %v. "+
							"Root cause: TGW mode was switched (likely referenced → managed) and the calling shoot's attachment hasn't migrated yet. "+
							"Impact: cross-shoot connectivity is broken — the shoot can't reach the seed via TGW, even though its own VPC routes look healthy. "+
							"Action: reconcile Infrastructure %s/%s to migrate the attachment to the canonical managed TGW",
						att.VpcId, att.TransitGatewayAttachmentId, att.TransitGatewayId, canonicalIDs,
						request.Namespace, request.Name))
				}
			}
		}
	}

	if len(allAtts) == 0 {
		// Definitive failure regardless of mode: a previously-reconciled shoot
		// (ProviderStatus is set, gated above) has no TGW attachment for its VPC.
		// In referenced mode we know the expected TGW ID; in managed mode the
		// reconciler creates the TGW and we don't carry its ID in the seed config,
		// so the message identifies the expected target generically.
		expected := tgwID
		if expected == "" {
			expected = "the managed TGW (auto-created by the reconciler)"
		} else {
			expected = "TGW " + expected
		}
		issues = append(issues, fmt.Sprintf(
			"[Missing Attachment] VPC %s has no TGW attachment (expected on %s). "+
				"Impact: shoot workers have no TGW connectivity to seed services, nodes will remain in Pending state. "+
				"Action: reconcile Infrastructure %s/%s to create the attachment",
			vpcID, expected, request.Namespace, request.Name))
	}

	// --- Check 2: Blackhole routes in any VPC RT we manage ---
	// Scope: shoot VPC + every globalVPC (includes mgmt + auto-discovered runtime).
	// Previously this only scanned the shoot's own VPC, missing
	// blackholes in runtime/mgmt/globalVPC RTs that form during cross-TGW
	// switches. The reconciler's invariant sweep cleans them, but the
	// healthcheck must flag them as unhealthy until they're cleaned —
	// otherwise TGWNetworkHealthy reports True while routes are still
	// blackholed.
	scanForBlackholes := func(awsClient awsclient.Interface, scanVpcID, vpcRole string) {
		rts, err := awsClient.FindRouteTablesByFilters(ctx, []ec2types.Filter{
			{Name: ptr.To("vpc-id"), Values: []string{scanVpcID}},
		})
		if err != nil {
			return
		}
		for _, rt := range rts {
			for _, r := range rt.Routes {
				if r.TransitGatewayId != nil && r.State != nil && *r.State == "blackhole" && r.DestinationCidrBlock != nil {
					issues = append(issues, fmt.Sprintf(
						"[Blackhole Route] Route %s → TGW %s in %s route table %s (%s) is a blackhole — the target TGW has been deleted. "+
							"Impact: traffic to %s is being dropped, which may cause worker nodes to remain Pending or lose connectivity to the seed. "+
							"Action: reconcile Infrastructure %s/%s to replace the blackhole with an active route to the current TGW",
						*r.DestinationCidrBlock, *r.TransitGatewayId, vpcRole, rt.RouteTableId, rt.Tags["Name"],
						*r.DestinationCidrBlock, request.Namespace, request.Name))
				}
			}
		}
	}
	// Shoot's own VPC.
	scanForBlackholes(awsClient, vpcID, "shoot VPC")
	// Every configured globalVPC (includes mgmt + auto-discovered runtime VPC for child shoots).
	for i := range seedConfig.TransitGateway.GlobalVPCs {
		gvpc := &seedConfig.TransitGateway.GlobalVPCs[i]
		if gvpc.VpcID == nil || *gvpc.VpcID == "" {
			continue
		}
		scanForBlackholes(awsClient, *gvpc.VpcID, fmt.Sprintf("globalVPC %s", gvpc.Name))
	}

	// --- Check 3: Topology invariant — attachment associated with the right RT for the isolation mode ---
	//
	// In hub-spoke mode, the SEED shoot's own attachment (which IS the seed VPC
	// attachment) must be associated with the HUB RT; child shoots' own
	// attachments must be associated with the SPOKE RT. In shared mode, all
	// attachments associate with the SHARED RT. This drift is what caused the
	// 2026-04-29 H2 incident — silent data-path failure invisible to the
	// existing blackhole / wrong-TGW checks.
	//
	// This check is the healthcheck-side complement of fix #2 (A)'s reconcile-
	// time enforcement (assertSeedSideAssociations). The healthcheck only
	// REPORTS drift — the reconciler corrects it. Reporting drives the
	// autoTriggerReconcile path (Fibonacci backoff) so a wedged topology
	// becomes visible and self-healing within a healthcheck cycle (~30s)
	// rather than waiting for the 1h shoot sync.
	//
	// Two-tier expected-RT resolution:
	//   1. REFERENCED mode: read from seedConfig.TransitGateway.{Hub,Spoke,RouteTable}ID.
	//   2. MANAGED mode: tag-search the TGW for the extension's hub/spoke/shared
	//      RTs (cluster tag = seedShootNS), classify by Name suffix.
	// In either case, "" means the expected RT can't be determined this cycle
	// (managed mode bootstrap before RTs created, lookup failure, etc.) — skip.
	// Detect if the calling shoot IS the seed shoot (ManagedSeed pattern).
	// The naive `request.Name == seed.Name` check fails for ManagedSeed shoots:
	// the calling shoot's name and its parent seed's name are different
	// strings, so the comparison is a false negative and the seed shoot's
	// own attachment on HUB RT gets falsely flagged as drift (expecting SPOKE).
	//
	// Authoritative detection mirrors actuator_reconcile.go: look up a Seed in
	// the garden cluster with the shoot's name. If it exists, this shoot IS a
	// ManagedSeed. Falls back to the naive check when gardenReader isn't
	// available (e.g., legacy registration without garden access plumbed).
	isSeedShoot := request.Name == seed.Name
	if h.gardenReader != nil {
		candidateSeed := &gardencorev1beta1.Seed{}
		if err := h.gardenReader.Get(ctx, client.ObjectKey{Name: request.Name}, candidateSeed); err == nil {
			isSeedShoot = true
		}
	}
	expectedRT := computeExpectedRTForOwnAttachment(seedConfig.TransitGateway, isSeedShoot)
	if expectedRT == "" && tgwID != "" {
		seedShootNS := findSeedShootNamespace(ctx, h.seedClient, seed.Name, request.Namespace)
		rts := findManagedTGWRouteTables(ctx, tgwClient, tgwID, seedShootNS)
		expectedRT = computeExpectedRTManagedMode(rts, seedConfig.TransitGateway.IsolationMode, isSeedShoot)
		h.logger.Info("topology check: managed-mode RT discovery", "shoot", request.Name,
			"tgwID", tgwID, "seedShootNS", seedShootNS, "isolationMode", seedConfig.TransitGateway.IsolationMode,
			"isSeedShoot", isSeedShoot, "hubRT", rts.hub, "spokeRT", rts.spoke, "sharedRT", rts.shared,
			"expectedRT", expectedRT)
	} else if expectedRT == "" && tgwID == "" {
		// Managed mode without a resolved tgwID — discover the TGW by listing
		// our cluster-tagged TGW attachments and using whichever TGW the shoot
		// VPC's tagged attachment points at. Same fallback pattern as
		// preWireSeedVPCOnNewTGW.
		shootPrefix := request.Name + "-tgw-attachment"
		var discoveredTGW string
		for _, att := range allAtts {
			if strings.Contains(att.Tags["Name"], shootPrefix) {
				discoveredTGW = att.TransitGatewayId
				break
			}
		}
		if discoveredTGW != "" {
			seedShootNS := findSeedShootNamespace(ctx, h.seedClient, seed.Name, request.Namespace)
			rts := findManagedTGWRouteTables(ctx, tgwClient, discoveredTGW, seedShootNS)
			expectedRT = computeExpectedRTManagedMode(rts, seedConfig.TransitGateway.IsolationMode, isSeedShoot)
			tgwID = discoveredTGW
			h.logger.Info("topology check: managed-mode RT discovery (TGW discovered from attachment)",
				"shoot", request.Name, "discoveredTGW", discoveredTGW, "seedShootNS", seedShootNS,
				"isolationMode", seedConfig.TransitGateway.IsolationMode, "isSeedShoot", isSeedShoot,
				"hubRT", rts.hub, "spokeRT", rts.spoke, "sharedRT", rts.shared, "expectedRT", expectedRT)
		}
	}
	if expectedRT != "" {
		for _, att := range allAtts {
			if att.State != "available" || (tgwID != "" && att.TransitGatewayId != tgwID) {
				continue
			}
			// Restrict to attachments tagged for THIS shoot — the same filter
			// the wrong-TGW check uses. The VPC may have unrelated attachments
			// (other teams sharing the AWS account) that we should not audit.
			attName := att.Tags["Name"]
			shootPrefix := request.Name + "-tgw-attachment"
			if !strings.Contains(attName, shootPrefix) {
				continue
			}
			currentRT, assocErr := tgwClient.GetTransitGatewayAttachmentAssociation(ctx, att.TransitGatewayAttachmentId)
			if assocErr != nil {
				h.logger.Info("topology check: failed to read association — skipping",
					"attachmentId", att.TransitGatewayAttachmentId, "error", assocErr)
				continue
			}
			if currentRT == "" || currentRT == expectedRT {
				continue
			}
			// Drift observed.
			isolation := "hub-spoke"
			if seedConfig.TransitGateway.IsolationMode == "shared" {
				isolation = "shared"
			}
			role := "shoot"
			if request.Name == seed.Name {
				role = "seed"
			}
			issues = append(issues, fmt.Sprintf(
				"[Topology Drift] %s VPC attachment %s is associated with route table %s but %q isolation mode expects %s. "+
					"Impact: traffic between this VPC and the rest of the TGW topology may be silently dropped at the TGW. "+
					"Action: reconcile Infrastructure %s/%s — the seed-shoot reconcile is the canonical mover and will correct it",
				role, att.TransitGatewayAttachmentId, currentRT, isolation, expectedRT,
				request.Namespace, request.Name))
		}
	}

	// --- Build result ---
	if len(issues) > 0 {
		detail := fmt.Sprintf("TGW network health check failed — %d issue(s) detected:\n%s",
			len(issues), "• "+strings.Join(issues, "\n• "))
		h.logger.Info("TGW health check failed", "shoot", request.Name, "namespace", request.Namespace, "issues", len(issues))

		// Auto-trigger infra reconcile for definitive failures (with cooldown).
		h.autoTriggerReconcile(ctx, request)

		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: detail,
		}, nil
	}

	// Healthy — reset Fibonacci backoff so the next failure starts at 1m again.
	h.resetAutoReconcileBackoff(request.Namespace + "/" + request.Name)

	attachmentCount := len(allAtts)
	tgwMode := "referenced"
	if seedConfig.TransitGateway.ID == nil {
		tgwMode = "managed"
	}
	isolationMode := "hub-spoke"
	if seedConfig.TransitGateway.IsolationMode == "shared" {
		isolationMode = "shared"
	}

	// Enriched ConditionTrue message. The earlier
	// version returned ConditionProgressing whenever LastOperation was
	// Processing, which triggered Gardener's healthcheck threshold logic to
	// flip the condition to False during long reconciles. That cascade scaled
	// down DWD-protected components on the seed shoot and broke worker
	// bootstrap on S3. Lesson: only False or True from this healthcheck —
	// never Progressing on transient reconcile state.
	reconciledAgoStr := ""
	if infra.Status.LastOperation != nil && !infra.Status.LastOperation.LastUpdateTime.IsZero() {
		reconciledAgoStr = fmt.Sprintf(" · last reconciled %s ago", time.Since(infra.Status.LastOperation.LastUpdateTime.Time).Round(time.Second).String())
	}
	return &healthcheck.SingleCheckResult{
		Status: gardencorev1beta1.ConditionTrue,
		Detail: fmt.Sprintf("TGW healthy · %s/%s · %d attachment(s)%s",
			tgwMode, isolationMode, attachmentCount, reconciledAgoStr),
	}, nil
}

// autoTriggerReconcile annotates the Infrastructure resource with gardener.cloud/operation=reconcile
// to trigger the infra reconciler, which will fix TGW issues (blackhole routes, stale attachments).
//
// Uses Fibonacci backoff: 1m, 1m, 2m, 3m, 5m, 8m, 13m (capped at 15m).
// Resets to 1m when the health check passes (issue resolved).
func (h *TGWHealthChecker) autoTriggerReconcile(ctx context.Context, request types.NamespacedName) {
	key := request.Namespace + "/" + request.Name

	h.backoffMu.Lock()
	state, exists := h.backoff[key]
	if !exists {
		state = &autoReconcileState{
			prevDelay: 0,
			currDelay: autoReconcileInitialCooldown,
		}
		h.backoff[key] = state
	}
	h.backoffMu.Unlock()

	if !state.lastTrigger.IsZero() && time.Since(state.lastTrigger) < state.currDelay {
		h.logger.Info("skipping auto-reconcile trigger (Fibonacci cooldown active)",
			"infra", key, "cooldown", state.currDelay.Round(time.Second),
			"remaining", (state.currDelay - time.Since(state.lastTrigger)).Round(time.Second))
		return
	}

	infra := &extensionsv1alpha1.Infrastructure{}
	if err := h.infraClient.Get(ctx, request, infra); err != nil {
		h.logger.Info("warning: failed to get Infrastructure for auto-reconcile", "error", err)
		return
	}

	// Only annotate if not already annotated.
	annotations := infra.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	if annotations["gardener.cloud/operation"] == "reconcile" {
		h.logger.Info("Infrastructure already has reconcile annotation — skipping", "infra", key)
		return
	}

	annotations["gardener.cloud/operation"] = "reconcile"
	infra.SetAnnotations(annotations)
	if err := h.infraClient.Update(ctx, infra); err != nil {
		h.logger.Info("warning: failed to annotate Infrastructure for auto-reconcile", "infra", key, "error", err)
		return
	}

	// Advance Fibonacci backoff.
	h.backoffMu.Lock()
	state.lastTrigger = time.Now()
	nextDelay := state.prevDelay + state.currDelay
	if nextDelay > autoReconcileMaxCooldown {
		nextDelay = autoReconcileMaxCooldown
	}
	state.prevDelay = state.currDelay
	state.currDelay = nextDelay
	h.backoffMu.Unlock()

	h.logger.Info("auto-triggered infra reconcile due to TGW health failure",
		"infra", key, "currentCooldown", state.prevDelay.Round(time.Second),
		"nextCooldown", state.currDelay.Round(time.Second))
}

// computeExpectedRTForOwnAttachment returns the route table ID that THIS
// shoot's own VPC attachment must be associated with, given the seed's TGW
// config and whether this shoot is the seed shoot itself.
//
// Returns "" when the expected RT cannot be determined from referenced
// configuration alone (managed mode — caller falls back to
// findManagedTGWRouteTables for tag-based discovery).
//
//   - shared mode: all attachments associate with RouteTableID
//   - hub-spoke mode, seed shoot's own attachment: HubRouteTableID
//   - hub-spoke mode, child shoot's own attachment: SpokeRouteTableID
func computeExpectedRTForOwnAttachment(tgw *awsapi.TransitGateway, isSeedShoot bool) string {
	if tgw == nil {
		return ""
	}
	if tgw.IsolationMode == "shared" {
		if tgw.RouteTableID != nil {
			return *tgw.RouteTableID
		}
		return ""
	}
	// hub-spoke (default).
	if isSeedShoot {
		if tgw.HubRouteTableID != nil {
			return *tgw.HubRouteTableID
		}
		return ""
	}
	if tgw.SpokeRouteTableID != nil {
		return *tgw.SpokeRouteTableID
	}
	return ""
}

// managedTGWRouteTables holds the IDs of the hub/spoke/shared RTs the
// extension created on a managed TGW for one seed.
type managedTGWRouteTables struct {
	hub    string
	spoke  string
	shared string
}

// findManagedTGWRouteTables tag-searches the managed TGW for the route tables
// the extension created for this seed. Mirrors the classification at
// reconcile.go cleanOrphanedRouteTables — `kubernetes.io/cluster/<seedShootNS>`
// tag plus a Name-suffix match on `-tgw-rt-{hub,spoke,shared}`.
//
// Returns an empty struct on lookup error or when no RTs match — caller treats
// that as "expected RT not discoverable, skip the drift check".
func findManagedTGWRouteTables(ctx context.Context, tgwClient awsclient.Interface, tgwID, seedShootNS string) managedTGWRouteTables {
	var out managedTGWRouteTables
	if tgwID == "" {
		return out
	}
	// Two-tier discovery:
	//   1. Tag-search by seed cluster namespace — clean path when RTs are
	//      properly tagged (`kubernetes.io/cluster/<seedShootNS>`).
	//   2. Fallback: list ALL RTs on the TGW and classify by Name suffix.
	//      Required because some managed-mode deployments end up with empty
	//      cluster-tag namespaces on their RTs (`kubernetes.io/cluster/`,
	//      `Name: -tgw-rt-hub`) — likely a producer-side regression where
	//      the RT was created before the namespace was bound to commonTags.
	//      Filed as a separate bug; healthcheck tolerates the bad state.
	classify := func(rts []*awsclient.TransitGatewayRouteTableInfo) {
		for _, rt := range rts {
			if rt.TransitGatewayId != tgwID {
				continue
			}
			name := rt.Tags["Name"]
			switch {
			case strings.HasSuffix(name, "-tgw-rt-hub"):
				out.hub = rt.TransitGatewayRouteTableId
			case strings.HasSuffix(name, "-tgw-rt-spoke"):
				out.spoke = rt.TransitGatewayRouteTableId
			case strings.HasSuffix(name, "-tgw-rt-shared"):
				out.shared = rt.TransitGatewayRouteTableId
			}
		}
	}
	if seedShootNS != "" {
		tags := awsclient.Tags{fmt.Sprintf("kubernetes.io/cluster/%s", seedShootNS): "1"}
		if rts, err := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, tags); err == nil {
			classify(rts)
		}
	}
	if out.hub == "" && out.spoke == "" && out.shared == "" {
		// Fallback: scan all RTs on the TGW.
		if allRTs, err := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, nil); err == nil {
			classify(allRTs)
		}
	}
	return out
}

// findSeedShootNamespace locates the seed shoot's Infrastructure namespace by
// listing Infrastructures and matching the shoot whose name == seedName and
// Spec.Type == "aws". Same pattern as seed_tgw_watcher.preWireSeedVPCOnNewTGW.
//
// Returns "" if not found — caller skips the managed-mode topology check.
// findSeedShootNamespace resolves the namespace of the seed shoot's
// Infrastructure resource. For child shoots running on a managed seed, the
// seed shoot's Infrastructure resource lives on the LOCAL seed (where the
// managed seed's control plane runs), not on the managed seed itself, so a
// direct List on seedClient won't find it.
//
// Falls back to Gardener's namespace convention: `shoot--<project>--<seedName>`
// derived from the calling shoot's own namespace prefix. This matches the
// convention preWireSeedVPCOnNewTGW and cleanOrphanedRouteTables use when
// composing the cluster tag for the seed shoot.
func findSeedShootNamespace(ctx context.Context, seedClient client.Client, seedName, callingNS string) string {
	if seedName == "" {
		return ""
	}
	// First try a direct lookup — only works when the seed shoot's
	// Infrastructure happens to live on the same cluster the healthcheck
	// runs on (i.e. the calling shoot IS the seed shoot, or non-managed-seed
	// topologies).
	allInfra := &extensionsv1alpha1.InfrastructureList{}
	if err := seedClient.List(ctx, allInfra); err == nil {
		for _, infra := range allInfra.Items {
			if infra.Name == seedName && infra.Spec.Type == "aws" {
				return infra.Namespace
			}
		}
	}
	// Convention fallback: derive `shoot--<project>--<seedName>` from the
	// calling shoot's namespace by replacing the trailing shoot name.
	// E.g. a shoot in namespace `shoot--<proj>--<shoot>` with parent seed
	// `<seedName>` resolves to `shoot--<proj>--<seedName>`.
	if callingNS == "" {
		return ""
	}
	const prefix = "shoot--"
	if !strings.HasPrefix(callingNS, prefix) {
		return ""
	}
	rest := callingNS[len(prefix):]
	sep := strings.Index(rest, "--")
	if sep < 0 {
		return ""
	}
	project := rest[:sep]
	return fmt.Sprintf("%s%s--%s", prefix, project, seedName)
}

// computeExpectedRTManagedMode resolves the expected RT for the calling shoot's
// own attachment in MANAGED TGW mode by tag-searching the TGW for the
// extension's route tables. Mirrors the referenced-mode logic in
// computeExpectedRTForOwnAttachment but reads from AWS rather than seedConfig.
//
// Returns "" if discovery fails or the relevant RT isn't (yet) created.
func computeExpectedRTManagedMode(rts managedTGWRouteTables, isolationMode string, isSeedShoot bool) string {
	if isolationMode == "shared" {
		return rts.shared
	}
	// hub-spoke (default).
	if isSeedShoot {
		return rts.hub
	}
	return rts.spoke
}

// resetAutoReconcileBackoff resets the Fibonacci backoff for an Infrastructure
// when the health check passes (issue resolved). Called from Check when healthy.
func (h *TGWHealthChecker) resetAutoReconcileBackoff(key string) {
	h.backoffMu.Lock()
	defer h.backoffMu.Unlock()
	delete(h.backoff, key)
}
