// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	awspkg "github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

const (
	// TagKeyName is the name tag key
	TagKeyName = "Name"
	// TagKeyClusterTemplate is the template for the cluster tag key
	TagKeyClusterTemplate = "kubernetes.io/cluster/%s"
	// TagKeyRolePublicELB is the tag key for the public ELB
	TagKeyRolePublicELB = "kubernetes.io/role/elb"
	// TagKeyRolePrivateELB is the tag key for the internal ELB
	TagKeyRolePrivateELB = "kubernetes.io/role/internal-elb"
	// TagValueCluster is the tag value for the cluster tag
	TagValueCluster = "1"
	// TagValueELB is the tag value for the ELB tag keys
	TagValueELB = "1"

	// IdentifierVPC is the key for the VPC id
	IdentifierVPC = "VPC"
	// IdentifierDHCPOptions is the key for the id of the DHCPOptions resource
	IdentifierDHCPOptions = "DHCPOptions"
	// IdentifierDefaultSecurityGroup is the key for the id of the default security group
	IdentifierDefaultSecurityGroup = "DefaultSecurityGroup"
	// IdentifierInternetGateway is the key for the id of the internet gateway resource
	IdentifierInternetGateway = "InternetGateway"
	// IdentifierEgressOnlyInternetGateway is the key for the id of the internet gateway resource
	IdentifierEgressOnlyInternetGateway = "EgressOnlyInternetGateway"
	// IdentifierMainRouteTable is the key for the id of the main route table
	IdentifierMainRouteTable = "MainRouteTable"
	// IdentifierNodesSecurityGroup is the key for the id of the nodes security group
	IdentifierNodesSecurityGroup = "NodesSecurityGroup"
	// IdentifierZoneSubnetWorkers is the key for the id of the workers subnet
	IdentifierZoneSubnetWorkers = "SubnetWorkers"
	// IdentifierZoneSubnetPublic is the key for the id of the public utility subnet
	IdentifierZoneSubnetPublic = "SubnetPublicUtility"
	// IdentifierZoneSubnetPrivate is the key for the id of the private utility subnet
	IdentifierZoneSubnetPrivate = "SubnetPrivateUtility"
	// IdentifierZoneSuffix is the key for the suffix used for a zone
	IdentifierZoneSuffix = "Suffix"
	// IdentifierManagedZoneNATGWElasticIP is the key for the allocationID of the gardener managed NAT gateway elastic IP
	IdentifierManagedZoneNATGWElasticIP = "NATGatewayElasticIP"
	// IdentifierZoneNATGateway is the key for the id of the NAT gateway resource
	IdentifierZoneNATGateway = "NATGateway"
	// IdentifierZoneRouteTable is the key for the id of route table of the zone
	IdentifierZoneRouteTable = "ZoneRouteTable"
	// IdentifierZoneSubnetPublicRouteTableAssoc is the key for the id of the public route table association resource
	IdentifierZoneSubnetPublicRouteTableAssoc = "SubnetPublicRouteTableAssoc"
	// IdentifierZoneSubnetPrivateRouteTableAssoc is the key for the id of the private c route table association resource
	IdentifierZoneSubnetPrivateRouteTableAssoc = "SubnetPrivateRouteTableAssoc"
	// IdentifierZoneSubnetWorkersRouteTableAssoc is key for the id of the workers route table association resource
	IdentifierZoneSubnetWorkersRouteTableAssoc = "SubnetWorkersRouteTableAssoc"
	// IdentifierVpcIPv6CidrBlock is the IPv6 CIDR block attached to the vpc
	IdentifierVpcIPv6CidrBlock = "VPCIPv6CidrBlock"
	// IdentifierEgressCIDRs is the key for the slice containing egress CIDRs strings.
	IdentifierEgressCIDRs = "EgressCIDRs"
	// IdentifierServiceCIDR is the key for the subnet cidr reservation for the service range.
	IdentifierServiceCIDR = "ServiceCIDR"
	// NameIAMRole is the key for the name of the IAM role
	NameIAMRole = "IAMRoleName"
	// NameIAMInstanceProfile is the key for the name of the IAM instance profile
	NameIAMInstanceProfile = "IAMInstanceProfileName"
	// NameIAMRolePolicy is the key for the name of the IAM role policy
	NameIAMRolePolicy = "IAMRolePolicyName"
	// NameKeyPair is the key for the name of the EC2 key pair resource
	NameKeyPair = "KeyPair"
	// ARNIAMRole is the key for the ARN of the IAM role
	ARNIAMRole = "IAMRoleARN"
	// KeyPairFingerprint is the key to store the fingerprint of the key pair
	KeyPairFingerprint = "KeyPairFingerprint"
	// KeyPairSpecFingerprint is the key to store the fingerprint of the public key from the spec
	KeyPairSpecFingerprint = "KeyPairSpecFingerprint"

	// IdentifierManagedEfsID is the key for the EFS system ID
	IdentifierManagedEfsID = "efsSystemID"
	// ChildEfsMountTargets is the children key for the EFS mount targets
	ChildEfsMountTargets = "efsMountTargets"

	// ChildIdVPCEndpoints is the child key for the VPC endpoints
	ChildIdVPCEndpoints = "VPCEndpoints"
	// ChildIdZones is the child key for the zones
	ChildIdZones = "Zones"

	// ObjectMainRouteTable is the object key used for caching the main route table object
	ObjectMainRouteTable = "MainRouteTable"
	// ObjectZoneRouteTable is the object key used for caching the zone route table object
	ObjectZoneRouteTable = "ZoneRouteTable"

	// IdentifierTransitGatewayID is the key for the id of the TGW (always persisted — referenced or auto-created)
	IdentifierTransitGatewayID = "TransitGatewayID"
	// IdentifierTransitGatewayHubRouteTable is the key for the hub route table id (always persisted — referenced or auto-created)
	IdentifierTransitGatewayHubRouteTable = "TransitGatewayHubRouteTable"
	// IdentifierTransitGatewaySpokeRouteTable is the key for the spoke route table id (always persisted — referenced or auto-created)
	IdentifierTransitGatewaySpokeRouteTable = "TransitGatewaySpokeRouteTable"
	// IdentifierTransitGatewayAttachment is the key for the id of the seed-level TGW VPC attachment
	IdentifierTransitGatewayAttachment = "TransitGatewayAttachment"
	// IdentifierSeedVPCTransitGatewayAttachment is the key for the seed's own VPC TGW attachment.
	// This is a shared, seed-level resource — created during shoot reconciliation, NOT deleted
	// when individual shoots are deleted. Only cleaned up when TGW is disabled on the seed.
	IdentifierSeedVPCTransitGatewayAttachment = "SeedVPCTransitGatewayAttachment"
	// IdentifierShootTransitGatewayAttachment is the key for the id of the shoot-level TGW VPC attachment
	IdentifierShootTransitGatewayAttachment = "ShootTransitGatewayAttachment"
	// IdentifierRuntimeVPCTransitGatewayAttachment is the key for the runtime VPC's TGW attachment
	// in managed TGW mode. The runtime VPC is auto-discovered from Garden API DNS resolution.
	IdentifierRuntimeVPCTransitGatewayAttachment = "RuntimeVPCTransitGatewayAttachment"
	// IdentifierRuntimeVPCID is the discovered runtime VPC ID.
	IdentifierRuntimeVPCID = "RuntimeVPCID"
	// IdentifierRuntimeVPCCIDR is the discovered runtime VPC CIDR.
	IdentifierRuntimeVPCCIDR = "RuntimeVPCCIDR"
	// IdentifierTransitGatewayManaged is "true" when the TGW was auto-created (nil ID in config)
	IdentifierTransitGatewayManaged = "TransitGatewayManaged"
	// IdentifierTransitGatewayHubRouteTableManaged is "true" when the hub route table was auto-created
	IdentifierTransitGatewayHubRouteTableManaged = "TransitGatewayHubRouteTableManaged"
	// IdentifierTransitGatewaySpokeRouteTableManaged is "true" when the spoke route table was auto-created
	IdentifierTransitGatewaySpokeRouteTableManaged = "TransitGatewaySpokeRouteTableManaged"
	// IdentifierTransitGatewaySharedRouteTable is the key for the shared route table id (shared isolation mode)
	IdentifierTransitGatewaySharedRouteTable = "TransitGatewaySharedRouteTable"
	// IdentifierTransitGatewaySharedRouteTableManaged is "true" when the shared route table was auto-created
	IdentifierTransitGatewaySharedRouteTableManaged = "TransitGatewaySharedRouteTableManaged"
	// IdentifierPreviousTGWs is a state child storing TGW IDs we've ever resolved
	// as ours. Used by the blackhole-sweep ownership check to verify abandoned
	// TGW provenance even after the TGW is deleted from AWS (DescribeTransitGateway
	// returns NotFound). Recorded at the top of reconcile() and in
	// reconcileTGWState Phase 0 (defense in depth — survives crashes between).
	//
	// Storage: ~30 bytes per entry; realistic growth <100 entries lifetime even
	// for long-running production seeds. Stored in
	// infrastructure.status.providerStatus (whiteboard); 100 KB is well below
	// the 1.5 MB Kubernetes object warning threshold. NO cap applied; an info
	// log fires if size exceeds 100 entries (signal of unusual cluster behavior).
	//
	// Inter-shoot coherence: each shoot maintains its OWN history. After a
	// mode switch, histories converge within one sync period as each shoot
	// reconciles. Brief eventual-consistency window may produce
	// TGWBlackholeUnverifiable warning events from shoots that haven't yet
	// observed the new TGW; these self-resolve on the next reconcile of the
	// canonical-owner shoot. Shared history (ConfigMap/CRD) is deferred per
	// tgw-cross-extension-todos.md until very-large-scale deployments report
	// the eventual-consistency noise as a real operator burden.
	IdentifierPreviousTGWs = "PreviousTGWs"
	// IdentifierShootVPCCIDR stores the shoot VPC CIDR for seed VPC route cleanup during deletion.
	IdentifierShootVPCCIDR = "ShootVPCCIDR"
	// IdentifierTGWIsolationSwitchTargetRT stores the target RT ID during a two-phase
	// isolation mode switch for the SHOOT VPC attachment. Phase 1 sets up propagation
	// to the target RT and stores this key. Phase 2 (next reconcile) verifies the
	// target RT has routes and performs the actual disassociate → re-associate.
	// Cleared after successful switch.
	IdentifierTGWIsolationSwitchTargetRT = "TGWIsolationSwitchTargetRT"
	// IdentifierSeedVPCIsolationSwitchTargetRT is the same as above but for the SEED VPC
	// attachment. Distinct key prevents collision when both attachments need switching.
	IdentifierSeedVPCIsolationSwitchTargetRT = "SeedVPCIsolationSwitchTargetRT"
	// IdentifierTGWIsolationSwitchAttempts counts Phase 2 retry attempts for the shoot
	// attachment. After maxIsolationSwitchAttempts, Phase 2 gives up with an error
	// rather than requeuing forever.
	IdentifierTGWIsolationSwitchAttempts = "TGWIsolationSwitchAttempts"
	// IdentifierSeedVPCIsolationSwitchAttempts counts Phase 2 retry attempts for the seed VPC.
	IdentifierSeedVPCIsolationSwitchAttempts = "SeedVPCIsolationSwitchAttempts"
	// IdentifierTGWLastSwitchedAt records the RFC3339Nano timestamp of the last
	// successful Phase 2 switch for the shoot's TGW attachment. shouldDeferPingPongSwitch
	// reads this on the next reconcile: if the timestamp is within pingPongCooldownPeriod,
	// a fresh Phase 1 detection means another writer reverted our switch — defer instead
	// of fighting back. After maxPingPongDefers consecutive deferrals, abandon.
	IdentifierTGWLastSwitchedAt = "TGWLastSwitchedAt"
	// IdentifierTGWPingPongDefers counts consecutive cooldown deferrals for the shoot
	// attachment switch. Reset to absent when a deferral check sees the cooldown expired.
	IdentifierTGWPingPongDefers = "TGWPingPongDefers"
	// IdentifierSeedVPCLastSwitchedAt is the equivalent of IdentifierTGWLastSwitchedAt
	// for the seed VPC attachment switch.
	IdentifierSeedVPCLastSwitchedAt = "SeedVPCLastSwitchedAt"
	// IdentifierSeedVPCPingPongDefers is the equivalent of IdentifierTGWPingPongDefers
	// for the seed VPC attachment switch.
	IdentifierSeedVPCPingPongDefers = "SeedVPCPingPongDefers"
	// pingPongCooldownPeriod is the window after a successful Phase 2 switch during
	// which a fresh Phase 1 detection (currentRT != targetRT) is treated as a
	// cross-extension fight and deferred instead of immediately re-switching.
	pingPongCooldownPeriod = 60 * time.Second
	// maxPingPongDefers is the cap on consecutive deferrals before abandoning the
	// switch and emitting a TGWSwitchDeadlock Warning event. 5 × 30s requeue ≈ 2.5min.
	maxPingPongDefers = 5
	// maxIsolationSwitchAttempts is the cap on Phase 2 retries before giving up.
	// 10 attempts × 30s requeue interval = ~5 minutes total wait.
	maxIsolationSwitchAttempts = 10

	// IdentifierGlobalVPCAttachmentPrefix is the prefix for managed globalVPC TGW attachment state keys.
	// Each managed globalVPC stores its attachment ID as "GlobalVPCAttachment/<name>".
	IdentifierGlobalVPCAttachmentPrefix = "GlobalVPCAttachment/"
	// IdentifierGlobalVPCAttachmentManagedPrefix is the prefix for managed markers.
	// "GlobalVPCAttachmentManaged/<name>" = "true" when the extension created the attachment.
	IdentifierGlobalVPCAttachmentManagedPrefix = "GlobalVPCAttachmentManaged/"

	// MarkerMigratedFromTerraform is the key for marking the state for successful state migration from Terraformer
	MarkerMigratedFromTerraform = "MigratedFromTerraform"
	// MarkerTerraformCleanedUp is the key for marking the state for successful cleanup of Terraformer resources.
	MarkerTerraformCleanedUp = "TerraformCleanedUp"
	// MarkerLoadBalancersAndSecurityGroupsDestroyed is the key for marking the state that orphan load balancers
	// and security groups have already been destroyed
	MarkerLoadBalancersAndSecurityGroupsDestroyed = "LoadBalancersAndSecurityGroupsDestroyed"
)

// Opts contain options to initialize a FlowContext
type Opts struct {
	Log            logr.Logger
	ClientFactory  awsclient.Interface
	Infrastructure *extensionsv1alpha1.Infrastructure
	State          *awsapi.InfrastructureState
	AwsClient      awsclient.Interface
	RuntimeClient  client.Client
	Shoot          *v1beta1.Shoot
	Seed           *v1beta1.Seed
	Recorder       record.EventRecorder
	// IsManagedSeedShoot is true when this shoot IS a ManagedSeed (its VPC is the
	// seed VPC for child shoots). When true, ensureTransitGatewayAttachment uses hub
	// RT instead of spoke and preserves spoke RT propagation so child shoots can
	// reach this VPC.
	IsManagedSeedShoot bool
}

// ownershipResult is the cached result of isAbandonedTGWOurs for a given
// abandoned TGW ID within a single reconcile.
type ownershipResult struct {
	// ours is true if the abandoned TGW was provably ours (state history hit
	// or live cluster-tag check passed).
	ours bool
	// transient is true if the live tag check failed with a transient AWS
	// error (throttle/timeout). Caller should defer this entry without
	// emitting an "unverifiable" event so it retries on the next reconcile.
	transient bool
}

// FlowContext contains the logic to reconcile or delete the AWS infrastructure.
type FlowContext struct {
	log           logr.Logger
	state         shared.Whiteboard
	namespace     string
	shootUUID     string
	infra         *extensionsv1alpha1.Infrastructure
	infraSpec     extensionsv1alpha1.InfrastructureSpec
	config        *awsapi.InfrastructureConfig
	seedConfig    *awsapi.SeedProviderConfig
	client        awsclient.Interface
	runtimeClient client.Client
	updater       awsclient.Updater
	commonTags    awsclient.Tags
	networking    *v1beta1.Networking

	// resolvedEffectiveGlobalVPCs is the computed list of globalVPCs including the
	// synthesized runtime VPC (if runtimeVPC.enabled). Set once during ensureTransitGateway.
	resolvedEffectiveGlobalVPCs []awsapi.GlobalVPC

	// seedNodesCIDR is the Seed's node network CIDR (from Seed.spec.networks.nodes).
	// Used for auto-discovering the seed VPC when attachSeedVpc is true.
	seedNodesCIDR string

	// seedName is the Seed object name (from resolveEffectiveSeed).
	seedName string

	// shootName is the Shoot object name (from cluster.Shoot.Name).
	shootName string

	// seedShootNamespace is the namespace of the seed shoot's Infrastructure resource.
	// Used for tag patterns when finding managed TGW resources (e.g., "kubernetes.io/cluster/<ns>").
	// Resolved during construction by finding the Infrastructure with name==seedName on the local cluster.
	// Empty if the seed shoot's Infrastructure doesn't exist on this cluster (e.g., seed hosted by a different runtime).
	seedShootNamespace string

	// peerShootCIDRs contains VPC CIDRs of other AWS shoots on this seed.
	// Used in shared isolation mode to add TGW routes so shoots can reach each other.
	// Resolved during construction from the Infrastructure list on the local cluster.
	peerShootCIDRs []string

	// isManagedSeedShoot is true when this shoot IS a ManagedSeed. Its VPC serves as the
	// seed VPC for child shoots and must be on hub RT with spoke propagation enabled.
	isManagedSeedShoot bool

	// gardenAPIDomain is the Garden API hostname (e.g., "api.garden.example.com"),
	// constructed from Seed.spec.dns.defaults[0].domain. Used for runtime VPC auto-discovery
	// in managed TGW mode.
	gardenAPIDomain string

	// Resolved TGW IDs — set by ensureTransitGateway, consumed by ensureTransitGatewayAttachment.
	resolvedTGWID              string
	resolvedHubRouteTableID    string
	resolvedSpokeRouteTableID  string
	resolvedSharedRouteTableID string

	// tgwDriftDetected is set by reconcileTGWState when drift is found and fixed.
	// The caller can use this to requeue the reconcile for verification.
	tgwDriftDetected bool

	// tgwDriftCorrectedThisReconcile is set by assertSeedSideAssociations after
	// it successfully MOVES an attachment from the wrong RT to the canonical RT.
	// Distinct from tgwDriftDetected (which fires on observation alone): this
	// only flips on successful corrective action. The actuator reads this after
	// Reconcile() returns and triggers post-hoc reconciles on every child shoot
	// so DWD-scaled deployments come back online without waiting for the next
	// 1h sync. Reset to false at the start of each Reconcile call.
	tgwDriftCorrectedThisReconcile bool

	// staleAttachmentIDs are TGW VPC attachments flagged for deferred cleanup.
	// Set by reconcileTGWState Phase 1, cleaned by cleanupStaleAttachments
	// (which runs AFTER ensureTransitGatewayAttachment creates the new attachment).
	staleAttachmentIDs []string

	// tgwSweepReplacesThisReconcile counts ReplaceRoute calls made by the
	// invariant route sweep within a single reconcile pass. Bounded by
	// maxSweepReplacesPerReconcile to limit blast radius if a regression
	// pushes the sweep into an unintended replacement loop. Reset at the
	// start of each sweepStaleTGWRoutesAcrossVPCs run.
	tgwSweepReplacesThisReconcile int

	// tgwOwnershipCache memoizes isAbandonedTGWOurs results within a single
	// reconcile to avoid N DescribeTransitGateway calls when the same
	// abandoned TGW ID appears in multiple blackhole routes across VPCs.
	// Reset at the start of each sweepStaleTGWRoutesAcrossVPCs run.
	tgwOwnershipCache map[string]ownershipResult

	// cachedTGWClient is the lazily-initialized AWS client for TGW operations.
	// Set by getTGWClient() on first call. Nil means not yet initialized or same account.
	cachedTGWClient awsclient.Interface

	// recorder emits Kubernetes Events on the Infrastructure resource for TGW lifecycle visibility.
	recorder record.EventRecorder

	*shared.BasicFlowContext
}

// NewFlowContext creates a new FlowContext object
func NewFlowContext(opts Opts) (*FlowContext, error) {
	whiteboard := shared.NewWhiteboard()
	if opts.State != nil {
		whiteboard.ImportFromFlatMap(opts.State.Data)
	}

	infraConfig, err := helper.InfrastructureConfigFromInfrastructure(opts.Infrastructure)
	if err != nil {
		return nil, err
	}

	var seedConfig *awsapi.SeedProviderConfig
	var seedNodesCIDR string
	var seedName string
	var gardenAPIDomain string
	if opts.Seed != nil {
		seedName = opts.Seed.Name
		if cfg, decodeErr := helper.SeedProviderConfigFromSeed(opts.Seed); decodeErr != nil {
			opts.Log.Info("failed to decode seed provider config, ignoring", "error", decodeErr)
		} else {
			seedConfig = cfg
		}
		if opts.Seed.Spec.Networks.Nodes != nil {
			seedNodesCIDR = *opts.Seed.Spec.Networks.Nodes
		}
		// Extract Garden API domain for runtime VPC auto-discovery in managed TGW mode.
		if len(opts.Seed.Spec.DNS.Defaults) > 0 && opts.Seed.Spec.DNS.Defaults[0].Domain != "" {
			gardenAPIDomain = "api." + opts.Seed.Spec.DNS.Defaults[0].Domain
		}
	}

	// Resolve seed shoot namespace and peer shoot CIDRs from the Infrastructure list.
	// Single list call serves both: avoids hardcoding project name in namespace construction,
	// and discovers peer shoot VPC CIDRs for shared-mode TGW routes.
	var seedShootNS string
	var peerShootCIDRs []string
	isSharedMode := seedConfig != nil && seedConfig.TransitGateway != nil &&
		seedConfig.TransitGateway.IsolationMode == "shared"
	if seedName != "" || isSharedMode {
		infraList := &extensionsv1alpha1.InfrastructureList{}
		if err := opts.RuntimeClient.List(context.Background(), infraList); err == nil {
			for i := range infraList.Items {
				infra := &infraList.Items[i]
				if infra.Spec.Type != "aws" {
					continue
				}
				// Resolve seed shoot namespace.
				if seedName != "" && infra.Name == seedName {
					seedShootNS = infra.Namespace
				}
				// Collect peer shoot CIDRs for shared mode (skip self and seed shoot).
				if isSharedMode && infra.Namespace != opts.Infrastructure.Namespace {
					peerConfig, decodeErr := helper.InfrastructureConfigFromInfrastructure(infra)
					if decodeErr == nil && peerConfig != nil && peerConfig.Networks.VPC.CIDR != nil {
						peerShootCIDRs = append(peerShootCIDRs, *peerConfig.Networks.VPC.CIDR)
					}
				}
			}
		}
	}
	// If the calling shoot IS the seed shoot (ManagedSeed pattern), its OWN
	// namespace IS the seed shoot's namespace. Detect this BEFORE falling back
	// to the convention path that uses seedName — for the seed shoot itself,
	// seedName points to its parent seed, not the seed it becomes. Without
	// this guard, the seed shoot would derive `shoot--<project>--<parent>`
	// instead of `shoot--<project>--<own>`, mistagging managed TGW resources
	// for the parent seed and creating a parallel TGW.
	if seedShootNS == "" && opts.IsManagedSeedShoot {
		seedShootNS = opts.Infrastructure.Namespace
	}
	// Convention fallback: child shoots on a ManagedSeed can't find the seed
	// shoot's Infrastructure on the managed seed cluster (it lives on the
	// LOCAL seed where the managed seed's control plane runs), so derive
	// `shoot--<project>--<seedName>` from the calling shoot's namespace.
	// Mirrors the healthcheck's findSeedShootNamespace fallback.
	if seedShootNS == "" && seedName != "" {
		ns := opts.Infrastructure.Namespace
		const prefix = "shoot--"
		if strings.HasPrefix(ns, prefix) {
			rest := ns[len(prefix):]
			if sep := strings.Index(rest, "--"); sep >= 0 {
				project := rest[:sep]
				seedShootNS = fmt.Sprintf("%s%s--%s", prefix, project, seedName)
			}
		}
	}

	flowContext := &FlowContext{
		log:                opts.Log,
		state:              whiteboard,
		namespace:          opts.Infrastructure.Namespace,
		infraSpec:          opts.Infrastructure.Spec,
		config:             infraConfig,
		seedConfig:         seedConfig,
		seedNodesCIDR:      seedNodesCIDR,
		seedName:           seedName,
		shootName:          opts.Shoot.Name,
		seedShootNamespace: seedShootNS,
		peerShootCIDRs:     peerShootCIDRs,
		isManagedSeedShoot: opts.IsManagedSeedShoot,
		gardenAPIDomain:    gardenAPIDomain,
		updater:            awsclient.NewUpdater(opts.AwsClient, infraConfig.IgnoreTags),
		infra:              opts.Infrastructure,
		client:             opts.AwsClient,
		runtimeClient:      opts.RuntimeClient,
		networking:         opts.Shoot.Spec.Networking,
		shootUUID:          string(opts.Shoot.UID),
		recorder:           opts.Recorder,
	}
	flowContext.commonTags = awsclient.Tags{
		flowContext.tagKeyCluster(): TagValueCluster,
		TagKeyName:                  opts.Infrastructure.Namespace,
	}
	return flowContext, nil
}

// event emits a Kubernetes Event on the Infrastructure resource if a recorder is available.
func (c *FlowContext) event(eventType, reason, messageFmt string, args ...interface{}) {
	if c.recorder == nil {
		return
	}
	c.recorder.Eventf(c.infra, eventType, reason, messageFmt, args...)
}

// cidrsOverlap returns true if two CIDR blocks overlap.
func cidrsOverlap(a, b string) bool {
	_, netA, errA := net.ParseCIDR(a)
	_, netB, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return false
	}
	return netA.Contains(netB.IP) || netB.Contains(netA.IP)
}

func (c *FlowContext) persistState(ctx context.Context) error {
	return PatchProviderStatusAndState(ctx, c.runtimeClient, c.infra, c.networking, nil, c.computeInfrastructureState(), c.getEgressCIDRs(), c.state.Get(IdentifierVpcIPv6CidrBlock), c.state.Get(IdentifierServiceCIDR))
}

// PatchProviderStatusAndState patches the provider status and state of the infrastructure object
func PatchProviderStatusAndState(
	ctx context.Context,
	runtimeClient client.Client,
	infra *extensionsv1alpha1.Infrastructure,
	networking *v1beta1.Networking,
	status *awsv1alpha1.InfrastructureStatus,
	state *runtime.RawExtension,
	egressCIDRs []string,
	vpcIPv6CidrBlock *string,
	serviceCIDR *string,
) error {
	patch := client.MergeFrom(infra.DeepCopy())
	if status != nil {
		infra.Status.ProviderStatus = &runtime.RawExtension{Object: status}
		if egressCIDRs != nil {
			infra.Status.EgressCIDRs = egressCIDRs
		}

		infra.Status.Networking = &extensionsv1alpha1.InfrastructureStatusNetworking{}

		if vpcIPv6CidrBlock != nil && serviceCIDR != nil {
			infra.Status.Networking.Nodes = append(infra.Status.Networking.Nodes, *vpcIPv6CidrBlock)
			infra.Status.Networking.Pods = append(infra.Status.Networking.Pods, *vpcIPv6CidrBlock)
			infra.Status.Networking.Services = append(infra.Status.Networking.Services, *serviceCIDR)
			infra.Status.EgressCIDRs = append(infra.Status.EgressCIDRs, *vpcIPv6CidrBlock)
		}

		if networking != nil {
			if networking.Nodes != nil {
				infra.Status.Networking.Nodes = append(infra.Status.Networking.Nodes, *networking.Nodes)
			}
			if networking.Pods != nil {
				infra.Status.Networking.Pods = append(infra.Status.Networking.Pods, *networking.Pods)
			}
			if networking.Services != nil {
				infra.Status.Networking.Services = append(infra.Status.Networking.Services, *networking.Services)
			}
		}
	}

	if state != nil {
		infra.Status.State = state
	}

	// do not make a patch request if nothing has changed.
	if data, err := patch.Data(infra); err != nil {
		return fmt.Errorf("failed getting patch data for infra %s: %w", infra.Name, err)
	} else if string(data) == `{}` {
		return nil
	}

	return runtimeClient.Status().Patch(ctx, infra, patch)
}

func (c *FlowContext) computeInfrastructureStatus() *awsv1alpha1.InfrastructureStatus {
	return BuildInfrastructureStatus(c.state, c.config)
}

func (c *FlowContext) computeInfrastructureState() *runtime.RawExtension {
	return &runtime.RawExtension{
		Object: &awsv1alpha1.InfrastructureState{
			TypeMeta: metav1.TypeMeta{
				APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
				Kind:       "InfrastructureState",
			},
			Data: c.state.ExportAsFlatMap(),
		},
	}
}

// GetInfrastructureConfig returns the InfrastructureConfig object
func (c *FlowContext) GetInfrastructureConfig() *awsapi.InfrastructureConfig {
	return c.config
}

func (c *FlowContext) getEgressCIDRs() []string {
	if v := c.state.Get(IdentifierEgressCIDRs); v != nil {
		return strings.Split(*v, ",")
	}
	return nil
}

func (c *FlowContext) hasVPC() bool {
	return c.state.Get(IdentifierVPC) != nil
}

func (c *FlowContext) commonTagsWithSuffix(suffix string) awsclient.Tags {
	tags := c.commonTags.Clone()
	tags[TagKeyName] = fmt.Sprintf("%s-%s", c.namespace, suffix)
	return tags
}

// seedCanonicalTags returns the cluster + Name tags using the SEED shoot's
// namespace, suitable for resources whose canonical owner is the seed shoot
// rather than the calling child shoot. The seed VPC attachment, runtime VPC
// attachment, and globalVPC attachments are SHARED across all child shoots
// on a seed; tagging them with the seed shoot's namespace gives them a
// stable canonical identity regardless of which child reconciles first.
//
// Falls back to commonTagsWithSuffix (caller's namespace) when seedShootNamespace
// is unknown — preserves the legacy behavior so this can never produce empty
// or invalid tags.
func (c *FlowContext) seedCanonicalTags(suffix string) awsclient.Tags {
	if c.seedShootNamespace == "" {
		return c.commonTagsWithSuffix(suffix)
	}
	return awsclient.Tags{
		fmt.Sprintf(TagKeyClusterTemplate, c.seedShootNamespace): TagValueCluster,
		TagKeyName: fmt.Sprintf("%s-%s", c.seedShootNamespace, suffix),
	}
}

// retagToSeedCanonical brings the EC2 tags of a shared TGW attachment in line
// with the seed-canonical pattern. Used to migrate pre-fix-#1 attachments
// (created by a child shoot's reconcile, tagged with that child's namespace)
// to the canonical seed-shoot tags without re-creating the attachment.
//
// Idempotent: no-op when tags already match. Adds tags missing or differing
// from desired; removes any `kubernetes.io/cluster/<other-ns>` tags whose
// namespace doesn't match the seed shoot's. The Name tag is replaced via
// CreateTags (write wins) since AWS allows only one Name value per resource.
//
// Errors are logged and swallowed (best-effort) — retagging is purely
// observability/cleanup, never load-bearing for connectivity.
func (c *FlowContext) retagToSeedCanonical(ctx context.Context, log logr.Logger,
	tgwClient awsclient.Interface, attachmentID string,
	currentTags, desiredTags awsclient.Tags) {
	if c.seedShootNamespace == "" || attachmentID == "" {
		return
	}
	toAdd := awsclient.Tags{}
	for k, v := range desiredTags {
		if currentTags[k] != v {
			toAdd[k] = v
		}
	}
	toDelete := awsclient.Tags{}
	seedClusterKey := fmt.Sprintf(TagKeyClusterTemplate, c.seedShootNamespace)
	for k, v := range currentTags {
		if strings.HasPrefix(k, "kubernetes.io/cluster/") && k != seedClusterKey {
			toDelete[k] = v
		}
	}
	if len(toAdd) == 0 && len(toDelete) == 0 {
		return
	}
	log.Info("retagging shared TGW attachment to seed-canonical pattern",
		"attachmentId", attachmentID, "addingTags", toAdd, "deletingTags", toDelete)
	if len(toAdd) > 0 {
		if err := tgwClient.CreateEC2Tags(ctx, []string{attachmentID}, toAdd); err != nil {
			log.Info("retag CreateEC2Tags failed (continuing — tags are observability-only)",
				"attachmentId", attachmentID, "error", err.Error())
			return
		}
	}
	if len(toDelete) > 0 {
		if err := tgwClient.DeleteEC2Tags(ctx, []string{attachmentID}, toDelete); err != nil {
			log.Info("retag DeleteEC2Tags failed (continuing — stale cluster tag will be cleaned next reconcile)",
				"attachmentId", attachmentID, "error", err.Error())
		}
	}
}

func (c *FlowContext) tagKeyCluster() string {
	return fmt.Sprintf(TagKeyClusterTemplate, c.namespace)
}

func (c *FlowContext) clusterTags() awsclient.Tags {
	tags := awsclient.Tags{}
	tags[c.tagKeyCluster()] = TagValueCluster
	return tags
}

func (c *FlowContext) vpcEndpointServiceNamePrefix() string {
	return fmt.Sprintf("com.amazonaws.%s.", c.infraSpec.Region)
}

func (c *FlowContext) extractVpcEndpointName(item *awsclient.VpcEndpoint) string {
	return strings.TrimPrefix(item.ServiceName, c.vpcEndpointServiceNamePrefix())
}

func (c *FlowContext) zoneSuffixHelpers(zoneName string) *ZoneSuffixHelper {
	zoneChild := c.getSubnetZoneChild(zoneName)
	if suffix := zoneChild.Get(IdentifierZoneSuffix); suffix != nil {
		return &ZoneSuffixHelper{suffix: *suffix}
	}
	zones := c.state.GetChild(ChildIdZones)
	existing := sets.New[string]()
	for _, key := range zones.GetChildrenKeys() {
		otherChild := zones.GetChild(key)
		if suffix := otherChild.Get(IdentifierZoneSuffix); suffix != nil {
			existing.Insert(*suffix)
		}
	}
	for i := 0; ; i++ {
		suffix := fmt.Sprintf("z%d", i)
		if !existing.Has(suffix) {
			zoneChild.Set(IdentifierZoneSuffix, suffix)
			return &ZoneSuffixHelper{suffix: suffix}
		}
	}
}

func (c *FlowContext) isCsiEfsEnabled() bool {
	return c.config != nil && c.config.ElasticFileSystem != nil && c.config.ElasticFileSystem.Enabled
}

// isSeedTGWEnabled returns true if the seed has a TGW configured and enabled.
func (c *FlowContext) isSeedTGWEnabled() bool {
	return c.seedConfig != nil && c.seedConfig.TransitGateway != nil && c.seedConfig.TransitGateway.Enabled
}

// isShootTGWEnabled returns true if the shoot has its own TGW configured and enabled.
func (c *FlowContext) isShootTGWEnabled() bool {
	return c.config != nil && c.config.Networks.TransitGateway != nil && c.config.Networks.TransitGateway.Enabled
}

// isSharedIsolationMode returns true if the seed TGW is configured for "shared" isolation mode.
// In shared mode, all VPCs (seed + shoots) associate and propagate to a single route table.
func (c *FlowContext) isSharedIsolationMode() bool {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil {
		return false
	}
	return c.seedConfig.TransitGateway.IsolationMode == "shared"
}

// hasTGWStateResources returns true if the infrastructure state has any TGW-related keys,
// indicating TGW resources were previously created and may need cleanup.
func (c *FlowContext) hasTGWStateResources() bool {
	return c.state.Get(IdentifierTransitGatewayAttachment) != nil ||
		c.state.Get(IdentifierTransitGatewayID) != nil ||
		c.state.Get(IdentifierTransitGatewayHubRouteTable) != nil ||
		c.state.Get(IdentifierTransitGatewaySpokeRouteTable) != nil ||
		c.state.Get(IdentifierTransitGatewaySharedRouteTable) != nil ||
		c.state.Get(IdentifierSeedVPCTransitGatewayAttachment) != nil
}

// hasTGWConfigResources returns true if the seed config has TGW-related fields set
// (ID, route table IDs, globalVPCs) even when enabled=false. This indicates TGW was
// previously configured and resources may exist that need cleanup.
// Used alongside hasTGWStateResources() for the cleanup condition — the seed shoot's
// state may not have TGW keys (they're stored in child shoot states), but the config
// still has the TGW IDs, signaling that cleanup is needed.
func (c *FlowContext) hasTGWConfigResources() bool {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil {
		return false
	}
	tgw := c.seedConfig.TransitGateway
	return tgw.ID != nil ||
		tgw.HubRouteTableID != nil ||
		tgw.SpokeRouteTableID != nil ||
		tgw.RouteTableID != nil ||
		len(tgw.GlobalVPCs) > 0
}

// initEffectiveGlobalVPCs initializes the effective globalVPCs list from config.
// Called once during ensureTransitGateway, before discovery runs.
// In managed TGW mode, also auto-synthesizes the runtime VPC as a globalVPC
// so buildTGWRoutes adds the runtime VPC CIDR route in child shoot VPC route tables.
func (c *FlowContext) initEffectiveGlobalVPCs() {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil {
		return
	}
	vpcs := make([]awsapi.GlobalVPC, len(c.seedConfig.TransitGateway.GlobalVPCs))
	copy(vpcs, c.seedConfig.TransitGateway.GlobalVPCs)

	// Auto-discover the runtime VPC CIDR from Garden API DNS so buildTGWRoutes
	// adds the runtime VPC route in shoot VPC route tables. Needed in ALL TGW modes —
	// in ref mode, the shoot VPC still needs an explicit route to the runtime VPC
	// (TGW RT propagation only tells the TGW how to route, not the VPC).
	if c.gardenAPIDomain != "" {
		if runtimeCIDR := c.resolveRuntimeVPCCIDR(); runtimeCIDR != "" {
			vpcs = append(vpcs, awsapi.GlobalVPC{
				Name:  "runtime (auto-discovered)",
				CIDRs: []string{runtimeCIDR},
				// AttachmentID left nil — ensureGlobalVPCAssociations handles nil AttachmentID
				// by looking up the attachment from the VPC. For buildTGWRoutes, only CIDRs matter.
			})
		}
	}

	c.resolvedEffectiveGlobalVPCs = vpcs
}

// shouldCleanupTGW returns true if TGW cleanup should run.
// This uses a broad condition: run cleanup whenever TGW is disabled AND there's any
// indication that TGW resources may exist (from state, config, or just the fact that
// the seed has a node CIDR we can discover). The cleanup function itself is idempotent —
// if there's nothing to clean, it returns immediately after a few discovery API calls.
func (c *FlowContext) shouldCleanupTGW() bool {
	if c.isSeedTGWEnabled() {
		return false // TGW is enabled — ensure path handles everything
	}
	// TGW is disabled. Check if resources might exist from a previous enabled state.
	return c.hasTGWStateResources() || c.hasTGWConfigResources() || c.seedNodesCIDR != ""
}

// resolveRuntimeVPCCIDR resolves the Garden API hostname to find the runtime VPC CIDR.
// This is a lightweight version of discoverRuntimeVPC used by initEffectiveGlobalVPCs.
// Returns empty string if resolution fails (non-fatal — routes just won't be added).
func (c *FlowContext) resolveRuntimeVPCCIDR() string {
	if c.gardenAPIDomain == "" {
		return ""
	}
	ips, err := net.LookupHost(c.gardenAPIDomain)
	if err != nil || len(ips) == 0 {
		return ""
	}
	targetIP := net.ParseIP(ips[0])
	if targetIP == nil {
		return ""
	}
	// Find VPC containing this IP. Use the default client (same account for now).
	vpcs, err := c.client.FindVpcsByFilters(context.Background(), nil)
	if err != nil {
		return ""
	}
	for _, vpc := range vpcs {
		_, ipNet, parseErr := net.ParseCIDR(vpc.CidrBlock)
		if parseErr != nil {
			continue
		}
		if ipNet.Contains(targetIP) {
			return vpc.CidrBlock
		}
	}
	return ""
}

// isManagedTGWMode returns true if the seed creates its own TGW (ID is nil, createConfig may be set).
// In managed mode, the extension also needs to attach the runtime VPC to the managed TGW
// so the gardenlet and child shoots can reach the Garden API.
func (c *FlowContext) isManagedTGWMode() bool {
	return c.isSeedTGWEnabled() && c.seedConfig.TransitGateway.ID == nil
}

// shouldAttachSeedVPC returns true if the seed's own VPC should be attached to the TGW.
// This is implicit when TGW is enabled and the Seed has a node CIDR — no config field needed.
func (c *FlowContext) shouldAttachSeedVPC() bool {
	return c.isSeedTGWEnabled() && c.seedNodesCIDR != ""
}

// shouldDeleteManagedOnDisable returns true if auto-created TGW resources should be
// deleted when TGW is disabled. Defaults to false (preserve, safe) when config is removed entirely.
func (c *FlowContext) shouldDeleteManagedOnDisable() bool {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil {
		// Config block removed entirely — can't read deleteManagedOnDisable, default to preserve (safe).
		return false
	}
	return c.seedConfig.TransitGateway.DeleteManagedOnDisable
}

// gvpcAttachmentChild returns the Whiteboard child holding GlobalVPCAttachment/* values.
//
// State key layout note: IdentifierGlobalVPCAttachmentPrefix is "GlobalVPCAttachment/"
// with a trailing slash. The Whiteboard's ImportFromFlatMap (whiteboard.go:199)
// splits flat-map keys by Separator (= "/") into a hierarchy. So a value
// persisted as "GlobalVPCAttachment/management" → "x" comes back into memory
// as root.children["GlobalVPCAttachment"].data["management"], NOT as
// root.data["GlobalVPCAttachment/management"]. Reading via GetChild + Get
// works regardless of whether we're inside the same reconcile that set the
// value or a later one after persist+restore. Reading via the literal-slash
// key only works within the same reconcile (before persist). Always use
// these helpers for GlobalVPCAttachment / GlobalVPCAttachmentManaged state.
func (c *FlowContext) gvpcAttachmentChild() shared.Whiteboard {
	return c.state.GetChild(strings.TrimSuffix(IdentifierGlobalVPCAttachmentPrefix, "/"))
}

// gvpcManagedChild returns the Whiteboard child holding GlobalVPCAttachmentManaged/* values.
func (c *FlowContext) gvpcManagedChild() shared.Whiteboard {
	return c.state.GetChild(strings.TrimSuffix(IdentifierGlobalVPCAttachmentManagedPrefix, "/"))
}

// getGlobalVPCAttachmentID returns the persisted attachment ID for a managed globalVPC,
// reading via the hierarchical child first and falling back to the literal-slash root
// key (covers the case where the value was set in the same reconcile and not yet
// persisted+restored).
func (c *FlowContext) getGlobalVPCAttachmentID(name string) *string {
	if v := c.gvpcAttachmentChild().Get(name); v != nil {
		return v
	}
	return c.state.Get(IdentifierGlobalVPCAttachmentPrefix + name)
}

// setGlobalVPCAttachmentID writes the attachment ID to the hierarchical child.
// Persist will export it under "GlobalVPCAttachment/<name>" in the flat map; the
// next reconcile's Import re-creates the same hierarchy, so the read path stays
// consistent across reconciles.
func (c *FlowContext) setGlobalVPCAttachmentID(name, attachmentID string) {
	c.gvpcAttachmentChild().Set(name, attachmentID)
	// Clear any legacy literal-slash key at root (left over from older code paths
	// that wrote it both ways during restore-cycles). Without this, the legacy
	// value at root could shadow the new hierarchical one if a reader looks at
	// root first.
	c.state.Delete(IdentifierGlobalVPCAttachmentPrefix + name)
}

// setGlobalVPCAttachmentManaged marks an attachment as managed (created by us).
func (c *FlowContext) setGlobalVPCAttachmentManaged(name string, managed bool) {
	val := ""
	if managed {
		val = "true"
	}
	c.gvpcManagedChild().Set(name, val)
	c.state.Delete(IdentifierGlobalVPCAttachmentManagedPrefix + name)
}

// getGlobalVPCAttachmentManaged returns true if the attachment is marked managed.
func (c *FlowContext) getGlobalVPCAttachmentManaged(name string) bool {
	if v := c.gvpcManagedChild().Get(name); v != nil && *v == "true" {
		return true
	}
	if v := c.state.Get(IdentifierGlobalVPCAttachmentManagedPrefix + name); v != nil && *v == "true" {
		return true
	}
	return false
}

// deleteGlobalVPCAttachmentState clears all state for a globalVPC's attachment.
// Hits both the child and the literal-slash root key for forward + backward
// compatibility.
func (c *FlowContext) deleteGlobalVPCAttachmentState(name string) {
	c.gvpcAttachmentChild().Delete(name)
	c.gvpcManagedChild().Delete(name)
	c.state.Delete(IdentifierGlobalVPCAttachmentPrefix + name)
	c.state.Delete(IdentifierGlobalVPCAttachmentManagedPrefix + name)
}

// listGlobalVPCAttachmentNames returns the set of globalVPC names that have any
// attachment-state entry, scanning both the hierarchical child and any legacy
// literal-slash root keys.
func (c *FlowContext) listGlobalVPCAttachmentNames() []string {
	seen := map[string]struct{}{}
	for _, name := range c.gvpcAttachmentChild().Keys() {
		seen[name] = struct{}{}
	}
	for _, name := range c.gvpcManagedChild().Keys() {
		seen[name] = struct{}{}
	}
	for _, key := range c.state.Keys() {
		if name, ok := strings.CutPrefix(key, IdentifierGlobalVPCAttachmentPrefix); ok {
			seen[name] = struct{}{}
			continue
		}
		if name, ok := strings.CutPrefix(key, IdentifierGlobalVPCAttachmentManagedPrefix); ok {
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	return out
}

// hasManagedGlobalVPCAttachments returns true if any managed globalVPC attachments exist in state.
func (c *FlowContext) hasManagedGlobalVPCAttachments() bool {
	for _, name := range c.listGlobalVPCAttachmentNames() {
		if c.getGlobalVPCAttachmentManaged(name) {
			return true
		}
	}
	return false
}

// newClientFromCredentialsRef creates an AWS client from a GlobalVPCCredentialsRef.
// Three modes:
//  1. Secret only (Name+Namespace, no AssumeRoleARN): static keys used directly.
//  2. AssumeRole only (AssumeRoleARN, no Name/Namespace): shoot's own credentials
//     call sts:AssumeRole to get temporary creds in the target account.
//  3. Secret + AssumeRole (both): keys from the Secret call sts:AssumeRole.
//     This supports intermediary accounts — e.g., keys for Account A assume a
//     role in Account B that has the required TGW/VPC permissions.
func (c *FlowContext) newClientFromCredentialsRef(ctx context.Context, ref *awsapi.GlobalVPCCredentialsRef, description string) (awsclient.Interface, error) {
	hasSecretRef := ref.Name != "" && ref.Namespace != ""
	hasAssumeRole := ref.AssumeRoleARN != nil && *ref.AssumeRoleARN != ""

	externalID := ""
	if ref.ExternalID != nil {
		externalID = *ref.ExternalID
	}

	if hasSecretRef && hasAssumeRole {
		// Mode 3: Secret keys → sts:AssumeRole.
		secretRef := corev1.SecretReference{Name: ref.Name, Namespace: ref.Namespace}
		crossClient, err := awspkg.NewClientFromAssumeRole(ctx, c.runtimeClient, secretRef, *ref.AssumeRoleARN, externalID, c.infraSpec.Region)
		if err != nil {
			return nil, fmt.Errorf("failed to create AssumeRole AWS client for %s (secret %s/%s → role %s): %w",
				description, ref.Namespace, ref.Name, *ref.AssumeRoleARN, err)
		}
		return crossClient, nil
	}

	if hasAssumeRole {
		// Mode 2: Shoot's own credentials → sts:AssumeRole.
		crossClient, err := awspkg.NewClientFromAssumeRole(ctx, c.runtimeClient, c.infraSpec.SecretRef, *ref.AssumeRoleARN, externalID, c.infraSpec.Region)
		if err != nil {
			return nil, fmt.Errorf("failed to create AssumeRole AWS client for %s (shoot creds → role %s): %w",
				description, *ref.AssumeRoleARN, err)
		}
		return crossClient, nil
	}

	// Mode 1: Static keys from Secret, used directly.
	secretRef := corev1.SecretReference{Name: ref.Name, Namespace: ref.Namespace}
	crossClient, err := awspkg.NewClientFromSecretRef(ctx, c.runtimeClient, secretRef, c.infraSpec.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create cross-account AWS client for %s (secret %s/%s): %w",
			description, ref.Namespace, ref.Name, err)
	}
	return crossClient, nil
}

// getGlobalVPCClient returns an AWS client for a globalVPC. If credentialsRef is set,
// creates a cross-account client using the referenced credentials. Otherwise returns the
// default shoot client.
func (c *FlowContext) getGlobalVPCClient(ctx context.Context, gvpc *awsapi.GlobalVPC) (awsclient.Interface, error) {
	if gvpc.CredentialsRef == nil {
		return c.client, nil
	}
	return c.newClientFromCredentialsRef(ctx, gvpc.CredentialsRef, fmt.Sprintf("globalVPC %q", gvpc.Name))
}

// getSeedVPCClient returns the AWS client for seed VPC operations. If the seed config
// has SeedVPCCredentialsRef (cross-account), creates a client with those credentials.
// Otherwise returns the default shoot client (same account).
func (c *FlowContext) getSeedVPCClient(ctx context.Context) (awsclient.Interface, error) {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil || c.seedConfig.TransitGateway.SeedVPCCredentialsRef == nil {
		return c.client, nil
	}
	return c.newClientFromCredentialsRef(ctx, c.seedConfig.TransitGateway.SeedVPCCredentialsRef, "seed VPC")
}

// getTGWClient returns the AWS client for Transit Gateway operations. If the seed config
// has TransitGatewayCredentialsRef (cross-account TGW), creates a client with those
// credentials and caches it for the duration of this reconcile. Otherwise returns the
// default shoot client (same account).
func (c *FlowContext) getTGWClient(ctx context.Context) (awsclient.Interface, error) {
	if c.seedConfig == nil || c.seedConfig.TransitGateway == nil || c.seedConfig.TransitGateway.TransitGatewayCredentialsRef == nil {
		return c.client, nil
	}
	// Lazy cache — create once per reconcile.
	if c.cachedTGWClient != nil {
		return c.cachedTGWClient, nil
	}
	crossClient, err := c.newClientFromCredentialsRef(ctx, c.seedConfig.TransitGateway.TransitGatewayCredentialsRef, "TGW")
	if err != nil {
		return nil, err
	}
	c.cachedTGWClient = crossClient
	return crossClient, nil
}

// ZoneSuffixHelper provides methods to create suffices for various resources
type ZoneSuffixHelper struct {
	suffix string
}

// GetSuffixSubnetWorkers builds the suffix for the workers subnet
func (h *ZoneSuffixHelper) GetSuffixSubnetWorkers() string {
	return fmt.Sprintf("nodes-%s", h.suffix)
}

// GetSuffixSubnetPublic builds the suffix for the public utility subnet
func (h *ZoneSuffixHelper) GetSuffixSubnetPublic() string {
	return fmt.Sprintf("public-utility-%s", h.suffix)
}

// GetSuffixSubnetPrivate builds the suffix for the private utility subnet
func (h *ZoneSuffixHelper) GetSuffixSubnetPrivate() string {
	return fmt.Sprintf("private-utility-%s", h.suffix)
}

// GetSuffixElasticIP builds the suffix for the elastic IP of the NAT gateway
func (h *ZoneSuffixHelper) GetSuffixElasticIP() string {
	return fmt.Sprintf("eip-natgw-%s", h.suffix)
}

// GetSuffixNATGateway builds the suffix for the NAT gateway
func (h *ZoneSuffixHelper) GetSuffixNATGateway() string {
	return fmt.Sprintf("natgw-%s", h.suffix)
}
