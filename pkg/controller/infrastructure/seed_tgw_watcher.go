// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awspkg "github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// SeedTGWConfigChangedPredicate triggers only when a Seed's TGW configuration
// changes (enabled/disabled, isolation mode, TGW ID, globalVPCs, createConfig).
type SeedTGWConfigChangedPredicate struct {
	predicate.Funcs
}

// Update returns true only when the Seed's TGW config has changed.
func (p SeedTGWConfigChangedPredicate) Update(e event.UpdateEvent) bool {
	oldSeed, ok1 := e.ObjectOld.(*v1beta1.Seed)
	newSeed, ok2 := e.ObjectNew.(*v1beta1.Seed)
	if !ok1 || !ok2 {
		return false
	}

	oldConfig, _ := helper.SeedProviderConfigFromSeed(oldSeed)
	newConfig, _ := helper.SeedProviderConfigFromSeed(newSeed)

	if oldConfig == nil && newConfig == nil {
		return false
	}
	if oldConfig == nil || newConfig == nil {
		return true
	}
	if oldConfig.TransitGateway == nil && newConfig.TransitGateway == nil {
		return false
	}
	if oldConfig.TransitGateway == nil || newConfig.TransitGateway == nil {
		return true
	}

	return !reflect.DeepEqual(oldConfig.TransitGateway, newConfig.TransitGateway)
}

// Create returns false — initial Seed creation is handled by the normal flow.
func (p SeedTGWConfigChangedPredicate) Create(_ event.CreateEvent) bool {
	return false
}

// Delete returns false — Seed deletion is handled by the normal flow.
func (p SeedTGWConfigChangedPredicate) Delete(_ event.DeleteEvent) bool {
	return false
}

// effectiveTGWID returns a canonical identifier for the TGW mode:
// - referenced mode: the TGW ID string
// - managed mode: "managed"
// - TGW disabled: ""
func effectiveTGWID(tgw *awsapi.TransitGateway) string {
	if tgw == nil || !tgw.Enabled {
		return ""
	}
	if tgw.ID != nil && *tgw.ID != "" {
		return *tgw.ID
	}
	return "managed"
}

// seedToInfrastructureMapper returns a MapFunc that maps a Seed TGW config update
// to all AWS Infrastructure resources on this seed for re-reconciliation.
//
// When a TGW mode switch from managed to referenced is detected, the mapper
// pre-wires the seed VPC attachment on the new referenced TGW (RT association +
// propagation) BEFORE enqueuing infra reconciles. This prevents a deadlock where
// the managed seed's gardenlet loses connectivity during the switch because the
// seed VPC has no route through the new TGW.
func seedToInfrastructureMapper(seedClient client.Client, gardenClient client.Client) func(ctx context.Context, obj client.Object) []reconcile.Request {
	// Cache the last-seen effective TGW ID per seed to detect mode switches.
	var lastTGWID sync.Map

	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		logger := log.FromContext(ctx).WithName("seed-tgw-watcher")
		seed, ok := obj.(*v1beta1.Seed)
		if !ok {
			return nil
		}

		logger.Info("Seed TGW config changed, enqueuing all AWS Infrastructure resources",
			"seed", seed.Name)

		// Detect TGW mode switch (managed ↔ referenced).
		newConfig, _ := helper.SeedProviderConfigFromSeed(seed)
		var newTGW *awsapi.TransitGateway
		if newConfig != nil {
			newTGW = newConfig.TransitGateway
		}
		newID := effectiveTGWID(newTGW)

		if prev, loaded := lastTGWID.Swap(seed.Name, newID); loaded {
			oldID, _ := prev.(string)
			if oldID != newID && oldID != "" && newID != "" {
				// TGW mode switch detected. Pre-wire the seed VPC attachment
				// on the new TGW to prevent gardenlet connectivity loss.
				logger.Info("TGW mode switch detected, pre-wiring seed VPC attachment",
					"seed", seed.Name, "oldMode", oldID, "newMode", newID)
				preWireCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				if err := preWireSeedVPCOnNewTGW(preWireCtx, seedClient, seed, newConfig); err != nil {
					logger.Error(err, "Failed to pre-wire seed VPC on new TGW (will retry via normal reconcile)",
						"seed", seed.Name, "newMode", newID)
				} else {
					logger.Info("Successfully pre-wired seed VPC on new TGW",
						"seed", seed.Name, "newMode", newID)
				}
				cancel()
			}
		}

		// Trigger shoot reconciles for DWD recovery in a goroutine to avoid blocking
		// the controller-runtime informer. During TGW mode switches, garden API
		// connectivity may be disrupted, and triggerShootReconciles calls List+Patch
		// on the garden cluster — blocking the mapper would stall all events.
		// context.WithoutCancel detaches from the mapper's short-lived context but
		// preserves logger/trace values; the explicit 30s timeout bounds runtime.
		go func() {
			triggerCtx, triggerCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer triggerCancel()
			logger.Info("Triggering shoot reconciles for DWD recovery after TGW config change",
				"seed", seed.Name)
			if err := triggerShootReconciles(triggerCtx, gardenClient, seed.Name); err != nil {
				logger.Error(err, "Failed to trigger shoot reconciles for DWD recovery")
			}
		}()

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
			logger.Info("Enqueuing Infrastructure for TGW config reconcile",
				"infrastructure", infra.Name, "namespace", infra.Namespace)
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      infra.Name,
					Namespace: infra.Namespace,
				},
			})
		}

		logger.Info("Enqueued Infrastructure resources for TGW config change",
			"seed", seed.Name, "count", len(requests))
		return requests
	}
}

// preWireSeedVPCOnNewTGW ensures the seed VPC attachment on the target TGW has RT
// association and propagation set up, so that the managed seed's gardenlet retains
// connectivity to the Garden API during a TGW mode switch (managed↔referenced).
//
// For referenced TGW: uses the explicitly configured TGW ID and RT IDs.
// For managed TGW: discovers the TGW by seed shoot tags.
//
// This is a best-effort operation — errors are logged but do not block infra reconciles.
// The normal reconcile path will complete any missing setup.
func preWireSeedVPCOnNewTGW(ctx context.Context, seedClient client.Client, seed *v1beta1.Seed, config *awsapi.SeedProviderConfig) error {
	logger := log.FromContext(ctx).WithName("tgw-prewire")

	tgw := config.TransitGateway
	if tgw == nil {
		return fmt.Errorf("no TGW config")
	}

	// For referenced mode, TGW ID is explicit. For managed mode, we need to discover it.
	var tgwID string
	var discoverTGW bool
	if tgw.ID != nil && *tgw.ID != "" {
		tgwID = *tgw.ID
	} else {
		discoverTGW = true
	}

	// Resolve RT IDs.
	var associateRT string
	var propagateRTs []string

	isolationMode := tgw.IsolationMode
	if isolationMode == "" {
		isolationMode = "hub-spoke"
	}

	if isolationMode == "shared" {
		if tgw.RouteTableID != nil && *tgw.RouteTableID != "" {
			associateRT = *tgw.RouteTableID
			propagateRTs = append(propagateRTs, *tgw.RouteTableID)
		}
		// Also propagate to hub RT if available (for runtime VPC reachability).
		if tgw.HubRouteTableID != nil && *tgw.HubRouteTableID != "" {
			propagateRTs = append(propagateRTs, *tgw.HubRouteTableID)
		}
	} else {
		if tgw.HubRouteTableID != nil && *tgw.HubRouteTableID != "" {
			associateRT = *tgw.HubRouteTableID
			propagateRTs = append(propagateRTs, *tgw.HubRouteTableID)
		}
		if tgw.SpokeRouteTableID != nil && *tgw.SpokeRouteTableID != "" {
			propagateRTs = append(propagateRTs, *tgw.SpokeRouteTableID)
		}
		if tgw.RouteTableID != nil && *tgw.RouteTableID != "" {
			propagateRTs = append(propagateRTs, *tgw.RouteTableID)
		}
	}

	if associateRT == "" {
		return fmt.Errorf("no route table ID resolved for association (isolation=%s)", isolationMode)
	}

	logger.Info("Pre-wiring seed VPC on referenced TGW",
		"tgwID", tgwID, "isolation", isolationMode,
		"associateRT", associateRT, "propagateRTs", propagateRTs)

	// Find the seed shoot's Infrastructure resource to get the AWS secret.
	// Discover the namespace by finding Infrastructure with name matching the seed name,
	// rather than hardcoding the project name in the namespace.
	allInfra := &extensionsv1alpha1.InfrastructureList{}
	if err := seedClient.List(ctx, allInfra); err != nil {
		return fmt.Errorf("failed to list Infrastructure resources: %w", err)
	}
	var seedShootNS string
	for _, infra := range allInfra.Items {
		if infra.Name == seed.Name && infra.Spec.Type == "aws" {
			seedShootNS = infra.Namespace
			break
		}
	}
	if seedShootNS == "" {
		return fmt.Errorf("seed shoot Infrastructure not found for seed %s", seed.Name)
	}
	infraList := &extensionsv1alpha1.InfrastructureList{}
	if err := seedClient.List(ctx, infraList, client.InNamespace(seedShootNS)); err != nil {
		return fmt.Errorf("failed to list Infrastructure in namespace %s: %w", seedShootNS, err)
	}

	var seedInfra *extensionsv1alpha1.Infrastructure
	for i := range infraList.Items {
		if infraList.Items[i].Spec.Type == "aws" {
			seedInfra = &infraList.Items[i]
			break
		}
	}
	if seedInfra == nil {
		return fmt.Errorf("no AWS Infrastructure found in namespace %s", seedShootNS)
	}

	// Create AWS client from the seed shoot's secret.
	secretRef := corev1.SecretReference{
		Name:      seedInfra.Spec.SecretRef.Name,
		Namespace: seedInfra.Spec.SecretRef.Namespace,
	}
	region := seedInfra.Spec.Region
	awsClient, err := awspkg.NewClientFromSecretRef(ctx, seedClient, secretRef, region)
	if err != nil {
		return fmt.Errorf("failed to create AWS client from secret %s/%s: %w", secretRef.Namespace, secretRef.Name, err)
	}

	// If TransitGatewayCredentialsRef is set, create a separate TGW client.
	tgwClient := awsClient
	if tgw.TransitGatewayCredentialsRef != nil {
		tgwSecretRef := corev1.SecretReference{
			Name:      tgw.TransitGatewayCredentialsRef.Name,
			Namespace: tgw.TransitGatewayCredentialsRef.Namespace,
		}
		tgwClient, err = awspkg.NewClientFromSecretRef(ctx, seedClient, tgwSecretRef, region)
		if err != nil {
			return fmt.Errorf("failed to create TGW client from TransitGatewayCredentialsRef: %w", err)
		}
	}

	// Find the seed VPC from the seed's nodes CIDR.
	if seed.Spec.Networks.Nodes == nil || *seed.Spec.Networks.Nodes == "" {
		return fmt.Errorf("seed %s has no nodes CIDR", seed.Name)
	}
	seedNodesCIDR := *seed.Spec.Networks.Nodes
	seedVPCs, err := awsClient.FindVpcsByFilters(ctx, []ec2types.Filter{
		{Name: aws.String("cidr-block-association.cidr-block"), Values: []string{seedNodesCIDR}},
	})
	if err != nil || len(seedVPCs) == 0 {
		return fmt.Errorf("failed to discover seed VPC from CIDR %s: %v (found %d)", seedNodesCIDR, err, len(seedVPCs))
	}
	seedVpcID := seedVPCs[0].VpcId
	logger.Info("Discovered seed VPC", "vpcId", seedVpcID, "cidr", seedNodesCIDR)

	// For managed mode, discover the TGW by finding the seed VPC's TGW attachment.
	if discoverTGW {
		allAtts, attErr := tgwClient.FindTransitGatewayVPCAttachments(ctx, "", seedVpcID)
		if attErr != nil {
			return fmt.Errorf("failed to discover managed TGW from seed VPC attachments: %w", attErr)
		}
		// Find attachment tagged with the seed shoot namespace.
		seedShootTag := fmt.Sprintf("kubernetes.io/cluster/%s", seedShootNS)
		for _, att := range allAtts {
			if _, ok := att.Tags[seedShootTag]; ok {
				tgwID = att.TransitGatewayId
				logger.Info("Discovered managed TGW from seed VPC attachment tags",
					"tgwID", tgwID, "attachmentId", att.TransitGatewayAttachmentId)
				break
			}
		}
		if tgwID == "" {
			logger.Info("No managed TGW found for seed VPC — may not exist yet, infra reconcile will create it",
				"seedVpcId", seedVpcID)
			return nil
		}

		// For managed mode, discover RT IDs by tags on the TGW.
		if associateRT == "" {
			tgwRTs, rtErr := tgwClient.FindTransitGatewayRouteTablesByTags(ctx, awsclient.Tags{
				fmt.Sprintf("kubernetes.io/cluster/%s", seedShootNS): "1",
			})
			if rtErr == nil {
				for _, rt := range tgwRTs {
					if rt.TransitGatewayId == tgwID {
						rtName := rt.Tags["Name"]
						if strings.Contains(rtName, "shared") {
							associateRT = rt.TransitGatewayRouteTableId
							propagateRTs = append(propagateRTs, rt.TransitGatewayRouteTableId)
						} else if strings.Contains(rtName, "hub") {
							propagateRTs = append(propagateRTs, rt.TransitGatewayRouteTableId)
						} else if strings.Contains(rtName, "spoke") {
							propagateRTs = append(propagateRTs, rt.TransitGatewayRouteTableId)
						}
					}
				}
			}
			// If still no association RT, use the first one found.
			if associateRT == "" && len(propagateRTs) > 0 {
				associateRT = propagateRTs[0]
			}
		}
		if associateRT == "" {
			logger.Info("No route tables found on managed TGW — infra reconcile will create them",
				"tgwID", tgwID)
			return nil
		}
	}

	logger.Info("Pre-wiring seed VPC on target TGW",
		"tgwID", tgwID, "isolation", isolationMode,
		"associateRT", associateRT, "propagateRTs", propagateRTs)

	// Find existing seed VPC attachment on the new TGW.
	attachments, err := tgwClient.FindTransitGatewayVPCAttachments(ctx, tgwID, seedVpcID)
	if err != nil {
		return fmt.Errorf("failed to find seed VPC attachments on TGW %s: %w", tgwID, err)
	}

	var attachmentID string
	if len(attachments) > 0 {
		attachmentID = attachments[0].TransitGatewayAttachmentId
		logger.Info("Found existing seed VPC attachment on target TGW", "attachmentId", attachmentID)
	} else {
		// Attachment doesn't exist — we can't create it here because we may not have
		// the right subnets. The infra reconcile will handle creation. But we should
		// still try to find it by listing all attachments on the TGW.
		allAttachments, listErr := tgwClient.ListTransitGatewayVPCAttachments(ctx, tgwID)
		if listErr != nil {
			return fmt.Errorf("failed to list TGW attachments: %w", listErr)
		}
		for _, att := range allAttachments {
			if att.VpcId == seedVpcID {
				attachmentID = att.TransitGatewayAttachmentId
				logger.Info("Found seed VPC attachment via list", "attachmentId", attachmentID)
				break
			}
		}
		if attachmentID == "" {
			logger.Info("No seed VPC attachment found on target TGW — infra reconcile will create it",
				"tgwID", tgwID, "seedVpcId", seedVpcID)
			return nil
		}
	}

	// Associate with the target RT (ignore AlreadyAssociated).
	currentRT, _ := tgwClient.GetTransitGatewayAttachmentAssociation(ctx, attachmentID)
	if currentRT == "" {
		logger.Info("Associating seed VPC attachment with route table", "attachmentId", attachmentID, "routeTable", associateRT)
		if err := tgwClient.AssociateTransitGatewayRouteTable(ctx, associateRT, attachmentID); err != nil {
			if code := awsclient.GetAWSAPIErrorCode(err); code != "Resource.AlreadyAssociated" {
				return fmt.Errorf("failed to associate seed VPC attachment with RT %s: %w", associateRT, err)
			}
		}
	} else if currentRT != associateRT {
		// Already associated with a different RT. Don't disassociate (dangerous).
		// Just add propagation for connectivity.
		logger.Info("Seed VPC attachment already on different RT, adding propagation only",
			"currentRT", currentRT, "targetRT", associateRT)
	} else {
		logger.Info("Seed VPC attachment already correctly associated", "routeTable", associateRT)
	}

	// Enable propagation to all target RTs.
	for _, rtID := range propagateRTs {
		logger.Info("Enabling propagation to route table", "attachmentId", attachmentID, "routeTable", rtID)
		if err := tgwClient.EnableTransitGatewayRouteTablePropagation(ctx, rtID, attachmentID); err != nil {
			if code := awsclient.GetAWSAPIErrorCode(err); code != "TransitGatewayRouteTablePropagation.Duplicate" {
				logger.Error(err, "Failed to enable propagation (non-fatal)", "routeTable", rtID)
			}
		}
	}

	logger.Info("Pre-wiring complete", "attachmentId", attachmentID, "tgwID", tgwID)
	return nil
}
