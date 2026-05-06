// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"errors"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
)

const (
	sweepCurrentTGW   = "tgw-current"
	sweepAbandonedTGW = "tgw-abandoned"
	sweepVPCID        = "vpc-test"
	sweepManagedCIDR  = "10.50.0.0/16"
	sweepUserCIDR     = "192.168.0.0/16"
)

// routeOn builds a TGW route entry pointing at the given TGW with the given state.
func routeOn(tgwID, cidr, state string) *awsclient.Route {
	s := state
	return &awsclient.Route{
		DestinationCidrBlock: ptr.To(cidr),
		TransitGatewayId:     ptr.To(tgwID),
		State:                &s,
	}
}

// privateRT builds a route table tagged as private (the only kind the sweep touches).
func privateRT(routes []*awsclient.Route) *awsclient.RouteTable {
	return &awsclient.RouteTable{
		RouteTableId: "rtb-private",
		Tags:         awsclient.Tags{"Name": "shoot-private-zone-a"},
		Routes:       routes,
	}
}

var _ = Describe("sweepStaleRoutesToCurrentTGW", func() {
	var (
		ctx        context.Context
		ctrl       *gomock.Controller
		mockClient *mockawsclient.MockInterface
		c          *FlowContext
	)

	BeforeEach(func() {
		ctx = context.Background()
		ctrl = gomock.NewController(GinkgoT())
		mockClient = mockawsclient.NewMockInterface(ctrl)
		c = newTestFlowContext(mockClient)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Context("short-circuits", func() {
		It("returns false when currentTGWID is empty (no AWS calls)", func() {
			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, "",
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeFalse())
		})

		It("returns false when autoManagedCIDRs is empty (no AWS calls)", func() {
			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](), "test")
			Expect(result).To(BeFalse())
		})

		It("returns false when route table lookup errors", func() {
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return(nil, errors.New("AWS list failed"))
			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeFalse())
		})
	})

	Context("filters", func() {
		It("skips non-private route tables", func() {
			rt := &awsclient.RouteTable{
				RouteTableId: "rtb-public",
				Tags:         awsclient.Tags{"Name": "shoot-public-zone-a"},
				Routes:       []*awsclient.Route{routeOn(sweepAbandonedTGW, sweepManagedCIDR, "active")},
			}
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			// No ReplaceRoute expected — non-private RTs are out of scope.
			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeFalse())
		})

		It("skips routes already pointing at currentTGWID", func() {
			rt := privateRT([]*awsclient.Route{
				routeOn(sweepCurrentTGW, sweepManagedCIDR, "active"),
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			// No ReplaceRoute — already on the correct TGW.
			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeFalse())
		})

		It("skips routes with nil TransitGatewayId or nil DestinationCidrBlock", func() {
			rt := privateRT([]*awsclient.Route{
				{TransitGatewayId: nil, DestinationCidrBlock: ptr.To(sweepManagedCIDR)},
				{TransitGatewayId: ptr.To(sweepAbandonedTGW), DestinationCidrBlock: nil},
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			// No ReplaceRoute — both entries lack required fields.
			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeFalse())
		})
	})

	Context("Tier 1 — active stale (narrow CIDR scope)", func() {
		It("replaces an active stale route whose CIDR is in autoManagedCIDRs", func() {
			rt := privateRT([]*awsclient.Route{
				routeOn(sweepAbandonedTGW, sweepManagedCIDR, "active"),
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			mockClient.EXPECT().ReplaceRoute(ctx, "rtb-private", gomock.Any()).Return(nil)

			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeTrue())
			Expect(c.tgwSweepReplacesThisReconcile).To(Equal(1))
		})

		It("preserves user-route safety: skips active stale route whose CIDR is NOT auto-managed", func() {
			// This is the load-bearing invariant — narrow scope means we never
			// touch a user's custom-CIDR active route to a non-Gardener TGW.
			rt := privateRT([]*awsclient.Route{
				routeOn(sweepAbandonedTGW, sweepUserCIDR, "active"),
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			// No ReplaceRoute — must not touch user-managed CIDRs.

			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeFalse())
			Expect(c.tgwSweepReplacesThisReconcile).To(Equal(0))
		})
	})

	Context("Tier 2 — blackhole (ownership-proof gated)", func() {
		It("replaces a blackhole route when ownership is proven via state history", func() {
			c.state.GetChild(IdentifierPreviousTGWs).Set(sweepAbandonedTGW, "true")
			// CIDR is NOT in autoManagedCIDRs — ownership-proof alone is sufficient
			// for blackhole tier (captures cross-shoot CIDRs missed by static scope).
			rt := privateRT([]*awsclient.Route{
				routeOn(sweepAbandonedTGW, sweepUserCIDR, "blackhole"),
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			mockClient.EXPECT().ReplaceRoute(ctx, "rtb-private", gomock.Any()).Return(nil)

			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeTrue())
			Expect(c.tgwSweepReplacesThisReconcile).To(Equal(1))
		})

		It("skips blackhole route when ownership is definitively not ours", func() {
			c.tgwOwnershipCache = map[string]ownershipResult{
				sweepAbandonedTGW: {ours: false, transient: false},
			}
			rt := privateRT([]*awsclient.Route{
				routeOn(sweepAbandonedTGW, sweepUserCIDR, "blackhole"),
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			// No ReplaceRoute — emit TGWBlackholeUnverifiable instead, leave alone.

			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeFalse())
			Expect(c.tgwSweepReplacesThisReconcile).To(Equal(0))
			Expect(c.tgwDriftDetected).To(BeFalse())
		})

		It("defers the entry on transient ownership error and signals drift for next reconcile", func() {
			c.tgwOwnershipCache = map[string]ownershipResult{
				sweepAbandonedTGW: {transient: true},
			}
			rt := privateRT([]*awsclient.Route{
				routeOn(sweepAbandonedTGW, sweepUserCIDR, "blackhole"),
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			// No ReplaceRoute — defer this entry.

			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeFalse())
			Expect(c.tgwSweepReplacesThisReconcile).To(Equal(0))
			// Drift signal is critical: without it the completion gate has no
			// reason to requeue, and the transient blackhole stays unfixed.
			Expect(c.tgwDriftDetected).To(BeTrue())
		})
	})

	Context("per-reconcile cap", func() {
		It("aborts further work once tgwSweepReplacesThisReconcile reaches the cap", func() {
			// Pre-position so the cap fires after exactly one more replace.
			c.tgwSweepReplacesThisReconcile = maxSweepReplacesPerReconcile - 1
			c.state.GetChild(IdentifierPreviousTGWs).Set(sweepAbandonedTGW, "true")

			rt := privateRT([]*awsclient.Route{
				routeOn(sweepAbandonedTGW, "10.0.0.0/24", "blackhole"),
				routeOn(sweepAbandonedTGW, "10.0.1.0/24", "blackhole"),
				routeOn(sweepAbandonedTGW, "10.0.2.0/24", "blackhole"),
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			// Exactly ONE replace — cap halts the loop on the next iteration.
			mockClient.EXPECT().ReplaceRoute(ctx, "rtb-private", gomock.Any()).Return(nil).Times(1)

			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeTrue())
			Expect(c.tgwSweepReplacesThisReconcile).To(Equal(maxSweepReplacesPerReconcile))
		})
	})

	Context("error tolerance", func() {
		It("continues sweep past a single ReplaceRoute failure (counter only advances on success)", func() {
			c.state.GetChild(IdentifierPreviousTGWs).Set(sweepAbandonedTGW, "true")
			rt := privateRT([]*awsclient.Route{
				routeOn(sweepAbandonedTGW, "10.0.0.0/24", "blackhole"),
				routeOn(sweepAbandonedTGW, "10.0.1.0/24", "blackhole"),
			})
			mockClient.EXPECT().FindRouteTablesByFilters(ctx, gomock.Any()).
				Return([]*awsclient.RouteTable{rt}, nil)
			gomock.InOrder(
				mockClient.EXPECT().ReplaceRoute(ctx, "rtb-private", gomock.Any()).Return(errors.New("boom")),
				mockClient.EXPECT().ReplaceRoute(ctx, "rtb-private", gomock.Any()).Return(nil),
			)

			result := c.sweepStaleRoutesToCurrentTGW(
				ctx, logr.Discard(), mockClient, sweepVPCID, sweepCurrentTGW,
				sets.New[string](sweepManagedCIDR), "test")
			Expect(result).To(BeTrue())
			// Counter only advances for successful replaces, not for attempts.
			Expect(c.tgwSweepReplacesThisReconcile).To(Equal(1))
		})
	})
})
