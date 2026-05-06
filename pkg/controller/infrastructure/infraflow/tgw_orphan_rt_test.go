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

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
)

const (
	rtCleanupTGW = "tgw-clean"
	rtCleanupNS  = "shoot--garden--unit"
)

// rtInfo builds a TGW route table info entry for the cleanup tests.
// nameSuffix should match the production naming convention recognised by
// cleanOrphanedRouteTables: "-tgw-rt-hub", "-tgw-rt-spoke", or "-tgw-rt-shared".
func rtInfo(id, nameSuffix, tgwID string) *awsclient.TransitGatewayRouteTableInfo {
	return &awsclient.TransitGatewayRouteTableInfo{
		TransitGatewayRouteTableId: id,
		TransitGatewayId:           tgwID,
		Tags:                       awsclient.Tags{"Name": "anything" + nameSuffix},
	}
}

// withSharedIsolation mutates the given FlowContext to select the given
// isolation mode in its seed config. Other fields are left at zero values.
func withSharedIsolation(c *FlowContext, mode string) {
	c.seedConfig = &awsapi.SeedProviderConfig{
		TransitGateway: &awsapi.TransitGateway{
			Enabled:       true,
			IsolationMode: mode,
		},
	}
}

var _ = Describe("cleanOrphanedRouteTables", func() {
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

	It("returns false when the AWS RT lookup errors", func() {
		withSharedIsolation(c, "")
		mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).
			Return(nil, errors.New("AWS list failed"))
		Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
			To(BeFalse())
	})

	It("returns false on a clean hub-spoke layout (one hub + one spoke, no orphans)", func() {
		withSharedIsolation(c, "hub-spoke")
		mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
			[]*awsclient.TransitGatewayRouteTableInfo{
				rtInfo("rtb-hub", "-tgw-rt-hub", rtCleanupTGW),
				rtInfo("rtb-spoke", "-tgw-rt-spoke", rtCleanupTGW),
			}, nil,
		)
		// No DeleteTransitGatewayRouteTable expected.
		Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
			To(BeFalse())
	})

	It("returns false on a clean shared layout (single shared, no orphans)", func() {
		withSharedIsolation(c, "shared")
		mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
			[]*awsclient.TransitGatewayRouteTableInfo{
				rtInfo("rtb-shared", "-tgw-rt-shared", rtCleanupTGW),
			}, nil,
		)
		Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
			To(BeFalse())
	})

	Context("isolation switch leftovers", func() {
		It("hub-spoke mode: a leftover shared RT is an orphan and is deleted", func() {
			withSharedIsolation(c, "hub-spoke")
			mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
				[]*awsclient.TransitGatewayRouteTableInfo{
					rtInfo("rtb-hub", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-spoke", "-tgw-rt-spoke", rtCleanupTGW),
					rtInfo("rtb-shared-leftover", "-tgw-rt-shared", rtCleanupTGW),
				}, nil,
			)
			mockClient.EXPECT().DeleteTransitGatewayRouteTable(ctx, "rtb-shared-leftover").Return(nil)

			Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
				To(BeTrue())
		})

		It("shared mode: leftover hub and spoke RTs are orphans and are both deleted", func() {
			withSharedIsolation(c, "shared")
			mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
				[]*awsclient.TransitGatewayRouteTableInfo{
					rtInfo("rtb-shared", "-tgw-rt-shared", rtCleanupTGW),
					rtInfo("rtb-hub-leftover", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-spoke-leftover", "-tgw-rt-spoke", rtCleanupTGW),
				}, nil,
			)
			mockClient.EXPECT().DeleteTransitGatewayRouteTable(ctx, "rtb-hub-leftover").Return(nil)
			mockClient.EXPECT().DeleteTransitGatewayRouteTable(ctx, "rtb-spoke-leftover").Return(nil)

			Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
				To(BeTrue())
		})
	})

	Context("duplicate detection", func() {
		It("hub-spoke mode: when two hub RTs exist, keeps the first sorted and deletes the rest", func() {
			withSharedIsolation(c, "hub-spoke")
			mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
				[]*awsclient.TransitGatewayRouteTableInfo{
					// Sort order is alphabetical on ID — "rtb-hub-a" < "rtb-hub-b".
					rtInfo("rtb-hub-b", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-hub-a", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-spoke", "-tgw-rt-spoke", rtCleanupTGW),
				}, nil,
			)
			// Only the second-sorted hub RT should be deleted.
			mockClient.EXPECT().DeleteTransitGatewayRouteTable(ctx, "rtb-hub-b").Return(nil)

			Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
				To(BeTrue())
		})
	})

	Context("filters", func() {
		It("ignores RTs that belong to a different TGW", func() {
			withSharedIsolation(c, "hub-spoke")
			mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
				[]*awsclient.TransitGatewayRouteTableInfo{
					rtInfo("rtb-hub", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-spoke", "-tgw-rt-spoke", rtCleanupTGW),
					// Wrong TGW — must not be classified or deleted, even though it
					// looks like a shared RT (which would be an orphan in hub-spoke).
					rtInfo("rtb-shared-other-tgw", "-tgw-rt-shared", "tgw-different"),
				}, nil,
			)
			// No deletes — the foreign-TGW RT is filtered out before classification.

			Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
				To(BeFalse())
		})

		It("ignores RTs whose Name tag has no recognised TGW suffix", func() {
			withSharedIsolation(c, "hub-spoke")
			mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
				[]*awsclient.TransitGatewayRouteTableInfo{
					rtInfo("rtb-hub", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-spoke", "-tgw-rt-spoke", rtCleanupTGW),
					// Some other RT not following the naming convention — must be ignored.
					{
						TransitGatewayRouteTableId: "rtb-untagged",
						TransitGatewayId:           rtCleanupTGW,
						Tags:                       awsclient.Tags{"Name": "completely-different"},
					},
				}, nil,
			)
			// No deletes.
			Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
				To(BeFalse())
		})
	})

	Context("AWS-side safety", func() {
		It("treats IncorrectState as 'still in use' — orphan stays, function still reports drift", func() {
			withSharedIsolation(c, "hub-spoke")
			mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
				[]*awsclient.TransitGatewayRouteTableInfo{
					rtInfo("rtb-hub", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-spoke", "-tgw-rt-spoke", rtCleanupTGW),
					rtInfo("rtb-shared-busy", "-tgw-rt-shared", rtCleanupTGW),
				}, nil,
			)
			// AWS rejects the delete because attachments are still associated.
			// The function tolerates this — it does NOT forcibly disassociate
			// (which would create a connectivity gap), it simply leaves the
			// orphan for the next reconcile after attachments naturally migrate.
			mockClient.EXPECT().DeleteTransitGatewayRouteTable(ctx, "rtb-shared-busy").
				Return(awsCodeError("IncorrectState"))

			// Returns true because orphans were found (drift).
			Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
				To(BeTrue())
		})

		It("does not clear state keys when the only orphan delete failed", func() {
			withSharedIsolation(c, "hub-spoke")
			// Pre-set state pointing at the orphan RT — the function should NOT
			// clear the key when AWS refuses the delete (we'd lose tracking).
			c.state.Set(IdentifierTransitGatewaySharedRouteTable, "rtb-shared-busy")

			mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
				[]*awsclient.TransitGatewayRouteTableInfo{
					rtInfo("rtb-hub", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-spoke", "-tgw-rt-spoke", rtCleanupTGW),
					rtInfo("rtb-shared-busy", "-tgw-rt-shared", rtCleanupTGW),
				}, nil,
			)
			mockClient.EXPECT().DeleteTransitGatewayRouteTable(ctx, "rtb-shared-busy").
				Return(awsCodeError("IncorrectState"))

			Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
				To(BeTrue())
			Expect(c.state.Get(IdentifierTransitGatewaySharedRouteTable)).NotTo(BeNil())
		})

		It("clears state keys for an orphan that was successfully deleted", func() {
			withSharedIsolation(c, "hub-spoke")
			c.state.Set(IdentifierTransitGatewaySharedRouteTable, "rtb-shared-leftover")

			mockClient.EXPECT().FindTransitGatewayRouteTablesByTags(ctx, gomock.Any()).Return(
				[]*awsclient.TransitGatewayRouteTableInfo{
					rtInfo("rtb-hub", "-tgw-rt-hub", rtCleanupTGW),
					rtInfo("rtb-spoke", "-tgw-rt-spoke", rtCleanupTGW),
					rtInfo("rtb-shared-leftover", "-tgw-rt-shared", rtCleanupTGW),
				}, nil,
			)
			mockClient.EXPECT().DeleteTransitGatewayRouteTable(ctx, "rtb-shared-leftover").Return(nil)

			Expect(c.cleanOrphanedRouteTables(ctx, logr.Discard(), mockClient, rtCleanupTGW, rtCleanupNS)).
				To(BeTrue())
			Expect(c.state.Get(IdentifierTransitGatewaySharedRouteTable)).To(BeNil())
		})
	})
})
