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
	invTGWID         = "tgw-current"
	invHubRT         = "tgw-rtb-hub"
	invSharedRT      = "tgw-rtb-shared"
	invSpokeRT       = "tgw-rtb-spoke"
	invForeignRT     = "tgw-rtb-foreign"
	invSeedAttID     = "tgw-attach-seed"
	invRuntimeAttID  = "tgw-attach-runtime"
	invForeignTGW    = "tgw-other"
	invForeignAttID  = "tgw-attach-on-foreign-tgw"
)

// withTGWConfig mutates the given FlowContext with seed config + resolved
// route-table IDs ready for the topology invariant to run.
func withTGWConfig(c *FlowContext, isolation string) {
	c.seedConfig = &awsapi.SeedProviderConfig{
		TransitGateway: &awsapi.TransitGateway{
			Enabled:       true,
			IsolationMode: isolation,
		},
	}
	c.resolvedTGWID = invTGWID
	c.resolvedHubRouteTableID = invHubRT
	c.resolvedSharedRouteTableID = invSharedRT
	c.resolvedSpokeRouteTableID = invSpokeRT
}

// availableAttachmentOnOurTGW returns a TransitGatewayVPCAttachment with the
// state and TGW ID expected for a healthy attachment we own.
func availableAttachmentOnOurTGW(id string) *awsclient.TransitGatewayVPCAttachment {
	return &awsclient.TransitGatewayVPCAttachment{
		TransitGatewayAttachmentId: id,
		TransitGatewayId:           invTGWID,
		State:                      "available",
	}
}

var _ = Describe("assertSeedSideAssociations", func() {
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

	Context("no-op short-circuits", func() {
		It("returns nil when tgwID is empty", func() {
			withTGWConfig(c, "hub-spoke")
			// No mock expectations — the function should return before hitting AWS.
			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), "")).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})

		It("returns nil when seed TGW is not enabled", func() {
			c.seedConfig = nil
			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})

		It("returns nil when expected RT is not yet resolved (managed bootstrap)", func() {
			withTGWConfig(c, "hub-spoke")
			c.resolvedHubRouteTableID = "" // not resolved yet
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})

		It("returns nil when no seed-side attachments are in state", func() {
			withTGWConfig(c, "hub-spoke")
			// state has nothing — collectSeedSideAttachments returns empty.
			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})
	})

	Context("happy path — attachment on the expected RT", func() {
		It("hub-spoke: seed VPC attachment on HUB RT, no drift detected", func() {
			withTGWConfig(c, "hub-spoke")
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return(invHubRT, nil)
			// No move calls.

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})

		It("shared: seed VPC attachment on SHARED RT, no drift detected", func() {
			withTGWConfig(c, "shared")
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return(invSharedRT, nil)

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})
	})

	Context("drift on canonical-owner reconcile (managed seed shoot)", func() {
		BeforeEach(func() {
			c.isManagedSeedShoot = true
		})

		It("hub-spoke + seed att on SHARED RT: pre-propagate, disassociate, associate", func() {
			withTGWConfig(c, "hub-spoke")
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return(invSharedRT, nil)
			gomock.InOrder(
				mockClient.EXPECT().EnableTransitGatewayRouteTablePropagation(ctx, invHubRT, invSeedAttID).Return(nil),
				mockClient.EXPECT().DisassociateTransitGatewayRouteTable(ctx, invSharedRT, invSeedAttID).Return(nil),
				mockClient.EXPECT().AssociateTransitGatewayRouteTable(ctx, invHubRT, invSeedAttID).Return(nil),
			)

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeTrue())
			// Fix #3: successful corrective move signals the actuator to
			// trigger post-hoc reconciles on every child shoot.
			Expect(c.DriftCorrectedThisReconcile()).To(BeTrue())
		})

		It("shared + seed att on HUB RT: mirror move", func() {
			withTGWConfig(c, "shared")
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return(invHubRT, nil)
			gomock.InOrder(
				mockClient.EXPECT().EnableTransitGatewayRouteTablePropagation(ctx, invSharedRT, invSeedAttID).Return(nil),
				mockClient.EXPECT().DisassociateTransitGatewayRouteTable(ctx, invHubRT, invSeedAttID).Return(nil),
				mockClient.EXPECT().AssociateTransitGatewayRouteTable(ctx, invSharedRT, invSeedAttID).Return(nil),
			)

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeTrue())
		})

		It("tolerates AWS 'already done' codes during the move", func() {
			withTGWConfig(c, "hub-spoke")
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return(invSharedRT, nil)
			gomock.InOrder(
				mockClient.EXPECT().EnableTransitGatewayRouteTablePropagation(ctx, invHubRT, invSeedAttID).
					Return(awsCodeError("TransitGatewayRouteTablePropagation.Duplicate")),
				mockClient.EXPECT().DisassociateTransitGatewayRouteTable(ctx, invSharedRT, invSeedAttID).
					Return(awsCodeError("InvalidAssociation.NotFound")),
				mockClient.EXPECT().AssociateTransitGatewayRouteTable(ctx, invHubRT, invSeedAttID).
					Return(awsCodeError("Resource.AlreadyAssociated")),
			)

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			// Drift was detected even though every individual call returned 'already done'.
			Expect(c.tgwDriftDetected).To(BeTrue())
		})

		It("transient pre-propagate failure: keeps tgwDriftDetected true and stops the move", func() {
			withTGWConfig(c, "hub-spoke")
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return(invSharedRT, nil)
			mockClient.EXPECT().EnableTransitGatewayRouteTablePropagation(ctx, invHubRT, invSeedAttID).
				Return(awsCodeError("IncorrectState"))
			// No subsequent disassociate/associate calls — the move aborts on
			// the transient pre-propagate error and waits for the next reconcile.

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeTrue())
			// Fix #3: a transient failure should NOT signal post-hoc reconciles —
			// the next reconcile will retry, and only success increments the
			// signal.
			Expect(c.DriftCorrectedThisReconcile()).To(BeFalse())
		})

		It("multiple roles: seed + runtime + globalVPC all drifted, all moved", func() {
			withTGWConfig(c, "hub-spoke")
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			c.state.Set(IdentifierRuntimeVPCTransitGatewayAttachment, invRuntimeAttID)
			c.seedConfig.TransitGateway.GlobalVPCs = []awsapi.GlobalVPC{
				{Name: "mgmt", VpcID: ptrTo("vpc-mgmt"), CIDRs: []string{"10.50.0.0/16"}},
			}
			c.state.Set(IdentifierGlobalVPCAttachmentPrefix+"mgmt", "tgw-attach-mgmt")

			for _, attID := range []string{invSeedAttID, invRuntimeAttID, "tgw-attach-mgmt"} {
				mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, attID).
					Return(availableAttachmentOnOurTGW(attID), nil)
				mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, attID).
					Return(invSharedRT, nil)
				mockClient.EXPECT().EnableTransitGatewayRouteTablePropagation(ctx, invHubRT, attID).Return(nil)
				mockClient.EXPECT().DisassociateTransitGatewayRouteTable(ctx, invSharedRT, attID).Return(nil)
				mockClient.EXPECT().AssociateTransitGatewayRouteTable(ctx, invHubRT, attID).Return(nil)
			}

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeTrue())
		})

		It("skips referenced globalVPCs (those carrying their own AttachmentID)", func() {
			withTGWConfig(c, "hub-spoke")
			c.seedConfig.TransitGateway.GlobalVPCs = []awsapi.GlobalVPC{
				{Name: "ref-mgmt", AttachmentID: ptrTo("tgw-attach-ref-mgmt"), CIDRs: []string{"10.99.0.0/16"}},
			}
			// Even with a state key (which there shouldn't be for referenced),
			// we never look at it because AttachmentID is set.
			c.state.Set(IdentifierGlobalVPCAttachmentPrefix+"ref-mgmt", "tgw-attach-ref-mgmt")
			// No mock expectations — the only candidate (referenced gvpc) is filtered out.

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})
	})

	Context("drift on child-shoot reconcile (NOT canonical owner)", func() {
		BeforeEach(func() {
			c.isManagedSeedShoot = false
		})

		It("flags drift, sets tgwDriftDetected, but does NOT execute the move", func() {
			withTGWConfig(c, "hub-spoke")
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return(invSharedRT, nil)
			// No EnableTransitGatewayRouteTablePropagation / Disassociate / Associate
			// calls — the child shoot reconcile only flags, the seed shoot moves.

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeTrue())
		})
	})

	Context("safety against stale-attachment / wrong-TGW (Phase 1 territory)", func() {
		It("attachment on a different TGW: defers to Phase 1, no events, no move", func() {
			withTGWConfig(c, "hub-spoke")
			c.isManagedSeedShoot = true
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invForeignAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invForeignAttID).
				Return(&awsclient.TransitGatewayVPCAttachment{
					TransitGatewayAttachmentId: invForeignAttID,
					TransitGatewayId:           invForeignTGW, // not ours
					State:                      "available",
				}, nil)
			// No association lookup; no move; no event.

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})

		It("attachment in terminal state: defers, no move", func() {
			withTGWConfig(c, "hub-spoke")
			c.isManagedSeedShoot = true
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(&awsclient.TransitGatewayVPCAttachment{
					TransitGatewayAttachmentId: invSeedAttID,
					TransitGatewayId:           invTGWID,
					State:                      "deleting",
				}, nil)
			// No association lookup; no move.

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeFalse())
		})

		It("attachment lookup error: defers, sets tgwDriftDetected so reconcile retries", func() {
			withTGWConfig(c, "hub-spoke")
			c.isManagedSeedShoot = true
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(nil, errors.New("transient AWS error"))

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeTrue())
		})

		It("association lookup error: defers, sets tgwDriftDetected", func() {
			withTGWConfig(c, "hub-spoke")
			c.isManagedSeedShoot = true
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return("", errors.New("throttled"))

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeTrue())
		})

		It("attachment unassociated (currentRT empty): polls then defers to bootstrap, no move", func() {
			// The bootstrap-associate path in ensureSeedVPCAttachment handles the
			// "no association at all" case; the invariant must not duplicate that work.
			// readAssociationWithPoll retries associationPollAttempts times to ride
			// out AWS eventual-consistency before declaring "still empty".
			withTGWConfig(c, "hub-spoke")
			c.isManagedSeedShoot = true
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).
				Return("", nil).Times(associationPollAttempts)
			// No EnableTransitGatewayRouteTablePropagation / Disassociate / Associate.

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			// Drift signal must still fire so the reconcile completion gate requeues.
			Expect(c.tgwDriftDetected).To(BeTrue())
		})

		It("attachment association settles after a brief poll: drift detected on real RT", func() {
			// Realistic case: AWS returns "" once during transition then the
			// real (drifted) RT once it settles. The helper must trust the
			// post-poll value.
			withTGWConfig(c, "hub-spoke")
			c.isManagedSeedShoot = true
			c.state.Set(IdentifierSeedVPCTransitGatewayAttachment, invSeedAttID)
			mockClient.EXPECT().GetTransitGatewayVPCAttachment(ctx, invSeedAttID).
				Return(availableAttachmentOnOurTGW(invSeedAttID), nil)
			gomock.InOrder(
				mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).Return("", nil),
				mockClient.EXPECT().GetTransitGatewayAttachmentAssociation(ctx, invSeedAttID).Return(invSharedRT, nil),
			)
			// Drift detected → canonical owner moves it.
			gomock.InOrder(
				mockClient.EXPECT().EnableTransitGatewayRouteTablePropagation(ctx, invHubRT, invSeedAttID).Return(nil),
				mockClient.EXPECT().DisassociateTransitGatewayRouteTable(ctx, invSharedRT, invSeedAttID).Return(nil),
				mockClient.EXPECT().AssociateTransitGatewayRouteTable(ctx, invHubRT, invSeedAttID).Return(nil),
			)

			Expect(c.assertSeedSideAssociations(ctx, logr.Discard(), invTGWID)).To(Succeed())
			Expect(c.tgwDriftDetected).To(BeTrue())
		})
	})
})

// ptrTo returns a pointer to the given string.
func ptrTo(s string) *string { return &s }
