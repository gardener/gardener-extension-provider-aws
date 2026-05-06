// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/smithy-go"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	"go.uber.org/mock/gomock"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

const (
	testNamespace      = "shoot--garden--unit"
	testAbandonedTGWID = "tgw-abandoned"
)

// newTestFlowContext returns a minimal FlowContext suitable for unit testing
// internal helpers like isAbandonedTGWOurs and sweepStaleRoutesToCurrentTGW.
// seedConfig is nil so getTGWClient returns c.client unchanged — no
// cross-account credential resolution is exercised.
func newTestFlowContext(client awsclient.Interface) *FlowContext {
	return &FlowContext{
		log:       logr.Discard(),
		state:     shared.NewWhiteboard(),
		namespace: testNamespace,
		client:    client,
	}
}

// awsCodeError constructs an error that GetAWSAPIErrorCode resolves to `code`.
func awsCodeError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: code}
}

var _ = Describe("isAbandonedTGWOurs", func() {
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

	Context("step 1: state history short-circuit", func() {
		It("returns (ours=true, transient=false) without an AWS call when history has the TGW", func() {
			c.state.GetChild(IdentifierPreviousTGWs).Set(testAbandonedTGWID, "true")
			// No mock expectations — history hit must short-circuit before AWS.
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeTrue())
			Expect(transient).To(BeFalse())
		})

		It("falls through to live check when history value is not literally 'true'", func() {
			c.state.GetChild(IdentifierPreviousTGWs).Set(testAbandonedTGWID, "false")
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).
				Return(nil, awsCodeError("InvalidTransitGatewayID.NotFound"))
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeFalse())
			Expect(transient).To(BeFalse())
		})
	})

	Context("step 2: per-reconcile cache short-circuit", func() {
		It("returns cached ours=true without an AWS call", func() {
			c.tgwOwnershipCache = map[string]ownershipResult{
				testAbandonedTGWID: {ours: true},
			}
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeTrue())
			Expect(transient).To(BeFalse())
		})

		It("returns cached transient=true without an AWS call", func() {
			c.tgwOwnershipCache = map[string]ownershipResult{
				testAbandonedTGWID: {transient: true},
			}
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeFalse())
			Expect(transient).To(BeTrue())
		})
	})

	Context("step 3: live cluster-tag check", func() {
		It("returns ours=true and records to history when the TGW has our cluster tag", func() {
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).Return(
				&awsclient.TransitGateway{
					TransitGatewayId: testAbandonedTGWID,
					Tags: awsclient.Tags{
						fmt.Sprintf(TagKeyClusterTemplate, testNamespace): TagValueCluster,
					},
				}, nil,
			)
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeTrue())
			Expect(transient).To(BeFalse())
			// Side effect: a successful ours-check must persist to history so
			// future reconciles short-circuit at step 1 even after the TGW is
			// deleted from AWS.
			Expect(c.state.GetChild(IdentifierPreviousTGWs).Get(testAbandonedTGWID)).
				To(gstruct.PointTo(Equal("true")))
		})

		It("returns ours=false when the TGW exists but lacks our cluster tag", func() {
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).Return(
				&awsclient.TransitGateway{
					TransitGatewayId: testAbandonedTGWID,
					Tags: awsclient.Tags{
						"kubernetes.io/cluster/some-other-shoot": TagValueCluster,
					},
				}, nil,
			)
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeFalse())
			Expect(transient).To(BeFalse())
		})

		It("returns definitive (false, false) on InvalidTransitGatewayID.NotFound", func() {
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).
				Return(nil, awsCodeError("InvalidTransitGatewayID.NotFound"))
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeFalse())
			Expect(transient).To(BeFalse())
		})

		It("returns transient=true on a recognized AWS throttle error", func() {
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).
				Return(nil, awsCodeError("ThrottlingException"))
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeFalse())
			Expect(transient).To(BeTrue())
		})

		It("returns transient=true when the error has no AWS code (network error)", func() {
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).
				Return(nil, errors.New("connection refused"))
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeFalse())
			Expect(transient).To(BeTrue())
		})

		It("returns definitive (false, false) when the AWS client returns nil tgw and nil error", func() {
			// Contract: GetTransitGateway returns nil for terminal/deleted state.
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).Return(nil, nil)
			ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(ours).To(BeFalse())
			Expect(transient).To(BeFalse())
		})

		It("populates tgwOwnershipCache after the live check", func() {
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).
				Return(nil, awsCodeError("ThrottlingException"))
			_, _ = c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			cached, hit := c.tgwOwnershipCache[testAbandonedTGWID]
			Expect(hit).To(BeTrue())
			Expect(cached).To(Equal(ownershipResult{ours: false, transient: true}))
		})

		It("does not record to history on transient error", func() {
			// History recording is reserved for ours=true; transient must not pollute it.
			mockClient.EXPECT().GetTransitGateway(ctx, testAbandonedTGWID).
				Return(nil, awsCodeError("ThrottlingException"))
			_, _ = c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, testAbandonedTGWID)
			Expect(c.state.GetChild(IdentifierPreviousTGWs).Get(testAbandonedTGWID)).To(BeNil())
		})
	})

	It("returns (false, false) on empty TGW ID without an AWS call", func() {
		ours, transient := c.isAbandonedTGWOurs(ctx, logr.Discard(), nil, "")
		Expect(ours).To(BeFalse())
		Expect(transient).To(BeFalse())
	})
})

