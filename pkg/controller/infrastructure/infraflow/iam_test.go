// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

var _ = Describe("IAM role and instance profile", func() {
	const (
		namespace      = "shoot--myproject--mycluster"
		shootUID       = "abc-123-def"
		newRoleName    = namespace + "-" + shootUID + "-nodes"
		newRoleARN     = "arn:aws:iam::111111111111:role/" + newRoleName
		legacyRoleName = namespace + "-nodes"
		legacyRoleARN  = "arn:aws:iam::111111111111:role/" + legacyRoleName
	)

	var (
		ctrl    *gomock.Controller
		client  *mockawsclient.MockInterface
		updater *mockawsclient.MockUpdater
		ctx     context.Context
		c       *FlowContext
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		client = mockawsclient.NewMockInterface(ctrl)
		updater = mockawsclient.NewMockUpdater(ctrl)
		ctx = context.TODO()
		c = &FlowContext{
			state:     shared.NewWhiteboard(),
			namespace: namespace,
			shootUUID: shootUID,
			client:    client,
			updater:   updater,
		}
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	// ─── ensureIAMRole ────────────────────────────────────────────────────────────

	Describe("ensureIAMRole", func() {
		desiredRole := func(name string) *awsclient.IAMRole {
			return &awsclient.IAMRole{
				RoleName: name,
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
		}

		Context("new shoot (no state)", func() {
			It("creates the UID-scoped role and records name+ARN in state", func() {
				created := &awsclient.IAMRole{RoleName: newRoleName, ARN: newRoleARN}
				client.EXPECT().GetIAMRole(ctx, newRoleName).Return(nil, nil)
				client.EXPECT().CreateIAMRole(ctx, desiredRole(newRoleName)).Return(created, nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRole)).To(HaveValue(Equal(newRoleName)))
				Expect(c.state.Get(ARNIAMRole)).To(HaveValue(Equal(newRoleARN)))
			})

			It("updates the role when it already exists (idempotent)", func() {
				existing := &awsclient.IAMRole{RoleName: newRoleName, ARN: newRoleARN}
				client.EXPECT().GetIAMRole(ctx, newRoleName).Return(existing, nil)
				updater.EXPECT().UpdateIAMRole(ctx, desiredRole(newRoleName), existing).Return(false, nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRole)).To(HaveValue(Equal(newRoleName)))
				Expect(c.state.Get(ARNIAMRole)).To(HaveValue(Equal(newRoleARN)))
			})
		})

		Context("existing shoot (legacy name in state)", func() {
			BeforeEach(func() {
				c.state.Set(NameIAMRole, legacyRoleName)
			})

			It("uses the legacy name and records ARN in state", func() {
				existing := &awsclient.IAMRole{RoleName: legacyRoleName, ARN: legacyRoleARN}
				client.EXPECT().GetIAMRole(ctx, legacyRoleName).Return(existing, nil)
				updater.EXPECT().UpdateIAMRole(ctx, desiredRole(legacyRoleName), existing).Return(false, nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRole)).To(HaveValue(Equal(legacyRoleName)))
				Expect(c.state.Get(ARNIAMRole)).To(HaveValue(Equal(legacyRoleARN)))
			})

			It("recreates the legacy role if it was deleted externally", func() {
				created := &awsclient.IAMRole{RoleName: legacyRoleName, ARN: legacyRoleARN}
				client.EXPECT().GetIAMRole(ctx, legacyRoleName).Return(nil, nil)
				client.EXPECT().CreateIAMRole(ctx, desiredRole(legacyRoleName)).Return(created, nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRole)).To(HaveValue(Equal(legacyRoleName)))
			})
		})
	})

	// ─── deleteIAMRole ────────────────────────────────────────────────────────────

	Describe("deleteIAMRole", func() {
		It("does nothing if no role name is in state", func() {
			Expect(c.deleteIAMRole(ctx)).To(Succeed())
		})

		It("deletes the role named in state", func() {
			c.state.Set(NameIAMRole, newRoleName)
			client.EXPECT().DeleteIAMRole(ctx, newRoleName).Return(nil)

			Expect(c.deleteIAMRole(ctx)).To(Succeed())
			Expect(c.state.Get(NameIAMRole)).To(BeNil())
		})

		It("deletes the legacy role named in state", func() {
			c.state.Set(NameIAMRole, legacyRoleName)
			client.EXPECT().DeleteIAMRole(ctx, legacyRoleName).Return(nil)

			Expect(c.deleteIAMRole(ctx)).To(Succeed())
			Expect(c.state.Get(NameIAMRole)).To(BeNil())
		})
	})
})
