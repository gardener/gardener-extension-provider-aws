// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

var _ = Describe("IAM migration and legacy delete", func() {
	const (
		namespace = "shoot--myproject--mycluster"
		shootUID  = "abc-123-def"

		newRoleName    = namespace + "-" + shootUID + "-nodes"
		newRoleARN     = "arn:aws:iam::111111111111:role/" + newRoleName
		legacyRoleName = namespace + "-nodes"
		uidTagKey      = TagKeyShootUID + shootUID
		otherUID       = "zzz-other-shoot"
		otherUIDTagKey = TagKeyShootUID + otherUID
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

	// ─── iamResourceHasOtherOwners ────────────────────────────────────────────────

	Describe("iamResourceHasOtherOwners", func() {
		It("returns false for nil tags", func() {
			Expect(iamResourceHasOtherOwners(nil, shootUID)).To(BeFalse())
		})
		It("returns false when only the own UID tag is present", func() {
			Expect(iamResourceHasOtherOwners(awsclient.Tags{uidTagKey: "1"}, shootUID)).To(BeFalse())
		})
		It("returns false when no shoot-UID tags are present", func() {
			Expect(iamResourceHasOtherOwners(awsclient.Tags{"unrelated-tag": "val"}, shootUID)).To(BeFalse())
		})
		It("returns true when another shoot's UID tag is present alongside the own", func() {
			tags := awsclient.Tags{uidTagKey: "1", otherUIDTagKey: "1"}
			Expect(iamResourceHasOtherOwners(tags, shootUID)).To(BeTrue())
		})
		It("returns true when only another shoot's UID tag is present (own tag missing)", func() {
			Expect(iamResourceHasOtherOwners(awsclient.Tags{otherUIDTagKey: "1"}, shootUID)).To(BeTrue())
		})
	})

	// ─── ensureIAMRole ────────────────────────────────────────────────────────────

	Describe("ensureIAMRole", func() {
		desiredRole := func() *awsclient.IAMRole {
			return &awsclient.IAMRole{
				RoleName: newRoleName,
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

		Context("brand-new shoot (no state)", func() {
			It("creates the UID-scoped role and records name+ARN in state", func() {
				created := &awsclient.IAMRole{RoleName: newRoleName, ARN: newRoleARN}
				client.EXPECT().GetIAMRole(ctx, newRoleName).Return(nil, nil)
				client.EXPECT().CreateIAMRole(ctx, desiredRole()).Return(created, nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRole)).To(HaveValue(Equal(newRoleName)))
				Expect(c.state.Get(ARNIAMRole)).To(HaveValue(Equal(newRoleARN)))
				Expect(c.state.Get(LegacyNameIAMRole)).To(BeNil())
			})

			It("updates and records state when the UID-scoped role already exists (idempotent re-run of new shoot)", func() {
				existing := &awsclient.IAMRole{RoleName: newRoleName, ARN: newRoleARN}
				client.EXPECT().GetIAMRole(ctx, newRoleName).Return(existing, nil)
				updater.EXPECT().UpdateIAMRole(ctx, desiredRole(), existing).Return(false, nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRole)).To(HaveValue(Equal(newRoleName)))
				Expect(c.state.Get(ARNIAMRole)).To(HaveValue(Equal(newRoleARN)))
			})
		})

		Context("existing shoot migrating from legacy name", func() {
			BeforeEach(func() {
				c.state.Set(NameIAMRole, legacyRoleName)
			})

			It("creates UID-scoped role, records legacy name in state, and tags legacy role", func() {
				created := &awsclient.IAMRole{RoleName: newRoleName, ARN: newRoleARN}
				client.EXPECT().GetIAMRole(ctx, newRoleName).Return(nil, nil)
				client.EXPECT().CreateIAMRole(ctx, desiredRole()).Return(created, nil)
				client.EXPECT().TagIAMRole(ctx, legacyRoleName, awsclient.Tags{uidTagKey: "1"}).Return(nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRole)).To(HaveValue(Equal(newRoleName)))
				Expect(c.state.Get(ARNIAMRole)).To(HaveValue(Equal(newRoleARN)))
				Expect(c.state.Get(LegacyNameIAMRole)).To(HaveValue(Equal(legacyRoleName)))
			})

			It("updates UID-scoped role when it already exists and still tags legacy", func() {
				existing := &awsclient.IAMRole{RoleName: newRoleName, ARN: newRoleARN}
				client.EXPECT().GetIAMRole(ctx, newRoleName).Return(existing, nil)
				updater.EXPECT().UpdateIAMRole(ctx, desiredRole(), existing).Return(false, nil)
				client.EXPECT().TagIAMRole(ctx, legacyRoleName, awsclient.Tags{uidTagKey: "1"}).Return(nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(LegacyNameIAMRole)).To(HaveValue(Equal(legacyRoleName)))
			})
		})

		Context("already-migrated shoot (state has new name)", func() {
			BeforeEach(func() {
				c.state.Set(NameIAMRole, newRoleName)
			})

			It("updates existing UID-scoped role without touching legacy state", func() {
				existing := &awsclient.IAMRole{RoleName: newRoleName, ARN: newRoleARN}
				client.EXPECT().GetIAMRole(ctx, newRoleName).Return(existing, nil)
				updater.EXPECT().UpdateIAMRole(ctx, desiredRole(), existing).Return(false, nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(LegacyNameIAMRole)).To(BeNil())
			})

			It("recreates UID-scoped role if it was deleted externally", func() {
				created := &awsclient.IAMRole{RoleName: newRoleName, ARN: newRoleARN}
				client.EXPECT().GetIAMRole(ctx, newRoleName).Return(nil, nil)
				client.EXPECT().CreateIAMRole(ctx, desiredRole()).Return(created, nil)

				Expect(c.ensureIAMRole(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRole)).To(HaveValue(Equal(newRoleName)))
			})
		})
	})

	// ─── deleteLegacyIAMRole ──────────────────────────────────────────────────────

	Describe("deleteLegacyIAMRole", func() {
		BeforeEach(func() {
			c.state.Set(LegacyNameIAMRole, legacyRoleName)
		})

		It("does nothing if no legacy role name is in state", func() {
			c.state.Delete(LegacyNameIAMRole)
			Expect(c.deleteLegacyIAMRole(ctx)).To(Succeed())
		})

		It("only removes own UID tag when other shoots are still tagged", func() {
			tags := awsclient.Tags{uidTagKey: "1", otherUIDTagKey: "1"}
			client.EXPECT().GetIAMRoleTags(ctx, legacyRoleName).Return(tags, nil)
			client.EXPECT().UntagIAMRole(ctx, legacyRoleName, []string{uidTagKey}).Return(nil)

			Expect(c.deleteLegacyIAMRole(ctx)).To(Succeed())
			Expect(c.state.Get(LegacyNameIAMRole)).To(BeNil())
		})

		It("deletes the legacy role when this is the last owner", func() {
			tags := awsclient.Tags{uidTagKey: "1"}
			client.EXPECT().GetIAMRoleTags(ctx, legacyRoleName).Return(tags, nil)
			client.EXPECT().DeleteIAMRolePolicy(ctx, legacyRoleName, legacyRoleName).Return(nil)
			client.EXPECT().DeleteIAMRole(ctx, legacyRoleName).Return(nil)

			Expect(c.deleteLegacyIAMRole(ctx)).To(Succeed())
			Expect(c.state.Get(LegacyNameIAMRole)).To(BeNil())
		})

		It("propagates GetIAMRoleTags error", func() {
			boom := errors.New("iam error")
			client.EXPECT().GetIAMRoleTags(ctx, legacyRoleName).Return(nil, boom)
			Expect(c.deleteLegacyIAMRole(ctx)).To(MatchError(boom))
		})
	})

	// ─── deleteLegacyIAMInstanceProfile ───────────────────────────────────────────

	Describe("deleteLegacyIAMInstanceProfile", func() {
		BeforeEach(func() {
			c.state.Set(LegacyNameIAMInstanceProfile, legacyRoleName)
			c.state.Set(LegacyNameIAMRole, legacyRoleName)
		})

		It("does nothing if no legacy profile name is in state", func() {
			c.state.Delete(LegacyNameIAMInstanceProfile)
			Expect(c.deleteLegacyIAMInstanceProfile(ctx)).To(Succeed())
		})

		It("only removes own UID tag when other shoots are still tagged", func() {
			tags := awsclient.Tags{uidTagKey: "1", otherUIDTagKey: "1"}
			client.EXPECT().GetIAMInstanceProfileTags(ctx, legacyRoleName).Return(tags, nil)
			client.EXPECT().UntagIAMInstanceProfile(ctx, legacyRoleName, []string{uidTagKey}).Return(nil)

			Expect(c.deleteLegacyIAMInstanceProfile(ctx)).To(Succeed())
			Expect(c.state.Get(LegacyNameIAMInstanceProfile)).To(BeNil())
		})

		It("deletes legacy profile (removes role first) when this is the last owner", func() {
			tags := awsclient.Tags{uidTagKey: "1"}
			client.EXPECT().GetIAMInstanceProfileTags(ctx, legacyRoleName).Return(tags, nil)
			client.EXPECT().RemoveRoleFromIAMInstanceProfile(ctx, legacyRoleName, legacyRoleName).Return(nil)
			client.EXPECT().DeleteIAMInstanceProfile(ctx, legacyRoleName).Return(nil)

			Expect(c.deleteLegacyIAMInstanceProfile(ctx)).To(Succeed())
			Expect(c.state.Get(LegacyNameIAMInstanceProfile)).To(BeNil())
		})

		It("propagates GetIAMInstanceProfileTags error", func() {
			boom := errors.New("iam error")
			client.EXPECT().GetIAMInstanceProfileTags(ctx, legacyRoleName).Return(nil, boom)
			Expect(c.deleteLegacyIAMInstanceProfile(ctx)).To(MatchError(boom))
		})
	})
})
