// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"bytes"
	"context"
	"text/template"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

var _ = Describe("IAM role and instance profile", func() {
	const (
		namespace = "shoot--myproject--mycluster"
		shootUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
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
			shootUUID: shootUUID,
			client:    client,
			updater:   updater,
		}
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	// ─── ensureIAMRole ────────────────────────────────────────────────────────────

	Describe("ensureIAMRole", func() {
		newRoleName := namespace + "-" + shootUUID[:8] + "-nodes"
		newRoleARN := "arn:aws:iam::111111111111:role/" + newRoleName
		legacyRoleName := namespace + "-nodes"
		legacyRoleARN := "arn:aws:iam::111111111111:role/" + legacyRoleName

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
		newRoleName := namespace + "-" + shootUUID[:8] + "-nodes"
		legacyRoleName := namespace + "-nodes"

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

	// ─── ensureIAMInstanceProfile ─────────────────────────────────────────────────

	Describe("ensureIAMInstanceProfile", func() {
		newProfileName := namespace + "-" + shootUUID[:8] + "-nodes"
		legacyProfileName := namespace + "-nodes"

		desiredProfile := func(name string) *awsclient.IAMInstanceProfile {
			return &awsclient.IAMInstanceProfile{
				InstanceProfileName: name,
				Path:                "/",
				RoleName:            name,
			}
		}

		Context("new shoot (no state)", func() {
			It("creates the UID-scoped instance profile and records name in state", func() {
				created := &awsclient.IAMInstanceProfile{InstanceProfileName: newProfileName}
				client.EXPECT().GetIAMInstanceProfile(ctx, newProfileName).Return(nil, nil)
				client.EXPECT().CreateIAMInstanceProfile(ctx, desiredProfile(newProfileName)).Return(created, nil)
				updater.EXPECT().UpdateIAMInstanceProfile(ctx, desiredProfile(newProfileName), created).Return(false, nil)

				Expect(c.ensureIAMInstanceProfile(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMInstanceProfile)).To(HaveValue(Equal(newProfileName)))
			})

			It("updates the instance profile when it already exists (idempotent)", func() {
				existing := &awsclient.IAMInstanceProfile{InstanceProfileName: newProfileName}
				client.EXPECT().GetIAMInstanceProfile(ctx, newProfileName).Return(existing, nil)
				updater.EXPECT().UpdateIAMInstanceProfile(ctx, desiredProfile(newProfileName), existing).Return(false, nil)

				Expect(c.ensureIAMInstanceProfile(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMInstanceProfile)).To(HaveValue(Equal(newProfileName)))
			})
		})

		Context("existing shoot (legacy name in state)", func() {
			BeforeEach(func() {
				c.state.Set(NameIAMInstanceProfile, legacyProfileName)
			})

			It("uses the legacy name and records it in state", func() {
				existing := &awsclient.IAMInstanceProfile{InstanceProfileName: legacyProfileName}
				client.EXPECT().GetIAMInstanceProfile(ctx, legacyProfileName).Return(existing, nil)
				updater.EXPECT().UpdateIAMInstanceProfile(ctx, desiredProfile(legacyProfileName), existing).Return(false, nil)

				Expect(c.ensureIAMInstanceProfile(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMInstanceProfile)).To(HaveValue(Equal(legacyProfileName)))
			})

			It("recreates the legacy instance profile if it was deleted externally", func() {
				created := &awsclient.IAMInstanceProfile{InstanceProfileName: legacyProfileName}
				client.EXPECT().GetIAMInstanceProfile(ctx, legacyProfileName).Return(nil, nil)
				client.EXPECT().CreateIAMInstanceProfile(ctx, desiredProfile(legacyProfileName)).Return(created, nil)
				updater.EXPECT().UpdateIAMInstanceProfile(ctx, desiredProfile(legacyProfileName), created).Return(false, nil)

				Expect(c.ensureIAMInstanceProfile(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMInstanceProfile)).To(HaveValue(Equal(legacyProfileName)))
			})
		})
	})

	// ─── deleteIAMInstanceProfile ─────────────────────────────────────────────────

	Describe("deleteIAMInstanceProfile", func() {
		newProfileName := namespace + "-" + shootUUID[:8] + "-nodes"
		legacyProfileName := namespace + "-nodes"

		It("does nothing if no instance profile name is in state", func() {
			Expect(c.deleteIAMInstanceProfile(ctx)).To(Succeed())
		})

		It("deletes the instance profile named in state", func() {
			c.state.Set(NameIAMInstanceProfile, newProfileName)
			client.EXPECT().DeleteIAMInstanceProfile(ctx, newProfileName).Return(nil)

			Expect(c.deleteIAMInstanceProfile(ctx)).To(Succeed())
			Expect(c.state.Get(NameIAMInstanceProfile)).To(BeNil())
		})

		It("deletes the legacy instance profile named in state", func() {
			c.state.Set(NameIAMInstanceProfile, legacyProfileName)
			client.EXPECT().DeleteIAMInstanceProfile(ctx, legacyProfileName).Return(nil)

			Expect(c.deleteIAMInstanceProfile(ctx)).To(Succeed())
			Expect(c.state.Get(NameIAMInstanceProfile)).To(BeNil())
		})
	})

	// ─── ensureIAMRolePolicy ──────────────────────────────────────────────────────

	Describe("ensureIAMRolePolicy", func() {
		policyName := namespace + "-" + shootUUID[:8] + "-nodes"
		legacyPolicyName := namespace + "-nodes"

		BeforeEach(func() {
			c.config = &awsapi.InfrastructureConfig{}
		})

		Context("new shoot (no state)", func() {
			It("creates the policy and records name in state", func() {
				client.EXPECT().GetIAMRolePolicy(ctx, policyName, policyName).Return(nil, nil)
				client.EXPECT().PutIAMRolePolicy(ctx, gomock.Any()).Return(nil)

				Expect(c.ensureIAMRolePolicy(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRolePolicy)).To(HaveValue(Equal(policyName)))
			})

			It("skips PutIAMRolePolicy when policy document is unchanged", func() {
				existing := &awsclient.IAMRolePolicy{PolicyName: policyName, RoleName: policyName}
				client.EXPECT().GetIAMRolePolicy(ctx, policyName, policyName).DoAndReturn(
					func(_ context.Context, _, _ string) (*awsclient.IAMRolePolicy, error) {
						// return a policy with the same document that ensureIAMRolePolicy would generate
						var buf bytes.Buffer
						_ = template.Must(template.New("").Parse(iamRolePolicyTemplate)).Execute(&buf, map[string]any{
							"enableECRAccess": true,
							"enableEfsAccess": false,
						})
						existing.PolicyDocument = buf.String()
						return existing, nil
					})

				Expect(c.ensureIAMRolePolicy(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRolePolicy)).To(HaveValue(Equal(policyName)))
			})
		})

		Context("existing shoot (legacy role name in state)", func() {
			BeforeEach(func() {
				c.state.Set(NameIAMRole, legacyPolicyName)
			})

			It("uses the legacy name from state and records it", func() {
				client.EXPECT().GetIAMRolePolicy(ctx, legacyPolicyName, legacyPolicyName).Return(nil, nil)
				client.EXPECT().PutIAMRolePolicy(ctx, gomock.Any()).Return(nil)

				Expect(c.ensureIAMRolePolicy(ctx)).To(Succeed())
				Expect(c.state.Get(NameIAMRolePolicy)).To(HaveValue(Equal(legacyPolicyName)))
			})
		})
	})

	// ─── deleteIAMRolePolicy ──────────────────────────────────────────────────────

	Describe("deleteIAMRolePolicy", func() {
		policyName := namespace + "-" + shootUUID[:8] + "-nodes"
		legacyPolicyName := namespace + "-nodes"

		It("does nothing if no policy name is in state", func() {
			Expect(c.deleteIAMRolePolicy(ctx)).To(Succeed())
		})

		It("removes role from instance profile and deletes the policy", func() {
			c.state.Set(NameIAMRolePolicy, policyName)
			c.state.Set(NameIAMRole, policyName)
			c.state.Set(NameIAMInstanceProfile, policyName)
			client.EXPECT().RemoveRoleFromIAMInstanceProfile(ctx, policyName, policyName).Return(nil)
			client.EXPECT().DeleteIAMRolePolicy(ctx, policyName, policyName).Return(nil)

			Expect(c.deleteIAMRolePolicy(ctx)).To(Succeed())
			Expect(c.state.Get(NameIAMRolePolicy)).To(BeNil())
		})

		It("falls back to policy name for role and profile when not in state", func() {
			c.state.Set(NameIAMRolePolicy, legacyPolicyName)
			client.EXPECT().RemoveRoleFromIAMInstanceProfile(ctx, legacyPolicyName, legacyPolicyName).Return(nil)
			client.EXPECT().DeleteIAMRolePolicy(ctx, legacyPolicyName, legacyPolicyName).Return(nil)

			Expect(c.deleteIAMRolePolicy(ctx)).To(Succeed())
			Expect(c.state.Get(NameIAMRolePolicy)).To(BeNil())
		})
	})
})
