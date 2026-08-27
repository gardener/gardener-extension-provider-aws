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

var _ = Describe("forceCleanupIAMRoleAttachments", func() {
	const (
		namespace = "shoot--myproject--mycluster"
		roleName  = namespace + "-nodes"
		roleARN   = "arn:aws:iam::123456789012:role/" + roleName
	)

	var (
		ctrl   *gomock.Controller
		client *mockawsclient.MockInterface
		ctx    context.Context
		c      *FlowContext
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		client = mockawsclient.NewMockInterface(ctrl)
		ctx = context.TODO()
		c = &FlowContext{
			state:     shared.NewWhiteboard(),
			namespace: namespace,
			client:    client,
		}
		c.state.Set(NameIAMRole, roleName)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	It("should do nothing if the role is not part of the flow state", func() {
		c.state.Delete(NameIAMRole)
		Expect(c.forceCleanupIAMRoleAttachments(ctx)).To(Succeed())
	})

	It("should do nothing if the role does not exist", func() {
		client.EXPECT().GetIAMRole(ctx, roleName).Return(nil, nil)
		Expect(c.forceCleanupIAMRoleAttachments(ctx)).To(Succeed())
	})

	It("should fail if the role ARN does not match the ARN recorded in the flow state", func() {
		c.state.Set(ARNIAMRole, "arn:aws:iam::999999999999:role/"+roleName)
		client.EXPECT().GetIAMRole(ctx, roleName).Return(&awsclient.IAMRole{RoleName: roleName, ARN: roleARN}, nil)
		Expect(c.forceCleanupIAMRoleAttachments(ctx)).To(MatchError(ContainSubstring("does not match")))
	})

	It("should detach managed policies, delete inline policies, and remove instance-profile associations", func() {
		c.state.Set(ARNIAMRole, roleARN)
		client.EXPECT().GetIAMRole(ctx, roleName).Return(&awsclient.IAMRole{RoleName: roleName, ARN: roleARN}, nil)
		client.EXPECT().ListAttachedIAMRolePolicies(ctx, roleName).Return([]string{
			"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
			"arn:aws:iam::123456789012:policy/account-baseline-policy",
		}, nil)
		client.EXPECT().DetachIAMRolePolicy(ctx, roleName, "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore").Return(nil)
		client.EXPECT().DetachIAMRolePolicy(ctx, roleName, "arn:aws:iam::123456789012:policy/account-baseline-policy").Return(nil)
		client.EXPECT().ListIAMRolePolicies(ctx, roleName).Return([]string{"extra-inline-policy"}, nil)
		client.EXPECT().DeleteIAMRolePolicy(ctx, "extra-inline-policy", roleName).Return(nil)
		client.EXPECT().ListIAMInstanceProfilesForRole(ctx, roleName).Return([]string{"extra-instance-profile"}, nil)
		client.EXPECT().RemoveRoleFromIAMInstanceProfile(ctx, "extra-instance-profile", roleName).Return(nil)

		Expect(c.forceCleanupIAMRoleAttachments(ctx)).To(Succeed())
	})

	It("should proceed without the ARN check if no ARN is recorded in the flow state", func() {
		client.EXPECT().GetIAMRole(ctx, roleName).Return(&awsclient.IAMRole{RoleName: roleName, ARN: roleARN}, nil)
		client.EXPECT().ListAttachedIAMRolePolicies(ctx, roleName).Return(nil, nil)
		client.EXPECT().ListIAMRolePolicies(ctx, roleName).Return(nil, nil)
		client.EXPECT().ListIAMInstanceProfilesForRole(ctx, roleName).Return(nil, nil)

		Expect(c.forceCleanupIAMRoleAttachments(ctx)).To(Succeed())
	})
})
