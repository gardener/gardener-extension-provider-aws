// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"crypto/md5" // #nosec G501
	"fmt"

	ext "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

var _ = Describe("key pair", func() {
	const (
		namespace = "shoot--myproject--mycluster"
		shootUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		sshKey    = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC test"
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
			shootUUID: shootUUID,
			client:    client,
			infraSpec: ext.InfrastructureSpec{
				SSHPublicKey: []byte(sshKey),
			},
		}
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	// ─── ensureKeyPair ────────────────────────────────────────────────────────────

	Describe("ensureKeyPair", func() {
		newKeyName := namespace + "-" + shootUUID + "-ssh-publickey"
		legacyKeyName := namespace + "-ssh-publickey"

		Context("new shoot (no state)", func() {
			It("imports the UID-scoped key pair and records name in state", func() {
				info := &awsclient.KeyPairInfo{KeyName: newKeyName, KeyFingerprint: "fp1"}
				client.EXPECT().GetKeyPair(ctx, newKeyName).Return(nil, nil)
				client.EXPECT().ImportKeyPair(ctx, newKeyName, []byte(sshKey), c.commonTags).Return(info, nil)

				Expect(c.ensureKeyPair(ctx)).To(Succeed())
				Expect(c.state.Get(NameKeyPair)).To(HaveValue(Equal(newKeyName)))
				Expect(c.state.Get(KeyPairFingerprint)).To(HaveValue(Equal("fp1")))
			})

			It("keeps existing key pair when fingerprint matches (idempotent)", func() {
				specFingerprint := fmt.Sprintf("%x", md5.Sum([]byte(sshKey))) // #nosec G401
				c.state.Set(KeyPairFingerprint, "fp1")
				c.state.Set(KeyPairSpecFingerprint, specFingerprint)
				existing := &awsclient.KeyPairInfo{KeyName: newKeyName, KeyFingerprint: "fp1"}
				client.EXPECT().GetKeyPair(ctx, newKeyName).Return(existing, nil)

				Expect(c.ensureKeyPair(ctx)).To(Succeed())
				Expect(c.state.Get(NameKeyPair)).To(HaveValue(Equal(newKeyName)))
			})
		})

		Context("existing shoot (legacy name in state)", func() {
			BeforeEach(func() {
				c.state.Set(NameKeyPair, legacyKeyName)
			})

			It("uses the legacy name and keeps the existing key pair", func() {
				specFingerprint := fmt.Sprintf("%x", md5.Sum([]byte(sshKey))) // #nosec G401
				c.state.Set(KeyPairFingerprint, "fp1")
				c.state.Set(KeyPairSpecFingerprint, specFingerprint)
				existing := &awsclient.KeyPairInfo{KeyName: legacyKeyName, KeyFingerprint: "fp1"}
				client.EXPECT().GetKeyPair(ctx, legacyKeyName).Return(existing, nil)

				Expect(c.ensureKeyPair(ctx)).To(Succeed())
				Expect(c.state.Get(NameKeyPair)).To(HaveValue(Equal(legacyKeyName)))
			})

			It("reimports the legacy key pair if deleted externally", func() {
				specFingerprint := fmt.Sprintf("%x", md5.Sum([]byte(sshKey))) // #nosec G401
				c.state.Set(KeyPairFingerprint, "fp1")
				c.state.Set(KeyPairSpecFingerprint, specFingerprint)
				info := &awsclient.KeyPairInfo{KeyName: legacyKeyName, KeyFingerprint: "fp1"}
				client.EXPECT().GetKeyPair(ctx, legacyKeyName).Return(nil, nil)
				client.EXPECT().ImportKeyPair(ctx, legacyKeyName, []byte(sshKey), c.commonTags).Return(info, nil)

				Expect(c.ensureKeyPair(ctx)).To(Succeed())
				Expect(c.state.Get(NameKeyPair)).To(HaveValue(Equal(legacyKeyName)))
			})
		})
	})

	// ─── deleteKeyPair ────────────────────────────────────────────────────────────

	Describe("deleteKeyPair", func() {
		newKeyName := namespace + "-" + shootUUID + "-ssh-publickey"
		legacyKeyName := namespace + "-ssh-publickey"

		It("does nothing if no key pair name is in state", func() {
			Expect(c.deleteKeyPair(ctx)).To(Succeed())
		})

		It("deletes the key pair named in state", func() {
			c.state.Set(NameKeyPair, newKeyName)
			client.EXPECT().DeleteKeyPair(ctx, newKeyName).Return(nil)

			Expect(c.deleteKeyPair(ctx)).To(Succeed())
			Expect(c.state.Get(NameKeyPair)).To(BeNil())
		})

		It("deletes the legacy key pair named in state", func() {
			c.state.Set(NameKeyPair, legacyKeyName)
			client.EXPECT().DeleteKeyPair(ctx, legacyKeyName).Return(nil)

			Expect(c.deleteKeyPair(ctx)).To(Succeed())
			Expect(c.state.Get(NameKeyPair)).To(BeNil())
		})
	})
})
