// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootservice

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"
	manager "sigs.k8s.io/controller-runtime/pkg/manager"
)

var _ = Describe("Add shoot service webhook", func() {
	It("should return webhook with ObjectSelector", func() {
		mgr, err := manager.New(&rest.Config{}, manager.Options{})
		Expect(err).ToNot(HaveOccurred())

		webhook, err := AddToManager(mgr)
		Expect(err).ToNot(HaveOccurred())
		Expect(webhook).ToNot(BeNil())
		Expect(webhook.ObjectSelector).ToNot(BeNil())
		Expect(webhook.NamespaceSelector).To(BeNil())
	})

	It("should return webhook for kube-system namespace with ObjectSelector", func() {
		mgr, err := manager.New(&rest.Config{}, manager.Options{})
		Expect(err).ToNot(HaveOccurred())

		webhook, err := AddNginxIngressWebhookToManager(mgr)
		Expect(err).ToNot(HaveOccurred())
		Expect(webhook).ToNot(BeNil())
		Expect(webhook.ObjectSelector).ToNot(BeNil())
		Expect(webhook.NamespaceSelector).ToNot(BeNil())
	})
})
