// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootconfigmap

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"
	manager "sigs.k8s.io/controller-runtime/pkg/manager"
)

var _ = Describe("Add shoot configmap webhook", func() {
	It("should return webhook with ObjectSelector", func() {
		mgr, err := manager.New(&rest.Config{}, manager.Options{})
		Expect(err).ToNot(HaveOccurred())

		webhook, err := AddToManager(mgr)
		Expect(err).ToNot(HaveOccurred())
		Expect(webhook).ToNot(BeNil())
		Expect(webhook.ObjectSelector).ToNot(BeNil())
	})
})
