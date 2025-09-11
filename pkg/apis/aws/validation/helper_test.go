// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ = Describe("Helper", func() {
	Describe("#rawExtensionToString", func() {
		It("should return <nil> for nil RawExtension", func() {
			Expect(rawExtensionToString(nil)).To(Equal("<nil>"))
		})

		It("should return empty string representation for nil RawExtension.Raw", func() {
			raw := &runtime.RawExtension{Raw: nil}
			Expect(rawExtensionToString(raw)).To(Equal(""))
		})

		It("should return empty string representation for empty RawExtension.Raw", func() {
			raw := &runtime.RawExtension{Raw: []byte{}}
			Expect(rawExtensionToString(raw)).To(Equal(""))
		})

		It("should return string representation of RawExtension", func() {
			raw := &runtime.RawExtension{Raw: []byte(`{"key":"value"}`)}
			Expect(rawExtensionToString(raw)).To(Equal(`{"key":"value"}`))
		})
	})
})
