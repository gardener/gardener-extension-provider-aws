// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
)

var _ = Describe("Scheme", func() {
	Describe("WorkloadIdentityConfigFromBytes", func() {
		It("should successfully parse WorkloadIdentityConfig", func() {
			raw := []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: role-arn
`)
			config, err := helper.WorkloadIdentityConfigFromBytes(raw)
			Expect(err).ToNot(HaveOccurred())
			Expect(config).ToNot(BeNil())
			Expect(config.RoleARN).To(Equal("role-arn"))
		})

		It("should fail to parse WorkloadIdentityConfig due to unknown field", func() {
			raw := []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: role-arn
additionalField: additionalValue
`)
			config, err := helper.WorkloadIdentityConfigFromBytes(raw)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("strict decoding error: unknown field \"additionalField\""))
			Expect(config).To(BeNil())
		})

		It("should fail to parse WorkloadIdentityConfig due to missing apiVersion", func() {
			raw := []byte(`kind: WorkloadIdentityConfig
roleARN: role-arn
`)
			config, err := helper.WorkloadIdentityConfigFromBytes(raw)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("strict decoding error: unknown field \"roleARN\""))
			Expect(config).To(BeNil())
		})

		It("should fail to parse WorkloadIdentityConfig due unregistered kind", func() {
			raw := []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: FooBar
roleARN: role-arn
`)
			config, err := helper.WorkloadIdentityConfigFromBytes(raw)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("no kind \"FooBar\" is registered for version \"aws.provider.extensions.gardener.cloud/v1alpha1\" in scheme")))
			Expect(config).To(BeNil())
		})

		It("should fail to parse WorkloadIdentityConfig due to empty config", func() {
			raw := []byte("")
			config, err := helper.WorkloadIdentityConfigFromBytes(raw)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("cannot parse WorkloadIdentityConfig from empty config"))
			Expect(config).To(BeNil())
		})
	})
})
