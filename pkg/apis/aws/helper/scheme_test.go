// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper_test

import (
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"

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

		It("should fail to parse WorkloadIdentityConfig due to nil config", func() {
			config, err := helper.WorkloadIdentityConfigFromBytes(nil)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("cannot parse WorkloadIdentityConfig from empty config"))
			Expect(config).To(BeNil())
		})

		It("should fail to parse WorkloadIdentityConfig due to empty config", func() {
			config, err := helper.WorkloadIdentityConfigFromBytes([]byte{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("cannot parse WorkloadIdentityConfig from empty config"))
			Expect(config).To(BeNil())
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
			Expect(err).To(MatchError(ContainSubstring("Object 'apiVersion' is missing in")))
			Expect(config).To(BeNil())
		})

		It("should fail to parse WorkloadIdentityConfig due to unsupported apiVersion", func() {
			raw := []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v0
kind: WorkloadIdentityConfig
roleARN: role-arn
`)
			config, err := helper.WorkloadIdentityConfigFromBytes(raw)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("no kind \"WorkloadIdentityConfig\" is registered for version \"aws.provider.extensions.gardener.cloud/v0\" in scheme")), err.Error())
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
	})

	Describe("WorkloadIdentityConfigFromRaw", func() {
		It("should fail to parse WorkloadIdentityConfig due to nil raw", func() {
			config, err := helper.WorkloadIdentityConfigFromRaw(nil)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("cannot parse WorkloadIdentityConfig from empty RawExtension"))
			Expect(config).To(BeNil())
		})

		It("should fail to parse WorkloadIdentityConfig due to nil raw", func() {
			config, err := helper.WorkloadIdentityConfigFromRaw(&runtime.RawExtension{Raw: nil})
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("cannot parse WorkloadIdentityConfig from empty RawExtension"))
			Expect(config).To(BeNil())
		})

		It("should successfully parse WorkloadIdentityConfig", func() {
			raw := &runtime.RawExtension{Raw: []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: role-arn
`)}
			config, err := helper.WorkloadIdentityConfigFromRaw(raw)
			Expect(err).ToNot(HaveOccurred())
			Expect(config.RoleARN).To(Equal("role-arn"))
		})
	})

	Describe("HasEFAWorkerPool", func() {
		newWorker := func(name string, providerConfig string) gardencorev1beta1.Worker {
			worker := gardencorev1beta1.Worker{Name: name}
			if providerConfig != "" {
				worker.ProviderConfig = &runtime.RawExtension{Raw: []byte(providerConfig)}
			}
			return worker
		}

		It("should return false for nil workers", func() {
			has, err := helper.HasEFAWorkerPool(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(has).To(BeFalse())
		})

		It("should return false for workers without provider config", func() {
			has, err := helper.HasEFAWorkerPool([]gardencorev1beta1.Worker{newWorker("pool-1", "")})
			Expect(err).ToNot(HaveOccurred())
			Expect(has).To(BeFalse())
		})

		It("should return false for workers without networkInterfaces", func() {
			has, err := helper.HasEFAWorkerPool([]gardencorev1beta1.Worker{
				newWorker("pool-1", `apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkerConfig
`),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(has).To(BeFalse())
		})

		It("should return false for workers with non-EFA networkInterfaces only", func() {
			has, err := helper.HasEFAWorkerPool([]gardencorev1beta1.Worker{
				newWorker("pool-1", `apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkerConfig
networkInterfaces:
- type: interface
`),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(has).To(BeFalse())
		})

		It("should return true when at least one worker has an efa interface", func() {
			has, err := helper.HasEFAWorkerPool([]gardencorev1beta1.Worker{
				newWorker("pool-1", `apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkerConfig
networkInterfaces:
- type: interface
`),
				newWorker("pool-2", `apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkerConfig
networkInterfaces:
- type: efa
`),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(has).To(BeTrue())
		})

		It("should return true when a worker has an efa-only interface", func() {
			has, err := helper.HasEFAWorkerPool([]gardencorev1beta1.Worker{
				newWorker("pool-1", `apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkerConfig
networkInterfaces:
- type: interface
- type: efa-only
`),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(has).To(BeTrue())
		})

		It("should match the AWS SDK constants for efa types", func() {
			Expect(string(ec2types.NetworkInterfaceTypeEfa)).To(Equal("efa"))
			Expect(string(ec2types.NetworkInterfaceTypeEfaOnly)).To(Equal("efa-only"))
		})

		It("should ignore network interfaces with nil type", func() {
			workerConfig := `apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkerConfig
networkInterfaces:
- {}
`
			has, err := helper.HasEFAWorkerPool([]gardencorev1beta1.Worker{newWorker("pool-1", workerConfig)})
			Expect(err).ToNot(HaveOccurred())
			Expect(has).To(BeFalse())
		})

		It("should return an error for invalid provider config", func() {
			has, err := helper.HasEFAWorkerPool([]gardencorev1beta1.Worker{
				newWorker("pool-1", `not yaml at all: [{`),
			})
			Expect(err).To(HaveOccurred())
			Expect(has).To(BeFalse())
		})
	})
})
