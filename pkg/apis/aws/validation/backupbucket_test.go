// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"encoding/json"
	"time"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var _ = Describe("BackupBucket Config Validation", func() {
	var fldPath *field.Path

	BeforeEach(func() {
		fldPath = field.NewPath("spec")
	})

	DescribeTable("#ValidateBackupBucketConfig",
		func(config *apisaws.BackupBucketConfig, wantErr bool, errMsg string) {
			errs := ValidateBackupBucketConfig(config, fldPath)
			if wantErr {
				Expect(errs).NotTo(BeEmpty())
				Expect(errs[0].Error()).To(ContainSubstring(errMsg))
			} else {
				Expect(errs).To(BeEmpty())
			}
		},
		Entry("valid config",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "bucket",
					RetentionPeriod: metav1.Duration{Duration: 48 * time.Hour},
					Mode:            "compliance",
				},
			}, false, ""),
		Entry("missing retentionType",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "",
					RetentionPeriod: metav1.Duration{Duration: 24 * time.Hour},
					Mode:            "compliance",
				},
			}, true, "must be 'bucket'"),
		Entry("invalid retentionType",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "invalid",
					RetentionPeriod: metav1.Duration{Duration: 24 * time.Hour},
					Mode:            "compliance",
				},
			}, true, "must be 'bucket'"),
		Entry("invalid retentionPeriod",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "bucket",
					RetentionPeriod: metav1.Duration{Duration: 2 * time.Hour},
					Mode:            "compliance",
				},
			}, true, "can't be less than 24hour"),
		Entry("negative retentionPeriod",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "bucket",
					RetentionPeriod: metav1.Duration{Duration: -1 * time.Hour},
					Mode:            "compliance",
				},
			}, true, "can't be less than 24hour"),
		Entry("empty retentionPeriod",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "bucket",
					RetentionPeriod: metav1.Duration{},
					Mode:            "compliance",
				},
			}, true, "can't be less than 24hour"),
		Entry("retentionPeriod not multiple of 24 hour",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "bucket",
					RetentionPeriod: metav1.Duration{Duration: 32 * time.Hour},
					Mode:            "compliance",
				},
			}, true, "must be a multiple of 24hour"),
		Entry("missing retention mode",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "bucket",
					RetentionPeriod: metav1.Duration{Duration: 24 * time.Hour},
					Mode:            "",
				},
			}, true, "should be either compliance mode or governance mode"),
		Entry("invalid retention mode",
			&apisaws.BackupBucketConfig{
				Immutability: &apisaws.ImmutableConfig{
					RetentionType:   "bucket",
					RetentionPeriod: metav1.Duration{Duration: 24 * time.Hour},
					Mode:            "invalid",
				},
			}, true, "should be either compliance mode or governance mode"),
	)

	var (
		scheme *runtime.Scheme

		decoder        runtime.Decoder
		lenientDecoder runtime.Decoder
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(core.AddToScheme(scheme)).To(Succeed())
		Expect(apisaws.AddToScheme(scheme)).To(Succeed())
		Expect(apisawsv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(gardencorev1beta1.AddToScheme(scheme)).To(Succeed())

		decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
		lenientDecoder = serializer.NewCodecFactory(scheme).UniversalDecoder()

		fldPath = field.NewPath("spec", "backup", "providerConfig")
	})

	// Helper function to generate provider config
	generateConfig := func(retentionType, retentionPeriod string, mode string, isImmutableConfigured bool) *runtime.RawExtension {
		var config *runtime.RawExtension
		if isImmutableConfigured {

			immutability := make(map[string]interface{})
			if retentionType != "" {
				immutability["retentionType"] = retentionType
			}
			if retentionPeriod != "" {
				immutability["retentionPeriod"] = retentionPeriod
				immutability["mode"] = mode
			}

			backupBucketConfig := map[string]interface{}{
				"apiVersion":   "aws.provider.extensions.gardener.cloud/v1alpha1",
				"kind":         "BackupBucketConfig",
				"immutability": immutability,
			}
			raw, err := json.Marshal(backupBucketConfig)
			Expect(err).NotTo(HaveOccurred())
			config = &runtime.RawExtension{
				Raw: raw,
			}
		}

		return config
	}

	Describe("ValidateUpdate", func() {
		DescribeTable("Valid update scenarios",
			func(oldConfig, newConfig *runtime.RawExtension) {
				Expect(ValidateBackupBucketProviderConfigUpdate(decoder, lenientDecoder, oldConfig, newConfig, fldPath)).To(BeEmpty())
			},
			Entry("Updation with empty provider config",
				&runtime.RawExtension{},
				&runtime.RawExtension{},
			),
			Entry("Immutable settings unchanged",
				generateConfig("bucket", "96h", "governance", true),
				generateConfig("bucket", "96h", "governance", true),
			),
			Entry("Immutable settings change the mode: governance to compliance",
				generateConfig("bucket", "24h", "governance", true),
				generateConfig("bucket", "24h", "compliance", true),
			),
			Entry("Retention period increased with mode: governance",
				generateConfig("bucket", "24h", "governance", true),
				generateConfig("bucket", "48h", "governance", true),
			),
			Entry("Retention period increased with mode: compliance",
				generateConfig("bucket", "24h", "compliance", true),
				generateConfig("bucket", "48h", "compliance", true),
			),
			Entry("Retention period decreased with mode: governance",
				generateConfig("bucket", "96h", "governance", true),
				generateConfig("bucket", "48h", "governance", true),
			),
			// TODO: @ishan16696 to be remove this test case, once immutability can't be disable
			Entry("Disabling immutability",
				generateConfig("bucket", "96h", "governance", true),
				generateConfig("", "", "", false),
			),
			Entry("Backup not configured",
				generateConfig("", "", "", false),
				generateConfig("", "", "", false),
			),
		)

		DescribeTable("Invalid update scenarios",
			func(oldConfig, newConfig *runtime.RawExtension, expectedError string) {
				errList := ValidateBackupBucketProviderConfigUpdate(decoder, lenientDecoder, oldConfig, newConfig, fldPath)
				Expect(errList).NotTo(BeEmpty())
				Expect(errList.ToAggregate().Error()).To(ContainSubstring(expectedError))
			},
			Entry("Reducing retention period in compliance mode is not allowed",
				generateConfig("bucket", "96h", "compliance", true),
				generateConfig("bucket", "48h", "compliance", true),
				"reducing the retention period from",
			),
			Entry("Changing the mode from compliance to governance is not allowed",
				generateConfig("bucket", "96h", "compliance", true),
				generateConfig("bucket", "96h", "governance", true),
				"mode can't be change to governance once it is compliance",
			),
			Entry("Changing retentionType is not allowed",
				generateConfig("bucket", "96h", "compliance", true),
				generateConfig("object", "96h", "compliance", true),
				"must be 'bucket'",
			),
			Entry("Retention period below minimum in any mode is not allowed",
				generateConfig("bucket", "96h", "compliance", true),
				generateConfig("bucket", "23h", "compliance", true),
				"it can't be less than 24hour",
			),
			Entry("Retention period not multiple of 24hours is not allowed",
				generateConfig("bucket", "96h", "compliance", true),
				generateConfig("bucket", "100h", "compliance", true),
				"must be a multiple of 24hour",
			),
			Entry("Invalid retention period format is not allowed",
				generateConfig("bucket", "96h", "compliance", true),
				generateConfig("bucket", "invalid", "compliance", true),
				"invalid duration",
			),
		)
	})

	Describe("ValidateCreate", func() {
		DescribeTable("Valid creation scenarios",
			func(config *runtime.RawExtension) {
				Expect(ValidateBackupBucketProviderConfigCreate(lenientDecoder, config, fldPath)).To(BeEmpty())
			},
			Entry("Creation with empty provider config",
				&runtime.RawExtension{},
			),
			Entry("Creation with valid immutable settings",
				generateConfig("bucket", "96h", "compliance", true),
			),
			Entry("Creation without immutable settings",
				generateConfig("", "", "", false),
			),
			Entry("Creation with compliance mode immutable settings",
				generateConfig("bucket", "96h", "compliance", true),
			),
			Entry("Retention period exactly at minimum (24h) with mode: governance",
				generateConfig("bucket", "24h", "governance", true),
			),
			Entry("Retention period of 3 days i.e 72h",
				generateConfig("bucket", "72h", "governance", true),
			),
			Entry("Backup not configured",
				generateConfig("", "", "", false),
			),
		)

		DescribeTable("Invalid creation scenarios",
			func(config *runtime.RawExtension, expectedError string) {
				errList := ValidateBackupBucketProviderConfigCreate(lenientDecoder, config, fldPath)
				Expect(errList).NotTo(BeEmpty())
				Expect(errList.ToAggregate().Error()).To(ContainSubstring(expectedError))
			},
			Entry("Invalid retention type",
				generateConfig("invalid", "96h", "governance", true),
				"must be 'bucket'",
			),
			Entry("Invalid retention period format",
				&runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1",
"kind": "BackupBucketConfig",
"immutability":{
	"retentionType": "bucket",
	"retentionPeriod": "invalid",
	"mode": "compliance"
}}`),
				},
				"invalid duration",
			),
			Entry("Negative retention period",
				generateConfig("bucket", "-96h", "compliance", true),
				"can't be less than 24hour",
			),
			Entry("Retention period below minimum retention period",
				generateConfig("bucket", "23h", "compliance", true),
				"can't be less than 24hour",
			),
			Entry("Retention period not multiple of 24h",
				generateConfig("bucket", "100h", "compliance", true),
				"must be a multiple of 24hour",
			),
			Entry("Invalid mode",
				generateConfig("bucket", "72h", "invalid", true),
				"should be either compliance mode or governance mode",
			),
			Entry("Invalid retention period format",
				generateConfig("bucket", "invalid", "compliance", true),
				"invalid duration",
			),
		)
	})
})
