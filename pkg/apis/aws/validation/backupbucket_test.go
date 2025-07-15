// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

var _ = Describe("ValidateBackupBucketConfig", func() {
	var fldPath *field.Path

	BeforeEach(func() {
		fldPath = field.NewPath("spec")
	})

	DescribeTable("validation cases",
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
})
