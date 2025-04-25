// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RetentionType defines the level at which immutability properties are applied on objects.
type RetentionType string

const (
	// BucketLevelImmutability sets the immutability feature on the bucket level.
	BucketLevelImmutability RetentionType = "bucket"
	// ComplianceMode is for "compliance" mode immutability.
	ComplianceMode string = "compliance"
	// GovernanceMode mode is of "governance" mode immutability.
	GovernanceMode string = "governance"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BackupBucketConfig represents the configuration for a backup bucket.
type BackupBucketConfig struct {
	metav1.TypeMeta

	// Immutability defines the immutability configuration for the backup bucket.
	Immutability *ImmutableConfig
}

// ImmutableConfig represents the immutability configuration for a backup bucket.
type ImmutableConfig struct {
	// RetentionType specifies the type of retention for the backup bucket.
	// Currently allowed value is:
	// - "bucket": retention policy applies on the entire bucket.
	RetentionType RetentionType

	// RetentionPeriod specifies the immutability retention period for the backup bucket.
	// S3 only supports immutability durations in days or years, therefore this field must be set as multiple of 24h.
	RetentionPeriod metav1.Duration

	// S3 provides two retention modes that apply different levels of protection to objects:
	// Allowed values are: "governance" or "compliance" mode.
	Mode string
}
