// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"time"

	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ValidateBackupBucketConfig validates a BackupBucketConfig object.
func ValidateBackupBucketConfig(backupBucketConfig *apisaws.BackupBucketConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if backupBucketConfig == nil || backupBucketConfig.Immutability == nil {
		return allErrs
	}

	// Currently, only RetentionType: BucketLevelImmutability is supported.
	if backupBucketConfig.Immutability.RetentionType != apisaws.BucketLevelImmutability {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("immutability", "retentionType"), backupBucketConfig.Immutability.RetentionType, "must be 'bucket'"))
	}

	// AWS S3 immutability period can only be set in days and can't be less than 1 day(24h) and must be a positive integer.
	if backupBucketConfig.Immutability.RetentionPeriod.Duration < 24*time.Hour {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("immutability", "retentionPeriod"), backupBucketConfig.Immutability.RetentionPeriod.Duration.String(), "can only be set in days, hence it can't be less than 24hour"))
	}

	// AWS S3 immutability period can only be set in days, hence it must be a multiple of 24h.
	if backupBucketConfig.Immutability.RetentionPeriod.Duration%(24*time.Hour) != 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("immutability", "retentionPeriod"), backupBucketConfig.Immutability.RetentionPeriod.Duration.String(), "can only be set in days, hence it must be a multiple of 24hour"))
	}

	// AWS S3 only supports two types of retention modes: compliance and governance mode.
	if backupBucketConfig.Immutability.Mode != apisaws.ComplianceMode && backupBucketConfig.Immutability.Mode != apisaws.GovernanceMode {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("immutability", "mode"), backupBucketConfig.Immutability.Mode, "should be either compliance mode or governance mode"))
	}

	return allErrs
}
