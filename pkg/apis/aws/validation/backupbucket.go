// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawshelper "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
)

// ValidateBackupBucketProviderConfigCreate validates the BackupBucket provider config on creation.
func ValidateBackupBucketProviderConfigCreate(lenientDecoder runtime.Decoder, config *runtime.RawExtension, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	backupBucketConfig, err := apisawshelper.DecodeBackupBucketConfig(lenientDecoder, config)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, config, fmt.Errorf("failed to decode new provider config: %v", err).Error()))
		return allErrs
	}

	allErrs = append(allErrs, ValidateBackupBucketConfig(backupBucketConfig, fldPath)...)

	return allErrs
}

// ValidateBackupBucketProviderConfigUpdate validates the BackupBucket provider config on update.
func ValidateBackupBucketProviderConfigUpdate(decoder, lenientDecoder runtime.Decoder, oldConfig, newConfig *runtime.RawExtension, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	oldBackupBucketConfig, err := apisawshelper.DecodeBackupBucketConfig(lenientDecoder, oldConfig)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, oldConfig, fmt.Errorf("failed to decode old provider config: %v", err).Error()))
		return allErrs
	}

	newBackupBucketConfig, err := apisawshelper.DecodeBackupBucketConfig(decoder, newConfig)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, newConfig, fmt.Errorf("failed to decode new provider config: %v", err).Error()))
		return allErrs
	}

	allErrs = append(allErrs, ValidateBackupBucketConfig(newBackupBucketConfig, fldPath)...)
	allErrs = append(allErrs, validateBackupBucketImmutabilityUpdate(oldBackupBucketConfig, newBackupBucketConfig, fldPath)...)

	return allErrs
}

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

// validateBackupBucketImmutabilityUpdate validates immutability constraints.
func validateBackupBucketImmutabilityUpdate(oldConfig, newConfig *apisaws.BackupBucketConfig, fldPath *field.Path) field.ErrorList {
	var (
		allErrs          = field.ErrorList{}
		immutabilityPath = fldPath.Child("immutability")
	)

	// Note: Right now, immutability can be disabled.
	// TODO: @ishan16696 to remove these conditions "newConfig == nil || newConfig.Immutability == nil" to not allow disablement of immutability settings.
	if oldConfig == nil || oldConfig.Immutability == nil || newConfig == nil || newConfig.Immutability == nil {
		return allErrs
	}

	// TODO: @ishan16696 uncomment this piece of code, so once disablement of the immutability settings on bucket is not allowed.
	/*
		if newConfig == nil || newConfig.Immutability == nil || *newConfig.Immutability == (apisaws.ImmutableConfig{}) {
			allErrs = append(allErrs, field.Invalid(immutabilityPath, newConfig, "immutability cannot be disabled"))
			return allErrs
		}
	*/

	if oldConfig.Immutability.Mode == apisaws.ComplianceMode && newConfig.Immutability.Mode == apisaws.GovernanceMode {
		allErrs = append(allErrs, field.Forbidden(immutabilityPath.Child("mode"), "immutable retention mode can't be change to governance once it is compliance"))
	} else if oldConfig.Immutability.Mode == apisaws.ComplianceMode && newConfig.Immutability.RetentionPeriod.Duration < oldConfig.Immutability.RetentionPeriod.Duration {
		allErrs = append(allErrs, field.Forbidden(
			immutabilityPath.Child("retentionPeriod"),
			fmt.Sprintf("reducing the retention period from %v to %v is prohibited when the immutable retention mode is compliance",
				oldConfig.Immutability.RetentionPeriod.Duration,
				newConfig.Immutability.RetentionPeriod.Duration,
			),
		))
	}

	return allErrs
}
