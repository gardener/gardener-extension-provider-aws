// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsvalidation "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

// seedValidator validates create and update operations on Seed resources,
// enforcing immutability of backup configurations.
type seedValidator struct {
	client         client.Client
	decoder        runtime.Decoder
	lenientDecoder runtime.Decoder
}

// NewSeedValidator returns a new instance of seed validator,
// to validate backupbucket configuration.
func NewSeedValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &seedValidator{
		client:         mgr.GetClient(),
		decoder:        serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		lenientDecoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
	}
}

// Validate validates the Seed resource during create or update operations.
// It enforces immutability policies on backup configurations to prevent
// disabling immutable settings, reducing retention periods, or changing retention types and mode.
func (s *seedValidator) Validate(_ context.Context, newObj, oldObj client.Object) error {
	newSeed, ok := newObj.(*core.Seed)
	if !ok {
		return fmt.Errorf("wrong object type %T for new object", newObj)
	}

	if oldObj != nil {
		oldSeed, ok := oldObj.(*core.Seed)
		if !ok {
			return fmt.Errorf("wrong object type %T for old object", oldObj)
		}
		return s.validateUpdate(oldSeed, newSeed).ToAggregate()
	}

	return s.validateCreate(newSeed).ToAggregate()
}

// validateCreate validates the Seed object upon creation.
// It checks if immutable settings are provided and if provided then it validates the immutable settings.
func (s *seedValidator) validateCreate(seed *core.Seed) field.ErrorList {
	var (
		allErrs               = field.ErrorList{}
		providerConfigfldPath = field.NewPath("spec", "backup", "providerConfig")
	)

	if seed.Spec.Backup == nil || seed.Spec.Backup.ProviderConfig == nil {
		return allErrs
	}

	backupBucketConfig, err := s.extractBackupBucketConfig(seed, s.lenientDecoder)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(providerConfigfldPath, seed.Spec.Backup.ProviderConfig, fmt.Errorf("failed to decode new provider config: %v", err).Error()))
		return allErrs
	}

	allErrs = append(allErrs, awsvalidation.ValidateBackupBucketConfig(backupBucketConfig, providerConfigfldPath)...)

	return allErrs
}

// validateUpdate validates updates to the Seed resource, ensuring that immutability settings for backup buckets
// are correctly managed. It enforces constraints such as changing of retention mode from compliance -> governance,
// and reduction of retention periods in compliance mode.
func (s *seedValidator) validateUpdate(oldSeed, newSeed *core.Seed) field.ErrorList {
	var (
		allErrs               = field.ErrorList{}
		providerConfigfldPath = field.NewPath("spec", "backup", "providerConfig")
	)

	if oldSeed.Spec.Backup == nil || oldSeed.Spec.Backup.ProviderConfig == nil {
		return s.validateCreate(newSeed)
	}

	oldBackupBucketConfig, err := s.extractBackupBucketConfig(oldSeed, s.lenientDecoder)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(providerConfigfldPath, oldSeed.Spec.Backup.ProviderConfig, fmt.Errorf("failed to decode old provider config: %v", err).Error()))
		return allErrs
	}

	newBackupBucketConfig, err := s.extractBackupBucketConfig(newSeed, s.decoder)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(providerConfigfldPath, newSeed.Spec.Backup.ProviderConfig, fmt.Errorf("failed to decode new provider config: %v", err).Error()))
		return allErrs
	}

	allErrs = append(allErrs, awsvalidation.ValidateBackupBucketConfig(newBackupBucketConfig, providerConfigfldPath)...)
	allErrs = append(allErrs, s.validateImmutabilityUpdate(oldBackupBucketConfig, newBackupBucketConfig, providerConfigfldPath)...)

	return allErrs
}

// extractBackupBucketConfig extracts BackupBucketConfig from the Seed.
func (s *seedValidator) extractBackupBucketConfig(seed *core.Seed, decoder runtime.Decoder) (*apisaws.BackupBucketConfig, error) {
	if seed.Spec.Backup != nil && seed.Spec.Backup.ProviderConfig != nil {
		config, err := DecodeBackupBucketConfig(decoder, seed.Spec.Backup.ProviderConfig)
		if err != nil {
			return nil, err
		}
		return config, nil
	}

	return nil, nil
}

// validateImmutability validates immutability constraints.
func (s *seedValidator) validateImmutabilityUpdate(oldConfig, newConfig *apisaws.BackupBucketConfig, fldPath *field.Path) field.ErrorList {
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

	if oldConfig.Immutability.Mode == "compliance" && newConfig.Immutability.Mode == "governance" {
		allErrs = append(allErrs, field.Forbidden(immutabilityPath.Child("mode"), "immutable retention mode can't be change to governance once it is compliance"))
	} else if oldConfig.Immutability.Mode == "compliance" && newConfig.Immutability.RetentionPeriod.Duration < oldConfig.Immutability.RetentionPeriod.Duration {
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
