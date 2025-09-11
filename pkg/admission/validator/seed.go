// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
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

	awsvalidation "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

// seedValidator validates create and update operations on Seed resources,
// enforcing immutability of backup configurations.
type seedValidator struct {
	decoder        runtime.Decoder
	lenientDecoder runtime.Decoder
}

// NewSeedValidator returns a new instance of seed validator,
// to validate backupbucket configuration.
func NewSeedValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &seedValidator{
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
		allErrs = field.ErrorList{}
	)

	if seed.Spec.Backup != nil {
		backupPath := field.NewPath("spec", "backup")
		allErrs = append(allErrs, awsvalidation.ValidateBackupBucketCredentialsRef(seed.Spec.Backup.CredentialsRef, backupPath.Child("credentialsRef"))...)

		if seed.Spec.Backup.ProviderConfig != nil {
			allErrs = append(allErrs, awsvalidation.ValidateBackupBucketProviderConfigCreate(s.lenientDecoder, seed.Spec.Backup.ProviderConfig, backupPath.Child("providerConfig"))...)
		}
	}

	return allErrs
}

// validateUpdate validates updates to the Seed resource, ensuring that immutability settings for backup buckets
// are correctly managed. It enforces constraints such as changing of retention mode from compliance -> governance,
// and reduction of retention periods in compliance mode.
func (s *seedValidator) validateUpdate(oldSeed, newSeed *core.Seed) field.ErrorList {
	var (
		allErrs    = field.ErrorList{}
		backupPath = field.NewPath("spec", "backup")

		oldBackupBucketConfig *runtime.RawExtension = nil
		newBackupBucketConfig *runtime.RawExtension = nil
	)

	if oldSeed.Spec.Backup != nil {
		oldBackupBucketConfig = oldSeed.Spec.Backup.ProviderConfig
	}

	if newSeed.Spec.Backup != nil {
		newBackupBucketConfig = newSeed.Spec.Backup.ProviderConfig
		allErrs = append(allErrs, awsvalidation.ValidateBackupBucketCredentialsRef(newSeed.Spec.Backup.CredentialsRef, backupPath.Child("credentialsRef"))...)
	}

	allErrs = append(allErrs, awsvalidation.ValidateBackupBucketProviderConfigUpdate(s.decoder, s.lenientDecoder, oldBackupBucketConfig, newBackupBucketConfig, backupPath.Child("providerConfig"))...)
	return allErrs
}
