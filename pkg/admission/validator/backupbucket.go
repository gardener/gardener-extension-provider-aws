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

	awsvalidation "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

// backupBucketValidator validates create and update operations on BackupBucket resources,
// enforcing immutability of backup configurations.
type backupBucketValidator struct {
	decoder        runtime.Decoder
	lenientDecoder runtime.Decoder
}

// NewBackupBucketValidator returns a new instance of backupBucket validator,
// to validate backupbucket configuration.
func NewBackupBucketValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &backupBucketValidator{
		decoder:        serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		lenientDecoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
	}
}

// Validate validates the BackupBucket resource during create or update operations.
// It enforces immutability policies on backup configurations to prevent
// disabling immutable settings, reducing retention periods, or changing retention types and mode.
func (s *backupBucketValidator) Validate(_ context.Context, newObj, oldObj client.Object) error {
	newBackupBucket, ok := newObj.(*core.BackupBucket)
	if !ok {
		return fmt.Errorf("wrong object type %T for new object", newObj)
	}

	if oldObj != nil {
		oldBackupBucket, ok := oldObj.(*core.BackupBucket)
		if !ok {
			return fmt.Errorf("wrong object type %T for old object", oldObj)
		}
		return s.validateUpdate(oldBackupBucket, newBackupBucket).ToAggregate()
	}

	return s.validateCreate(newBackupBucket).ToAggregate()
}

// validateCreate validates the BackupBucket object upon creation.
// It checks if immutable settings are provided and if provided then it validates the immutable settings.
func (b *backupBucketValidator) validateCreate(backupBucket *core.BackupBucket) field.ErrorList {
	var (
		allErrs               = field.ErrorList{}
		providerConfigfldPath = field.NewPath("spec", "providerConfig")
	)

	allErrs = append(allErrs, awsvalidation.ValidateBackupBucketProviderConfigCreate(b.lenientDecoder, backupBucket.Spec.ProviderConfig, providerConfigfldPath)...)

	return allErrs
}

// validateUpdate validates updates to the BackupBucket resource, ensuring that immutability settings for backup buckets
// are correctly managed. It enforces constraints such as changing of retention mode from compliance -> governance,
// and reduction of retention periods in compliance mode.
func (b *backupBucketValidator) validateUpdate(oldBackupBucket, backupBucket *core.BackupBucket) field.ErrorList {
	var (
		allErrs               = field.ErrorList{}
		providerConfigfldPath = field.NewPath("spec", "providerConfig")
	)

	if oldBackupBucket.Spec.ProviderConfig == nil {
		return b.validateCreate(backupBucket)
	}

	allErrs = append(allErrs, awsvalidation.ValidateBackupBucketProviderConfigUpdate(b.decoder, b.lenientDecoder, oldBackupBucket.Spec.ProviderConfig, backupBucket.Spec.ProviderConfig, providerConfigfldPath)...)

	return allErrs
}
