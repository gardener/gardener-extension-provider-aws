// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket

import (
	"context"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	awsvalidation "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

type validator struct {
	decoder        runtime.Decoder
	lenientDecoder runtime.Decoder
}

// New returns a new BackupBucket validator that validates the extensionsv1alpha1.BackupBucket
func New(mgr manager.Manager) extensionswebhook.Validator {
	return &validator{
		decoder:        serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		lenientDecoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
	}
}

// Validate validates the given object on creation or update.
func (v *validator) Validate(_ context.Context, newObj, oldObj client.Object) error {
	newBackupBucket, ok := newObj.(*extensionsv1alpha1.BackupBucket)
	if !ok {
		return fmt.Errorf("wrong object type %T for new object", newObj)
	}

	if oldObj != nil {
		oldBackupBucket, ok := oldObj.(*extensionsv1alpha1.BackupBucket)
		if !ok {
			return fmt.Errorf("wrong object type %T for old object", oldObj)
		}
		return v.validateUpdate(oldBackupBucket, newBackupBucket).ToAggregate()
	}

	return v.validateCreate(newBackupBucket).ToAggregate()
}

// validateCreate validates the BackupBucket object upon creation.
// It checks if immutable settings are provided and if provided then it validates the immutable settings.
func (v *validator) validateCreate(backupBucket *extensionsv1alpha1.BackupBucket) field.ErrorList {
	var (
		allErrs               = field.ErrorList{}
		providerConfigfldPath = field.NewPath("spec", "providerConfig")
	)

	allErrs = append(allErrs, awsvalidation.ValidateBackupBucketProviderConfigCreate(v.lenientDecoder, backupBucket.Spec.ProviderConfig, providerConfigfldPath)...)

	return allErrs
}

// validateUpdate validates updates to the BackupBucket resource, ensuring that immutability settings for backup buckets
// are correctly managed. It enforces constraints such as changing of retention mode from compliance -> governance,
// and reduction of retention periods in compliance mode.
func (v *validator) validateUpdate(oldBackupBucket, backupBucket *extensionsv1alpha1.BackupBucket) field.ErrorList {
	var (
		allErrs               = field.ErrorList{}
		providerConfigfldPath = field.NewPath("spec", "providerConfig")
	)

	if oldBackupBucket.Spec.ProviderConfig == nil {
		return v.validateCreate(backupBucket)
	}

	allErrs = append(allErrs, awsvalidation.ValidateBackupBucketProviderConfigUpdate(v.decoder, v.lenientDecoder, oldBackupBucket.Spec.ProviderConfig, backupBucket.Spec.ProviderConfig, providerConfigfldPath)...)

	return allErrs
}
