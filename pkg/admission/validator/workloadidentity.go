// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"errors"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	securityv1alpha1 "github.com/gardener/gardener/pkg/apis/security/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission"
	awsvalidation "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

type workloadIdentity struct {
	decoder runtime.Decoder
}

// NewWorkloadIdentityValidator returns a new instance of a WorkloadIdentity validator.
func NewWorkloadIdentityValidator(decoder runtime.Decoder) extensionswebhook.Validator {
	return &workloadIdentity{
		decoder: decoder,
	}
}

// Validate checks whether the given new workloadidentity contains a valid AWS configuration.
func (wi *workloadIdentity) Validate(_ context.Context, newObj, oldObj client.Object) error {
	workloadIdentity, ok := newObj.(*securityv1alpha1.WorkloadIdentity)
	if !ok {
		return fmt.Errorf("wrong object type %T", newObj)
	}

	if workloadIdentity.Spec.TargetSystem.ProviderConfig == nil {
		return errors.New("the new target system is missing configuration")
	}

	newConfig, err := admission.DecodeWorkloadIdentityConfig(wi.decoder, workloadIdentity.Spec.TargetSystem.ProviderConfig)
	if err != nil {
		return fmt.Errorf("cannot decode the new target system's configuration: %w", err)
	}

	fieldPath := field.NewPath("spec", "targetSystem", "providerConfig")
	if oldObj != nil {
		oldWorkloadIdentity, ok := oldObj.(*securityv1alpha1.WorkloadIdentity)
		if !ok {
			return fmt.Errorf("wrong object type %T for old object", oldObj)
		}

		oldConfig, err := admission.DecodeWorkloadIdentityConfig(wi.decoder, oldWorkloadIdentity.Spec.TargetSystem.ProviderConfig)
		if err != nil {
			return fmt.Errorf("cannot decode the old target system's configuration: %w", err)
		}
		errList := awsvalidation.ValidateWorkloadIdentityConfigUpdate(oldConfig, newConfig, fieldPath)
		if len(errList) > 0 {
			return fmt.Errorf("validation of target system's configuration failed: %w", errList.ToAggregate())
		}
		return nil
	}

	errList := awsvalidation.ValidateWorkloadIdentityConfig(newConfig, fieldPath)
	if len(errList) > 0 {
		return fmt.Errorf("validation of target system's configuration failed: %w", errList.ToAggregate())
	}
	return nil
}
