// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package cloudprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/webhook/cloudprovider"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	securityv1alpha1constants "github.com/gardener/gardener/pkg/apis/security/v1alpha1/constants"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

// NewEnsurer creates cloudprovider ensurer.
func NewEnsurer(logger logr.Logger) cloudprovider.Ensurer {
	return &ensurer{
		logger: logger,
	}
}

type ensurer struct {
	logger logr.Logger
}

// EnsureCloudProviderSecret ensures that cloudprovider secret contains
// the shared credentials file.
func (e *ensurer) EnsureCloudProviderSecret(ctx context.Context, gctx gcontext.GardenContext, newSecret, _ *corev1.Secret) error {
	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	if newSecret.Labels != nil && newSecret.Labels[securityv1alpha1constants.LabelWorkloadIdentityProvider] == "aws" {
		if _, ok := newSecret.Data[securityv1alpha1constants.DataKeyConfig]; !ok {
			return errors.New("cloudprovider secret is missing a 'config' data key")
		}
		workloadIdentityConfig, err := helper.WorkloadIdentityConfigFromBytes(newSecret.Data[securityv1alpha1constants.DataKeyConfig])
		if err != nil {
			return fmt.Errorf("could not decode 'config' as WorkloadIdentityConfig: %w", err)
		}

		// Validate the decoded config at this sink before interpolating any of its values into the
		// shared credentials file. Garden-side admission is defense in depth only; this is the trust
		// boundary where the INI file is produced, so values that could introduce new INI directives
		// (e.g. role_arn carrying CR/LF) must be rejected here as well.
		if errs := validation.ValidateWorkloadIdentityConfig(workloadIdentityConfig, field.NewPath("config")); len(errs) > 0 {
			return fmt.Errorf("invalid WorkloadIdentityConfig in cloudprovider secret: %w", errs.ToAggregate())
		}
		if errs := validation.ValidateRegion(cluster.Shoot.Spec.Region, field.NewPath("shoot", "spec", "region")); len(errs) > 0 {
			return fmt.Errorf("invalid region for cloudprovider secret: %w", errs.ToAggregate())
		}

		newSecret.Data[aws.RoleARN] = []byte(workloadIdentityConfig.RoleARN)
		newSecret.Data[aws.WorkloadIdentityTokenFileKey] = []byte(aws.WorkloadIdentityMountPath + "/token")
		newSecret.Data[aws.SharedCredentialsFile] = []byte("[default]\n" +
			fmt.Sprintf("web_identity_token_file=%s\n", aws.WorkloadIdentityMountPath+"/token") +
			fmt.Sprintf("role_arn=%s\n", workloadIdentityConfig.RoleARN) +
			fmt.Sprintf("region=%s", cluster.Shoot.Spec.Region),
		)
		return nil
	}

	if _, ok := newSecret.Data[aws.AccessKeyID]; !ok {
		return fmt.Errorf("could not mutate cloudprovider secret as %q field is missing", aws.AccessKeyID)
	}
	if _, ok := newSecret.Data[aws.SecretAccessKey]; !ok {
		return fmt.Errorf("could not mutate cloudprovider secret as %q field is missing", aws.SecretAccessKey)
	}

	// Validate the credential values at this sink before interpolating them into the shared
	// credentials file. The charset/length checks reject newlines and INI metacharacters so tenant
	// bytes cannot introduce new directives or sections (e.g. an injected source_profile chaining to
	// credential_process). Garden-side admission runs the same checks but is bypassable, so enforce
	// here at the trust boundary where the file is produced.
	if errs := validation.ValidateCloudProviderCredentialValues(
		string(newSecret.Data[aws.AccessKeyID]),
		string(newSecret.Data[aws.SecretAccessKey]),
		cluster.Shoot.Spec.Region,
		field.NewPath("secret", "data"),
	); len(errs) > 0 {
		return fmt.Errorf("invalid cloudprovider secret: %w", errs.ToAggregate())
	}

	e.logger.V(5).Info("mutate cloudprovider secret", "namespace", newSecret.Namespace, "name", newSecret.Name)
	newSecret.Data[aws.SharedCredentialsFile] = []byte("[default]\n" +
		fmt.Sprintf("aws_access_key_id=%s\n", string(newSecret.Data[aws.AccessKeyID])) +
		fmt.Sprintf("aws_secret_access_key=%s\n", string(newSecret.Data[aws.SecretAccessKey])) +
		fmt.Sprintf("region=%s", cluster.Shoot.Spec.Region),
	)

	return nil
}
