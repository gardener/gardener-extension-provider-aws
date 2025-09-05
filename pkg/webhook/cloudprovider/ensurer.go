// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
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

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
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

	e.logger.V(5).Info("mutate cloudprovider secret", "namespace", newSecret.Namespace, "name", newSecret.Name)
	newSecret.Data[aws.SharedCredentialsFile] = []byte("[default]\n" +
		fmt.Sprintf("aws_access_key_id=%s\n", string(newSecret.Data[aws.AccessKeyID])) +
		fmt.Sprintf("aws_secret_access_key=%s\n", string(newSecret.Data[aws.SecretAccessKey])) +
		fmt.Sprintf("region=%s", cluster.Shoot.Spec.Region),
	)

	return nil
}
