// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cloudprovider

import (
	"context"
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/webhook/cloudprovider"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

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
func (e *ensurer) EnsureCloudProviderSecret(_ context.Context, _ gcontext.GardenContext, new, _ *corev1.Secret) error {
	if _, ok := new.Data[aws.AccessKeyID]; !ok {
		return fmt.Errorf("could not mutate cloudprovider secret as %q field is missing", aws.AccessKeyID)
	}
	if _, ok := new.Data[aws.SecretAccessKey]; !ok {
		return fmt.Errorf("could not mutate cloudprovider secret as %q field is missing", aws.SecretAccessKey)
	}

	e.logger.V(5).Info("mutate cloudprovider secret", "namespace", new.Namespace, "name", new.Name)
	new.Data[aws.SharedCredentialsFile] = []byte("[default]\n" +
		fmt.Sprintf("aws_access_key_id=%s\n", string(new.Data[aws.AccessKeyID])) +
		fmt.Sprintf("aws_secret_access_key=%s", string(new.Data[aws.SecretAccessKey])),
	)

	return nil
}
