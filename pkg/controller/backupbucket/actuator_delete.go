// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket

import (
	"context"
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

func (a *actuator) Delete(ctx context.Context, _ logr.Logger, bb *extensionsv1alpha1.BackupBucket) error {
	authConfig, err := aws.GetCredentialsFromSecretRef(ctx, a.client, bb.Spec.SecretRef, false, bb.Spec.Region)
	if err != nil {
		return util.DetermineError(fmt.Errorf("could not get AWS credentials: %w", err), helper.KnownCodes)
	}

	awsClient, err := a.awsClientFactory.NewClient(*authConfig)
	if err != nil {
		return util.DetermineError(err, helper.KnownCodes)
	}

	return util.DetermineError(awsClient.DeleteBucketIfExists(ctx, bb.Name), helper.KnownCodes)
}
