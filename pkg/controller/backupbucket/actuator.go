// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket

import (
	"context"
	"errors"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gardener/gardener/extensions/pkg/controller/backupbucket"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/validator"
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

type actuator struct {
	backupbucket.Actuator
	client client.Client
}

func newActuator(mgr manager.Manager) backupbucket.Actuator {
	return &actuator{
		client: mgr.GetClient(),
	}
}

// Reconcile reconciles the BackupBucket resource with following:
// 1. Create aws client from secret ref.
// 2. Decode the backupbucket config (if provided).
// 3. Check if bucket already exist or not.
// 4. If bucket doesn't exist
//   - then create a new bucket according to backupbucketConfig, if provided.
//    If bucket exist
//   - check isUpdateRequired
//   - If yes then update the backup bucket according to backupbucketConfig(if provided)
//     otherwise do nothing.

func (a *actuator) Reconcile(ctx context.Context, logger logr.Logger, bb *extensionsv1alpha1.BackupBucket) error {
	logger.Info("Starting reconciliation for BackupBucket...")

	awsClient, err := aws.NewClientFromSecretRef(ctx, a.client, bb.Spec.SecretRef, bb.Spec.Region)
	if err != nil {
		return util.DetermineError(err, helper.KnownCodes)
	}

	s3client := awsClient.GetS3Client()

	var backupbucketConfig *apisaws.BackupBucketConfig
	if bb.Spec.ProviderConfig != nil {
		backupbucketConfig, err = validator.DecodeBackupBucketConfig(serializer.NewCodecFactory(a.client.Scheme(), serializer.EnableStrict).UniversalDecoder(), bb.Spec.ProviderConfig)
		if err != nil {
			logger.Error(err, "Failed to decode provider config")
			return err
		}
	}

	bucketVersioningStatus, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: awsv2.String(bb.Name),
	})
	if err != nil {
		var noSuchBucket *s3types.NoSuchBucket
		if errors.As(err, &noSuchBucket) {
			// bucket doesn't exist, create the bucket with buckupbucket config (if provided)
			return util.DetermineError(awsClient.CreateBucket(ctx, bb.Name, bb.Spec.Region, backupbucketConfig), helper.KnownCodes)
		}
	}

	if bucketVersioningStatus != nil && bucketVersioningStatus.Status == s3types.BucketVersioningStatusEnabled {
		// versioning is found to be enabled on bucket
		if isBucketUpdateRequired(ctx, s3client, bb.Name, backupbucketConfig) {
			return util.DetermineError(awsClient.UpdateBucket(ctx, bb.Name, backupbucketConfig, true), helper.KnownCodes)
		}
	}

	// object versioning is not found to be enabled on bucket
	// update the bucket according to buckupbucketConfig(if provided)
	return util.DetermineError(awsClient.UpdateBucket(ctx, bb.Name, backupbucketConfig, false), helper.KnownCodes)
}

func (a *actuator) Delete(ctx context.Context, _ logr.Logger, bb *extensionsv1alpha1.BackupBucket) error {
	awsClient, err := aws.NewClientFromSecretRef(ctx, a.client, bb.Spec.SecretRef, bb.Spec.Region)
	if err != nil {
		return util.DetermineError(err, helper.KnownCodes)
	}

	return util.DetermineError(awsClient.DeleteBucketIfExists(ctx, bb.Name), helper.KnownCodes)
}

func isBucketUpdateRequired(ctx context.Context, s3client s3.Client, bucket string, backupbucketConfig *apisaws.BackupBucketConfig) bool {
	if backupbucketConfig == nil || backupbucketConfig.Immutability == nil {
		return false
	}

	if objectConfig, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: awsv2.String(bucket),
	}); err != nil {
		// if object lock configurations aren't set on bucket
		// then bucket update is required
		return true
	} else if objectConfig != nil && objectConfig.ObjectLockConfiguration != nil && objectConfig.ObjectLockConfiguration.ObjectLockEnabled == s3types.ObjectLockEnabledEnabled {
		// If object lock is enabled for bucket then check the object lock rules defined for bucket
		if *objectConfig.ObjectLockConfiguration.Rule.DefaultRetention.Days == int32(backupbucketConfig.Immutability.RetentionPeriod.Duration/(24*time.Hour)) &&
			objectConfig.ObjectLockConfiguration.Rule.DefaultRetention.Mode == getBuckeRetentiontMode(backupbucketConfig.Immutability.Mode) {
			return false
		}
	}

	return true
}

func getBuckeRetentiontMode(mode string) s3types.ObjectLockRetentionMode {
	if mode == "governance" {
		return s3types.ObjectLockRetentionModeGovernance
	}
	return s3types.ObjectLockRetentionModeCompliance
}
