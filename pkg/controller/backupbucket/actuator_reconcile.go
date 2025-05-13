// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket

import (
	"context"
	"fmt"
	"time"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/validator"
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// Reconcile reconciles the BackupBucket resource with following steps:
// 1. Create aws client from secret ref.
// 2. Decode the backupbucket config (if provided).
// 3. Check if bucket already exist or not.
// 4. If bucket doesn't exist
//   - then create a new bucket according to backupbucketConfig, if provided.
//
// 5. If bucket exist
//   - check for bucket update is required or not
//   - If yes then update the backup bucket settings according to backupbucketConfig(if provided)
//     otherwise do nothing.
func (a *actuator) Reconcile(ctx context.Context, logger logr.Logger, bb *extensionsv1alpha1.BackupBucket) error {
	logger.Info("Starting reconciliation of BackupBucket...")

	authConfig, err := aws.GetCredentialsFromSecretRef(ctx, a.client, bb.Spec.SecretRef, false, bb.Spec.Region)
	if err != nil {
		return util.DetermineError(fmt.Errorf("could not get AWS credentials: %w", err), helper.KnownCodes)
	}

	awsClient, err := a.awsClientFactory.NewClient(*authConfig)
	if err != nil {
		return util.DetermineError(err, helper.KnownCodes)
	}

	var backupbucketConfig *apisaws.BackupBucketConfig
	if bb.Spec.ProviderConfig != nil {
		backupbucketConfig, err = validator.DecodeBackupBucketConfig(serializer.NewCodecFactory(a.client.Scheme(), serializer.EnableStrict).UniversalDecoder(), bb.Spec.ProviderConfig)
		if err != nil {
			return util.DetermineError(fmt.Errorf("failed to decode provider config: %w", err), helper.KnownCodes)
		}
	}

	// If immutability settings are provided then "isObjectLockRequired" will get set to `true`.
	isObjectLockRequired := (backupbucketConfig != nil && backupbucketConfig.Immutability != nil)

	enableOrUpdateObjectLock := func(ctx context.Context, enableVersioning bool) error {
		// Enable versioning on the bucket as a prerequisite for enabling object lock.
		if enableVersioning {
			// enable the versioning on the bucket,
			if err := awsClient.EnableBucketVersioning(ctx, bb.Name); err != nil {
				return err
			}
		}

		// enable or update the object lock config on the bucket.
		if isObjectLockRequired {
			// #nosec G115
			return awsClient.UpdateObjectLockConfiguration(ctx, bb.Name, backupbucketConfig.Immutability.Mode, int32(backupbucketConfig.Immutability.RetentionPeriod.Duration/(24*time.Hour)))
		}
		return nil
	}
	a.action = ActionFunc(enableOrUpdateObjectLock)

	return util.DetermineError(a.reconcile(ctx, backupbucketConfig, awsClient, bb, isObjectLockRequired), helper.KnownCodes)
}

func (a *actuator) reconcile(ctx context.Context, backupbucketConfig *apisaws.BackupBucketConfig, awsClient awsclient.Interface, bb *extensionsv1alpha1.BackupBucket, isObjectLockRequired bool) error {
	bucketVersioningStatus, err := awsClient.GetBucketVersioningStatus(ctx, bb.Name)
	if err != nil {
		apiErrCode := awsclient.GetAWSAPIErrorCode(err)
		switch apiErrCode {
		case "NoSuchBucket":
			// bucket doesn't exist, create the bucket with buckupbucket config (if provided)
			return util.DetermineError(a.createBucketWithConfig(ctx, awsClient, bb.Name, bb.Spec.Region, isObjectLockRequired), helper.KnownCodes)
		case "PermanentRedirect":
			return util.DetermineError(fmt.Errorf("bucket exists in different region %v", err), helper.KnownCodes)
		default:
			return util.DetermineError(fmt.Errorf("unable to check bucket versioning status: %v", err), helper.KnownCodes)
		}
	}

	// versioning is found to be enabled on bucket
	if bucketVersioningStatus != nil && bucketVersioningStatus.Status == s3types.BucketVersioningStatusEnabled {
		if isObjectLockConfigNeedToBeRemoved(ctx, awsClient, bb.Name, backupbucketConfig) {
			return util.DetermineError(awsClient.RemoveObjectLockConfiguration(ctx, bb.Name), helper.KnownCodes)
		} else if isBucketUpdateRequired(ctx, awsClient, bb.Name, backupbucketConfig) {
			// take action: update the bucket with object lock settings.
			return util.DetermineError(a.action.Do(ctx, false), helper.KnownCodes)
		}
		// do nothing if bucket configurations isn't required to be updated.
		return nil
	}

	if isObjectLockRequired {
		// take action: enable object lock on the bucket.
		// Note: Enable versioning on the bucket as a prerequisite for enabling object lock.
		return util.DetermineError(a.action.Do(ctx, true), helper.KnownCodes)
	}
	return nil
}

func (a *actuator) createBucketWithConfig(ctx context.Context, awsClient awsclient.Interface, bucketName, region string, isObjectLockRequired bool) error {
	// create the bucket in a given region
	if err := awsClient.CreateBucket(ctx, bucketName, region, isObjectLockRequired); err != nil {
		return err
	}

	if isObjectLockRequired {
		// take action: update the bucket with object lock settings.
		return a.action.Do(ctx, false)
	}
	return nil
}

func isBucketUpdateRequired(ctx context.Context, awsClient awsclient.Interface, bucket string, backupbucketConfig *apisaws.BackupBucketConfig) bool {
	if backupbucketConfig == nil || backupbucketConfig.Immutability == nil {
		return false
	}

	if objectConfig, err := awsClient.GetObjectLockConfiguration(ctx, bucket); err != nil {
		// if object lock configurations aren't set on bucket
		// then bucket update is required
		return true
	} else if objectConfig != nil && objectConfig.ObjectLockConfiguration != nil && objectConfig.ObjectLockConfiguration.ObjectLockEnabled == s3types.ObjectLockEnabledEnabled {
		// If object lock is enabled for bucket then check the object lock rules defined for bucket
		// #nosec G115
		if objectConfig.ObjectLockConfiguration.Rule != nil && *objectConfig.ObjectLockConfiguration.Rule.DefaultRetention.Days == int32(backupbucketConfig.Immutability.RetentionPeriod.Duration/(24*time.Hour)) &&
			objectConfig.ObjectLockConfiguration.Rule.DefaultRetention.Mode == awsclient.GetBucketRetentiontMode(backupbucketConfig.Immutability.Mode) {
			return false
		}
	}

	return true
}

func isObjectLockConfigNeedToBeRemoved(ctx context.Context, awsClient awsclient.Interface, bucket string, backupbucketConfig *apisaws.BackupBucketConfig) bool {
	objectConfig, err := awsClient.GetObjectLockConfiguration(ctx, bucket)
	if err != nil {
		// object lock config is not set
		return false
	}

	if objectConfig != nil && objectConfig.ObjectLockConfiguration != nil && objectConfig.ObjectLockConfiguration.ObjectLockEnabled == s3types.ObjectLockEnabledEnabled {
		if objectConfig.ObjectLockConfiguration.Rule == nil {
			// object lock config rules are already not set on bucket.
			return false
		} else if backupbucketConfig == nil || backupbucketConfig.Immutability == nil {
			return true
		}
	}
	return false
}
