// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket_test

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	gardenerutils "github.com/gardener/gardener/pkg/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

func secretsFromEnv() {
	if len(*accessKeyID) == 0 {
		accessKeyID = ptr.To(os.Getenv("AWS_ACCESS_KEY_ID"))
	}
	if len(*secretAccessKey) == 0 {
		secretAccessKey = ptr.To(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	}
	if len(*region) == 0 {
		region = ptr.To(os.Getenv("REGION"))
	}
}

func validateFlags() {
	if len(*accessKeyID) == 0 {
		panic("AWS access key ID required. Either provide it via the access-key-id flag or set the AWS_ACCESS_KEY_ID environment variable")
	}
	if len(*secretAccessKey) == 0 {
		panic("AWS secret access key required. Either provide it via the secret-access-key flag or set the AWS_SECRET_ACCESS_KEY environment variable")
	}
	if len(*region) == 0 {
		panic("AWS region required. Either provide it via the region flag or set the REGION environment variable")
	}
	if len(*logLevel) == 0 {
		logLevel = ptr.To("debug")
	} else {
		if !slices.Contains([]string{"debug", "info", "error"}, *logLevel) {
			panic("Invalid log level: " + *logLevel)
		}
	}
}

func getS3Client(accessKeyID, secretAccessKey, region string) *s3.Client {
	authConfig := awsclient.AuthConfig{
		AccessKey: &awsclient.AccessKey{
			ID:     accessKeyID,
			Secret: secretAccessKey,
		},
		Region: region,
	}

	awsClient, err := awsclient.NewClient(authConfig)
	Expect(err).NotTo(HaveOccurred(), "Failed to create AWS client")

	return &awsClient.S3
}

func createNamespace(ctx context.Context, c client.Client, namespace *corev1.Namespace) {
	log.Info("Creating namespace", "namespace", namespace.Name)
	Expect(c.Create(ctx, namespace)).To(Succeed(), "Failed to create namespace: %s", namespace.Name)
}

func deleteNamespace(ctx context.Context, c client.Client, namespace *corev1.Namespace) {
	log.Info("Deleting namespace", "namespace", namespace.Name)
	Expect(client.IgnoreNotFound(c.Delete(ctx, namespace))).To(Succeed())
}

func createBackupBucketSecret(ctx context.Context, c client.Client, secret *corev1.Secret) {
	log.Info("Creating secret", "name", secret.Name, "namespace", secret.Namespace)
	Expect(c.Create(ctx, secret)).To(Succeed(), "Failed to create secret: %s", secret.Name)
}

func deleteBackupBucketSecret(ctx context.Context, c client.Client, secret *corev1.Secret) {
	log.Info("Deleting secret", "name", secret.Name, "namespace", secret.Namespace)
	Expect(client.IgnoreNotFound(c.Delete(ctx, secret))).To(Succeed())
}

func createBackupBucket(ctx context.Context, c client.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	log.Info("Creating backupBucket", "backupBucket", backupBucket)
	Expect(c.Create(ctx, backupBucket)).To(Succeed(), "Failed to create backupBucket: %s", backupBucket.Name)
}

func fetchBackupBucket(ctx context.Context, c client.Client, name string) *extensionsv1alpha1.BackupBucket {
	backupBucket := &extensionsv1alpha1.BackupBucket{}
	err := c.Get(ctx, client.ObjectKey{Name: name}, backupBucket)
	Expect(err).NotTo(HaveOccurred(), "Failed to fetch backupBucket from the cluster")
	return backupBucket
}

func deleteBackupBucket(ctx context.Context, c client.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	log.Info("Deleting backupBucket", "backupBucket", backupBucket)
	Expect(client.IgnoreNotFound(c.Delete(ctx, backupBucket))).To(Succeed())
}

func waitUntilBackupBucketReady(ctx context.Context, c client.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	Expect(extensions.WaitUntilExtensionObjectReady(
		ctx,
		c,
		log,
		backupBucket,
		extensionsv1alpha1.BackupBucketResource,
		10*time.Second,
		30*time.Second,
		5*time.Minute,
		nil,
	)).To(Succeed(), "BackupBucket did not become ready: %s", backupBucket.Name)
	log.Info("BackupBucket is ready", "backupBucket", backupBucket)
}

func waitUntilBackupBucketDeleted(ctx context.Context, c client.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	Expect(extensions.WaitUntilExtensionObjectDeleted(
		ctx,
		c,
		log,
		backupBucket.DeepCopy(),
		extensionsv1alpha1.BackupBucketResource,
		10*time.Second,
		5*time.Minute,
	)).To(Succeed())
	log.Info("BackupBucket successfully deleted", "backupBucket", backupBucket)
}

func newBackupBucket(name, region string, providerConfig *awsv1alpha1.BackupBucketConfig) *extensionsv1alpha1.BackupBucket {
	var providerConfigRaw *runtime.RawExtension
	if providerConfig != nil {
		providerConfig.APIVersion = "aws.provider.extensions.gardener.cloud/v1alpha1"
		providerConfig.Kind = "BackupBucketConfig"
		providerConfigJSON, err := json.Marshal(providerConfig)
		Expect(err).NotTo(HaveOccurred(), "Failed to marshal providerConfig to JSON")
		providerConfigRaw = &runtime.RawExtension{
			Raw: providerConfigJSON,
		}
		log.Info("Creating new backupBucket object", "region", region, "providerConfig", string(providerConfigJSON))
	} else {
		providerConfigRaw = &runtime.RawExtension{}
		log.Info("Creating new backupBucket object with empty providerConfig", "region", region)
	}

	return &extensionsv1alpha1.BackupBucket{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "extensions.gardener.cloud/v1alpha1",
			Kind:       "BackupBucket",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: extensionsv1alpha1.BackupBucketSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type:           aws.Type,
				ProviderConfig: providerConfigRaw,
			},
			Region: region,
			SecretRef: corev1.SecretReference{
				Name:      backupBucketSecretName,
				Namespace: name,
			},
		},
	}
}

func randomString() string {
	rs, err := gardenerutils.GenerateRandomStringFromCharset(5, "0123456789abcdefghijklmnopqrstuvwxyz")
	Expect(err).NotTo(HaveOccurred(), "Failed to generate random string")
	log.Info("Generated random string", "randomString", rs)
	return rs
}

// functions for verification
func verifyBackupBucketAndStatus(ctx context.Context, c client.Client, s3Client *s3.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	By("getting backupbucket and verifying its status")
	verifyBackupBucketStatus(ctx, c, backupBucket)

	By("verifying that the AWS S3 bucket exists and matches backupbucket")
	verifyBackupBucket(ctx, s3Client, backupBucket)
}

func verifyBackupBucketStatus(ctx context.Context, c client.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	log.Info("Verifying backupBucket", "backupBucket", backupBucket)
	By("fetching backupBucket from the cluster")
	backupBucket = fetchBackupBucket(ctx, c, backupBucket.Name)

	By("verifying LastOperation state")
	Expect(backupBucket.Status.LastOperation).NotTo(BeNil(), "LastOperation should not be nil")
	Expect(backupBucket.Status.LastOperation.State).To(Equal(gardencorev1beta1.LastOperationStateSucceeded), "LastOperation state should be Succeeded")
	Expect(backupBucket.Status.LastOperation.Type).To(Equal(gardencorev1beta1.LastOperationTypeCreate), "LastOperation type should be Create")

	By("verifying GeneratedSecretRef")
	if backupBucket.Status.GeneratedSecretRef != nil {
		Expect(backupBucket.Status.GeneratedSecretRef.Name).NotTo(BeEmpty(), "GeneratedSecretRef name should not be empty")
		Expect(backupBucket.Status.GeneratedSecretRef.Namespace).NotTo(BeEmpty(), "GeneratedSecretRef namespace should not be empty")
	}
}

func verifyBackupBucket(ctx context.Context, s3Client *s3.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	bucketName := backupBucket.Name

	By("verifying AWS S3 bucket")
	headBucketOutput, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: awssdk.String(bucketName),
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to verify S3 bucket existence")

	By("verifying AWS S3 bucket region")
	Expect(headBucketOutput.BucketRegion).NotTo(BeNil(), "BucketRegion should not be nil")
	Expect(*headBucketOutput.BucketRegion).To(Equal(backupBucket.Spec.Region), "Bucket region does not match expected region")
}

func verifyBackupBucketDeleted(ctx context.Context, s3Client *s3.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	bucketName := backupBucket.Name

	By("verifying AWS S3 bucket deletion")
	_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: awssdk.String(bucketName),
	})
	Expect(err).To(HaveOccurred(), "Expected S3 bucket to be deleted, but it still exists")
}

func verifyImmutabilityPolicy(ctx context.Context, s3Client *s3.Client, backupBucket *extensionsv1alpha1.BackupBucket, immutabilityConfig *awsv1alpha1.ImmutableConfig) {
	By("getting the ObjectLockConfiguration of the AWS S3 bucket")
	getObjectLockConfigurationOutput, err := s3Client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: awssdk.String(backupBucket.Name),
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to get object lock configuration for bucket")

	By("verifying the object lock is enabled")
	Expect(getObjectLockConfigurationOutput.ObjectLockConfiguration.ObjectLockEnabled).To(Equal(s3types.ObjectLockEnabledEnabled), "Object lock should be enabled on the bucket")

	By("verifying the retention period matches the expected value")
	Expect(getObjectLockConfigurationOutput.ObjectLockConfiguration.Rule.DefaultRetention).NotTo(BeNil(), "Default retention should not be nil")
	Expect(*getObjectLockConfigurationOutput.ObjectLockConfiguration.Rule.DefaultRetention.Days).To(Equal(int32(immutabilityConfig.RetentionPeriod.Duration/(24*time.Hour))), "Retention period days do not match expected value")

	By("verifying the retention mode matches the expected value")
	Expect(getObjectLockConfigurationOutput.ObjectLockConfiguration.Rule.DefaultRetention.Mode).To(Equal(awsclient.GetBucketRetentiontMode(awsapi.ModeType(immutabilityConfig.Mode))), "Retention mode does not match expected value")
}

func verifyBucketImmutability(ctx context.Context, s3Client *s3.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	defer func() {
		By("retrieving the object version IDs for deletion")
		listObjectVersionsOutput, err := s3Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: awssdk.String(backupBucket.Name),
		})
		Expect(err).NotTo(HaveOccurred(), "Failed to list object versions")

		By("deleting all object versions in the bucket using s3:BypassGovernanceRetention")
		for _, version := range listObjectVersionsOutput.Versions {
			err := deleteObject(ctx, s3Client, backupBucket.Name, *version.Key, *version.VersionId, true)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete object")
		}
	}()

	By("writing an object to the bucket to verify immutability")
	putObjectOutput, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: awssdk.String(backupBucket.Name),
		Key:    awssdk.String(objectName),
		Body:   strings.NewReader("test content"),
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to write object to the bucket")
	log.Info("Object written to bucket", "bucket", backupBucket.Name, "object", objectName, "versionId", awssdk.ToString(putObjectOutput.VersionId))

	By("attempting to mutate the object")
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: awssdk.String(backupBucket.Name),
		Key:    awssdk.String(objectName),
		Body:   strings.NewReader("new content"),
	})
	Expect(err).NotTo(HaveOccurred(), "should write to a new version within the object")

	By("verifying that the 2nd write yields a new version")
	listObjectVersionsOutput, err := s3Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: awssdk.String(backupBucket.Name),
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to list object versions")
	Expect(listObjectVersionsOutput.Versions).To(HaveLen(2), "Expected 2 versions of the object, but found %d", len(listObjectVersionsOutput.Versions))
	log.Info("Object versions in bucket", "bucket", backupBucket.Name, "object", objectName, "versions", listObjectVersionsOutput.Versions)

	By("attempting to delete the objects")
	for _, version := range listObjectVersionsOutput.Versions {
		err := deleteObject(ctx, s3Client, backupBucket.Name, *version.Key, *version.VersionId, false)
		Expect(err).To(HaveOccurred(), "Expected deletion to fail due to immutability policy")
		log.Info("Expected error when deleting object", "bucket", backupBucket.Name, "object", objectName, "key", *version.Key, "versionId", *version.VersionId, "error", err)
	}
}

func deleteObject(ctx context.Context, s3Client *s3.Client, bucketName, objectKey, versionId string, bypassGovernanceRetention bool) error {
	_, err := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:                    awssdk.String(bucketName),
		Key:                       awssdk.String(objectKey),
		VersionId:                 ptr.To(versionId),
		BypassGovernanceRetention: awssdk.Bool(bypassGovernanceRetention),
	})
	return err
}

func verifyBucketRetentionPeriod(ctx context.Context, s3Client *s3.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	defer func() {
		By("retrieving the object version IDs for deletion")
		listObjectVersionsOutput, err := s3Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: awssdk.String(backupBucket.Name),
		})
		Expect(err).NotTo(HaveOccurred(), "Failed to list object versions")

		By("deleting all object versions in the bucket using s3:BypassGovernanceRetention")
		for _, version := range listObjectVersionsOutput.Versions {
			err := deleteObject(ctx, s3Client, backupBucket.Name, *version.Key, *version.VersionId, true)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete object")
		}
	}()

	By("writing an object to the bucket to verify immutability")
	putObjectOutput, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: awssdk.String(backupBucket.Name),
		Key:    awssdk.String(objectName),
		Body:   strings.NewReader("test content"),
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to write object to the bucket")
	log.Info("Object written to bucket", "bucket", backupBucket.Name, "object", objectName, "versionId", awssdk.ToString(putObjectOutput.VersionId))

	By("retrieving the object version IDs for deletion")
	listObjectVersionsOutput, err := s3Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: awssdk.String(backupBucket.Name),
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to list object versions")

	By("getting the ObjectRetention of the object")
	getObjectRetentionOutput, err := s3Client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
		Bucket:    awssdk.String(backupBucket.Name),
		Key:       awssdk.String(objectName),
		VersionId: listObjectVersionsOutput.Versions[0].VersionId,
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to get object retention for bucket")

	By("verifying the object retention is set to 48 hours")
	awsCurrentTime := time.Now().UTC()
	expectedRetentionDate := awsCurrentTime.Add(2 * 24 * time.Hour)
	tolerance := time.Minute
	log.Info("AWS Current Time", "awsCurrentTime", awsCurrentTime)
	log.Info("Expected Retention Date", "expectedRetentionDate", expectedRetentionDate)
	log.Info("Actual Retention Date", "actualRetentionDate", getObjectRetentionOutput.Retention.RetainUntilDate)
	Expect(*getObjectRetentionOutput.Retention.RetainUntilDate).To(BeTemporally("~", expectedRetentionDate, tolerance), "Retention period should be 48 hours from now")

	By("attempting to shorten the retention period of the object")
	_, err = s3Client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
		Bucket: awssdk.String(backupBucket.Name),
		Key:    awssdk.String(objectName),
		Retention: &s3types.ObjectLockRetention{
			Mode:            s3types.ObjectLockRetentionModeGovernance,
			RetainUntilDate: awssdk.Time(time.Now().Add(24 * time.Hour)), // Attempt to shorten to 24 hours
		},
		VersionId: putObjectOutput.VersionId,
	})
	Expect(err).To(HaveOccurred(), "Expected error when trying to shorten retention period")
	log.Info("Expected error when shortening retention period", "error", err)
}
