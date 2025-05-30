// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket_test

import (
	"context"
	"os"
	"slices"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	gardenerutils "github.com/gardener/gardener/pkg/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

func ensureGardenNamespace(ctx context.Context, c client.Client) (*corev1.Namespace, bool) {
	gardenNamespaceAlreadyExists := false
	gardenNamespace := &corev1.Namespace{}
	err := c.Get(ctx, client.ObjectKey{Name: gardenNamespaceName}, gardenNamespace)
	if err != nil {
		if client.IgnoreNotFound(err) == nil {
			log.Info("Garden namespace not found, creating it", "namespace", gardenNamespaceName)
			gardenNamespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: gardenNamespaceName,
				},
			}
			Expect(c.Create(ctx, gardenNamespace)).To(Succeed(), "Failed to create garden namespace")
		} else {
			log.Error(err, "Failed to check for garden namespace")
			Expect(err).NotTo(HaveOccurred(), "Unexpected error while checking for garden namespace")
		}
	} else {
		gardenNamespaceAlreadyExists = true
		log.Info("Garden namespace already exists", "namespace", gardenNamespaceName)
	}
	return gardenNamespace, gardenNamespaceAlreadyExists
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

func deleteBackupBucket(ctx context.Context, c client.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	log.Info("Deleting backupBucket", "backupBucket", backupBucket)
	Expect(client.IgnoreNotFound(c.Delete(ctx, backupBucket))).To(Succeed())
}

func waitUntilBackupBucketReady(ctx context.Context, c client.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	err := extensions.WaitUntilExtensionObjectReady(
		ctx,
		c,
		log,
		backupBucket,
		extensionsv1alpha1.BackupBucketResource,
		10*time.Second,
		30*time.Second,
		5*time.Minute,
		nil,
	)
	if err != nil {
		log.Info("BackupBucket is not ready yet; this is expected during initial reconciliation", "error", err)
	}
	Expect(err).To(Succeed(), "BackupBucket did not become ready: %s", backupBucket.Name)
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

func getBackupBucketAndVerifyStatus(ctx context.Context, c client.Client, backupBucket *extensionsv1alpha1.BackupBucket) {
	log.Info("Verifying backupBucket", "backupBucket", backupBucket)
	Expect(c.Get(ctx, client.ObjectKey{Name: backupBucket.Name}, backupBucket)).To(Succeed())

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

func newBackupBucket(name, region string) *extensionsv1alpha1.BackupBucket {
	return &extensionsv1alpha1.BackupBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: extensionsv1alpha1.BackupBucketSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type: aws.Type,
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
