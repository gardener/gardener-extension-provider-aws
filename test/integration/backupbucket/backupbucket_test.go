// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket_test

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/logger"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	awsinstall "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	backupbucketctrl "github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupbucket"
)

type TestContext struct {
	ctx           context.Context
	client        client.Client
	s3Client      *s3.Client
	testNamespace *corev1.Namespace
	testName      string
	secret        *corev1.Secret
}

var (
	log       logr.Logger
	testEnv   *envtest.Environment
	mgrCancel context.CancelFunc
	tc        *TestContext

	// Flag variables
	accessKeyID        = flag.String("access-key-id", "", "AWS access key ID")
	secretAccessKey    = flag.String("secret-access-key", "", "AWS secret access key")
	region             = flag.String("region", "", "AWS region")
	logLevel           = flag.String("log-level", "", "Log level (debug, info, error)")
	useExistingCluster = flag.Bool("use-existing-cluster", true, "Set to true to use an existing cluster for the test")
)

const backupBucketSecretName = "backupbucket"

var runTest = func(tc *TestContext, backupBucket *v1alpha1.BackupBucket) {
	log.Info("Running BackupBucket test", "backupBucketName", backupBucket.Name)

	By("creating backupbucket")
	createBackupBucket(tc.ctx, tc.client, backupBucket)

	defer func() {
		By("deleting backupbucket")
		deleteBackupBucket(tc.ctx, tc.client, backupBucket)

		By("waiting until backupbucket is deleted")
		waitUntilBackupBucketDeleted(tc.ctx, tc.client, backupBucket)

		By("verifying that the AWS S3 bucket does not exist")
		verifyBackupBucketDeleted(tc.ctx, tc.s3Client, backupBucket)
	}()

	By("waiting until backupbucket is ready")
	waitUntilBackupBucketReady(tc.ctx, tc.client, backupBucket)

	By("getting backupbucket and verifying its status")
	getBackupBucketAndVerifyStatus(tc.ctx, tc.client, backupBucket)

	By("verifying that the AWS S3 bucket exists and matches backupbucket")
	verifyBackupBucket(tc.ctx, tc.s3Client, backupBucket)

	log.Info("BackupBucket test completed successfully", "backupBucketName", backupBucket.Name)
}

var _ = BeforeSuite(func() {
	ctx := context.Background()

	repoRoot := filepath.Join("..", "..", "..")

	flag.Parse()
	secretsFromEnv()
	validateFlags()

	logf.SetLogger(logger.MustNewZapLogger(*logLevel, logger.FormatJSON, zap.WriteTo(GinkgoWriter)))
	log := logf.Log.WithName("backupbucket-test")
	log.Info("Starting BackupBucket test", "logLevel", *logLevel)

	DeferCleanup(func() {
		By("stopping manager")
		mgrCancel()

		By("deleting aws provider secret")
		deleteBackupBucketSecret(tc.ctx, tc.client, tc.secret)

		By("deleting test namespace")
		deleteNamespace(tc.ctx, tc.client, tc.testNamespace)

		By("stopping test environment")
		Expect(testEnv.Stop()).To(Succeed())
	})

	By("generating randomized backupbucket test id")
	testName := fmt.Sprintf("aws-backupbucket-it--%s", randomString())

	By("starting test environment")
	testEnv = &envtest.Environment{
		UseExistingCluster: ptr.To(*useExistingCluster),
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{
				filepath.Join(repoRoot, "example", "20-crd-extensions.gardener.cloud_backupbuckets.yaml"),
			},
		},
		ControlPlaneStopTimeout: 2 * time.Minute,
	}

	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred(), "Failed to start the test environment")
	Expect(cfg).ToNot(BeNil(), "Test environment configuration is nil")
	log.Info("Test environment started successfully", "useExistingCluster", *useExistingCluster)

	By("setting up manager")
	mgr, err := manager.New(cfg, manager.Options{
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	Expect(err).ToNot(HaveOccurred(), "Failed to create manager for the test environment")

	Expect(v1alpha1.AddToScheme(mgr.GetScheme())).To(Succeed(), "Failed to add v1alpha1 scheme to manager")
	Expect(awsinstall.AddToScheme(mgr.GetScheme())).To(Succeed(), "Failed to add AWS scheme to manager")

	Expect(backupbucketctrl.AddToManagerWithOptions(ctx, mgr, backupbucketctrl.AddOptions{})).To(Succeed(), "Failed to add BackupBucket controller to manager")

	var mgrContext context.Context
	mgrContext, mgrCancel = context.WithCancel(ctx)

	By("starting manager")
	go func() {
		defer GinkgoRecover()
		err := mgr.Start(mgrContext)
		Expect(err).NotTo(HaveOccurred(), "Failed to start the manager")
	}()

	By("getting clients")
	c, err := client.New(cfg, client.Options{
		Scheme: mgr.GetScheme(),
		Mapper: mgr.GetRESTMapper(),
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(c).NotTo(BeNil())

	s3Client := getS3Client(*accessKeyID, *secretAccessKey, *region)
	Expect(s3Client).ToNot(BeNil())

	By("creating test namespace")
	testNamespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testName,
		},
	}
	createNamespace(ctx, c, testNamespace)

	By("creating aws provider secret")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      backupBucketSecretName,
			Namespace: testName,
		},
		Data: map[string][]byte{
			aws.AccessKeyID:     []byte(*accessKeyID),
			aws.SecretAccessKey: []byte(*secretAccessKey),
		},
	}
	createBackupBucketSecret(ctx, c, secret)

	// Initialize the TestContext
	tc = &TestContext{
		ctx:           ctx,
		client:        c,
		s3Client:      s3Client,
		testNamespace: testNamespace,
		testName:      testName,
		secret:        secret,
	}
})

var _ = Describe("BackupBucket tests", func() {
	Context("when a BackupBucket is created with basic configuration", func() {
		It("should successfully create and delete a backupbucket", func() {
			backupBucket := newBackupBucket(tc.testName, *region)
			runTest(tc, backupBucket)
		})
	})
})
