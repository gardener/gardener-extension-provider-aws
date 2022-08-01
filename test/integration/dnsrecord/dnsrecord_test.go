// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnsrecord_test

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	awsinstall "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	dnsrecordctrl "github.com/gardener/gardener-extension-provider-aws/pkg/controller/dnsrecord"
	"github.com/go-logr/logr"

	"github.com/aws/aws-sdk-go/service/route53"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/logger"
	gardenerutils "github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	accessKeyID     = flag.String("access-key-id", "", "AWS access key id")
	secretAccessKey = flag.String("secret-access-key", "", "AWS secret access key")
)

func validateFlags() {
	if len(*accessKeyID) == 0 {
		panic("need an AWS access key id")
	}
	if len(*secretAccessKey) == 0 {
		panic("need an AWS secret access key")
	}
}

var (
	ctx = context.Background()

	log       logr.Logger
	awsClient *awsclient.Client
	testEnv   *envtest.Environment
	mgrCancel context.CancelFunc
	c         client.Client

	testName string
	zoneName string
	zoneID   string

	namespace *corev1.Namespace
	secret    *corev1.Secret
	cluster   *extensionsv1alpha1.Cluster
)

var _ = BeforeSuite(func() {
	repoRoot := filepath.Join("..", "..", "..")

	// enable manager logs
	logf.SetLogger(logger.MustNewZapLogger(logger.DebugLevel, logger.FormatJSON, zap.WriteTo(GinkgoWriter)))

	log = logf.Log.WithName("dnsrecord-test")

	DeferCleanup(func() {
		defer func() {
			By("stopping manager")
			mgrCancel()
		}()

		By("running cleanup actions")
		framework.RunCleanupActions()

		By("deleting AWS DNS hosted zone")
		deleteDNSHostedZone(ctx, awsClient, zoneID)

		By("tearing down shoot environment")
		teardownShootEnvironment(ctx, c, namespace, secret, cluster)

		By("stopping test environment")
		Expect(testEnv.Stop()).To(Succeed())
	})

	By("generating randomized test resource identifiers")
	testName = fmt.Sprintf("aws-dnsrecord-it--%s", randomString())
	zoneName = testName + ".gardener.cloud"
	namespace = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testName,
		},
	}
	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dnsrecord",
			Namespace: testName,
		},
		Data: map[string][]byte{
			aws.AccessKeyID:     []byte(*accessKeyID),
			aws.SecretAccessKey: []byte(*secretAccessKey),
		},
	}
	cluster = &extensionsv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: testName,
		},
		Spec: extensionsv1alpha1.ClusterSpec{
			CloudProfile: runtime.RawExtension{Raw: []byte("{}")},
			Seed:         runtime.RawExtension{Raw: []byte("{}")},
			Shoot:        runtime.RawExtension{Raw: []byte("{}")},
		},
	}

	By("starting test environment")
	testEnv = &envtest.Environment{
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{
				filepath.Join(repoRoot, "example", "20-crd-extensions.gardener.cloud_dnsrecords.yaml"),
				filepath.Join(repoRoot, "example", "20-crd-extensions.gardener.cloud_clusters.yaml"),
			},
		},
	}

	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	By("setting up manager")
	mgr, err := manager.New(cfg, manager.Options{
		MetricsBindAddress: "0",
	})
	Expect(err).ToNot(HaveOccurred())

	Expect(extensionsv1alpha1.AddToScheme(mgr.GetScheme())).To(Succeed())
	Expect(awsinstall.AddToScheme(mgr.GetScheme())).To(Succeed())

	Expect(dnsrecordctrl.AddToManagerWithOptions(mgr, dnsrecordctrl.AddOptions{
		RateLimiter: dnsrecordctrl.RateLimiterOptions{
			Limit:       rate.Inf,
			WaitTimeout: 1 * time.Second,
		},
	})).To(Succeed())

	var mgrContext context.Context
	mgrContext, mgrCancel = context.WithCancel(ctx)

	By("starting manager")
	go func() {
		defer GinkgoRecover()
		err := mgr.Start(mgrContext)
		Expect(err).NotTo(HaveOccurred())
	}()

	// test client should be uncached and independent from the tested manager
	c, err = client.New(cfg, client.Options{
		Scheme: mgr.GetScheme(),
		Mapper: mgr.GetRESTMapper(),
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(c).NotTo(BeNil())

	flag.Parse()
	validateFlags()

	awsClient, err = awsclient.NewClient(*accessKeyID, *secretAccessKey, aws.DefaultDNSRegion)
	Expect(err).NotTo(HaveOccurred())

	By("setting up shoot environment")
	setupShootEnvironment(ctx, c, namespace, secret, cluster)

	By("creating AWS DNS hosted zone")
	zoneID = createDNSHostedZone(ctx, awsClient, zoneName)
})

var runTest = func(dns *extensionsv1alpha1.DNSRecord, newValues []string, beforeCreate, beforeUpdate, beforeDelete func()) {
	if beforeCreate != nil {
		beforeCreate()
	}

	By("creating dnsrecord")
	createDNSRecord(ctx, c, dns)

	defer func() {
		if beforeDelete != nil {
			beforeDelete()
		}

		By("deleting dnsrecord")
		deleteDNSRecord(ctx, c, dns)

		By("waiting until dnsrecord is deleted")
		waitUntilDNSRecordDeleted(ctx, c, log, dns)

		By("verifying that the AWS DNS recordset does not exist")
		verifyDNSRecordSetDeleted(ctx, awsClient, dns)
	}()

	framework.AddCleanupAction(func() {
		By("deleting the AWS DNS recordset if it still exists")
		deleteDNSRecordSet(ctx, awsClient, dns)
	})

	By("waiting until dnsrecord is ready")
	waitUntilDNSRecordReady(ctx, c, log, dns)

	By("getting dnsrecord and verifying its status")
	getDNSRecordAndVerifyStatus(ctx, c, dns, zoneID)

	By("verifying that the AWS DNS recordset exists and matches dnsrecord")
	verifyDNSRecordSet(ctx, awsClient, dns)

	By("verifying that the meta AWS DNS recordset does not exist")
	verifyMetaDNSRecordSetDeleted(ctx, awsClient, dns)

	if len(newValues) > 0 {
		if beforeUpdate != nil {
			beforeUpdate()
		}

		dns.Spec.Values = newValues
		metav1.SetMetaDataAnnotation(&dns.ObjectMeta, v1beta1constants.GardenerOperation, v1beta1constants.GardenerOperationReconcile)

		By("updating dnsrecord")
		updateDNSRecord(ctx, c, dns)

		By("waiting until dnsrecord is ready")
		waitUntilDNSRecordReady(ctx, c, log, dns)

		By("getting dnsrecord and verifying its status")
		getDNSRecordAndVerifyStatus(ctx, c, dns, zoneID)

		By("verifying that the AWS DNS recordset exists and matches dnsrecord")
		verifyDNSRecordSet(ctx, awsClient, dns)
	}
}

var _ = Describe("DNSRecord tests", func() {
	Context("when a DNS recordset doesn't exist and is not changed or deleted before dnsrecord deletion", func() {
		It("should successfully create and delete a dnsrecord of type A", func() {
			dns := newDNSRecord(testName, zoneName, nil, extensionsv1alpha1.DNSRecordTypeA, []string{"1.1.1.1", "2.2.2.2"}, pointer.Int64(300))
			runTest(dns, nil, nil, nil, nil)
		})

		It("should successfully create and delete a dnsrecord of type CNAME", func() {
			dns := newDNSRecord(testName, zoneName, pointer.String(zoneID), extensionsv1alpha1.DNSRecordTypeCNAME, []string{"foo.example.com"}, pointer.Int64(600))
			runTest(dns, nil, nil, nil, nil)
		})

		It("should successfully create and delete a dnsrecord of type CNAME as an alias target", func() {
			dns := newDNSRecord(testName, zoneName, nil, extensionsv1alpha1.DNSRecordTypeCNAME, []string{"foo.elb.eu-west-1.amazonaws.com"}, nil)
			runTest(dns, nil, nil, nil, nil)
		})

		It("should successfully create and delete a dnsrecord of type TXT", func() {
			dns := newDNSRecord(testName, zoneName, pointer.String(zoneID), extensionsv1alpha1.DNSRecordTypeTXT, []string{"foo", "bar"}, nil)
			runTest(dns, nil, nil, nil, nil)
		})
	})

	Context("when a DNS recordset exists and is changed before dnsrecord update and deletion", func() {
		It("should successfully create, update, and delete a dnsrecord", func() {
			dns := newDNSRecord(testName, zoneName, pointer.String(zoneID), extensionsv1alpha1.DNSRecordTypeA, []string{"1.1.1.1", "2.2.2.2"}, pointer.Int64(300))
			runTest(
				dns,
				[]string{"3.3.3.3", "1.1.1.1"},
				func() {
					By("creating AWS DNS recordset and its meta recordset")
					Expect(awsClient.CreateOrUpdateDNSRecordSet(ctx, zoneID, dns.Spec.Name, route53.RRTypeA, []string{"8.8.8.8"}, 120)).To(Succeed())
					Expect(awsClient.CreateOrUpdateDNSRecordSet(ctx, zoneID, "comment-"+dns.Spec.Name, route53.RRTypeTxt, []string{"foo"}, 600)).To(Succeed())
				},
				func() {
					By("updating AWS DNS recordset")
					Expect(awsClient.CreateOrUpdateDNSRecordSet(ctx, zoneID, dns.Spec.Name, route53.RRTypeA, []string{"8.8.8.8"}, 120)).To(Succeed())
				},
				func() {
					By("updating AWS DNS recordset")
					Expect(awsClient.CreateOrUpdateDNSRecordSet(ctx, zoneID, dns.Spec.Name, route53.RRTypeA, []string{"8.8.8.8"}, 120)).To(Succeed())
				},
			)
		})
	})

	Context("when a DNS recordset exists and is deleted before dnsrecord deletion", func() {
		It("should successfully create and delete a dnsrecord", func() {
			dns := newDNSRecord(testName, zoneName, nil, extensionsv1alpha1.DNSRecordTypeA, []string{"1.1.1.1", "2.2.2.2"}, pointer.Int64(300))
			runTest(
				dns,
				nil,
				func() {
					By("creating AWS DNS recordset")
					Expect(awsClient.CreateOrUpdateDNSRecordSet(ctx, zoneID, dns.Spec.Name, route53.RRTypeA, []string{"8.8.8.8"}, 120)).To(Succeed())
				},
				nil,
				func() {
					By("deleting AWS DNS recordset")
					Expect(awsClient.DeleteDNSRecordSet(ctx, zoneID, dns.Spec.Name, route53.RRTypeA, nil, 0)).To(Succeed())
				},
			)
		})
	})
})

func setupShootEnvironment(ctx context.Context, c client.Client, namespace *corev1.Namespace, secret *corev1.Secret, cluster *extensionsv1alpha1.Cluster) {
	Expect(c.Create(ctx, namespace)).To(Succeed())
	Expect(c.Create(ctx, secret)).To(Succeed())
	Expect(c.Create(ctx, cluster)).To(Succeed())
}

func teardownShootEnvironment(ctx context.Context, c client.Client, namespace *corev1.Namespace, secret *corev1.Secret, cluster *extensionsv1alpha1.Cluster) {
	Expect(client.IgnoreNotFound(c.Delete(ctx, cluster))).To(Succeed())
	Expect(client.IgnoreNotFound(c.Delete(ctx, secret))).To(Succeed())
	Expect(client.IgnoreNotFound(c.Delete(ctx, namespace))).To(Succeed())
}

func createDNSRecord(ctx context.Context, c client.Client, dns *extensionsv1alpha1.DNSRecord) {
	Expect(c.Create(ctx, dns)).To(Succeed())
}

func updateDNSRecord(ctx context.Context, c client.Client, dns *extensionsv1alpha1.DNSRecord) {
	Expect(c.Update(ctx, dns)).To(Succeed())
}

func deleteDNSRecord(ctx context.Context, c client.Client, dns *extensionsv1alpha1.DNSRecord) {
	Expect(client.IgnoreNotFound(c.Delete(ctx, dns))).To(Succeed())
}

func getDNSRecordAndVerifyStatus(ctx context.Context, c client.Client, dns *extensionsv1alpha1.DNSRecord, zoneID string) {
	Expect(c.Get(ctx, client.ObjectKey{Namespace: dns.Namespace, Name: dns.Name}, dns)).To(Succeed())
	Expect(dns.Status.Zone).To(PointTo(Equal(zoneID)))
}

func waitUntilDNSRecordReady(ctx context.Context, c client.Client, log logr.Logger, dns *extensionsv1alpha1.DNSRecord) {
	Expect(extensions.WaitUntilExtensionObjectReady(
		ctx,
		c,
		log,
		dns,
		extensionsv1alpha1.DNSRecordResource,
		10*time.Second,
		30*time.Second,
		5*time.Minute,
		nil,
	)).To(Succeed())
}

func waitUntilDNSRecordDeleted(ctx context.Context, c client.Client, log logr.Logger, dns *extensionsv1alpha1.DNSRecord) {
	Expect(extensions.WaitUntilExtensionObjectDeleted(
		ctx,
		c,
		log,
		dns.DeepCopy(),
		extensionsv1alpha1.DNSRecordResource,
		10*time.Second,
		5*time.Minute,
	)).To(Succeed())
}

func newDNSRecord(namespace string, zoneName string, zone *string, recordType extensionsv1alpha1.DNSRecordType, values []string, ttl *int64) *extensionsv1alpha1.DNSRecord {
	name := "dnsrecord-" + randomString()
	return &extensionsv1alpha1.DNSRecord{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: extensionsv1alpha1.DNSRecordSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type: aws.DNSType,
			},
			SecretRef: corev1.SecretReference{
				Name:      "dnsrecord",
				Namespace: namespace,
			},
			Zone:       zone,
			Name:       name + "." + zoneName,
			RecordType: recordType,
			Values:     values,
			TTL:        ttl,
		},
	}
}

func createDNSHostedZone(ctx context.Context, awsClient *awsclient.Client, zoneName string) string {
	zoneID, err := awsClient.CreateDNSHostedZone(ctx, zoneName, "Temporary zone for integration test")
	Expect(err).NotTo(HaveOccurred())
	return normalizeZoneID(zoneID)
}

func deleteDNSHostedZone(ctx context.Context, awsClient *awsclient.Client, zoneID string) {
	Expect(awsClient.DeleteDNSHostedZone(ctx, zoneID)).To(Succeed())
}

func verifyDNSRecordSet(ctx context.Context, awsClient *awsclient.Client, dns *extensionsv1alpha1.DNSRecord) {
	recordType := getRecordType(dns)
	rrs, err := awsClient.GetDNSRecordSet(ctx, *dns.Status.Zone, dns.Spec.Name, recordType)
	Expect(err).NotTo(HaveOccurred())
	Expect(rrs).NotTo(BeNil())
	Expect(rrs.Name).To(PointTo(Equal(ensureTrailingDot(dns.Spec.Name))))
	Expect(rrs.Type).To(PointTo(Equal(recordType)))
	if !expectAliasTarget(dns) {
		Expect(rrs.ResourceRecords).To(ConsistOf(resourceRecords(recordType, dns.Spec.Values)))
		Expect(rrs.AliasTarget).To(BeNil())
		Expect(rrs.TTL).To(PointTo(Equal(pointer.Int64Deref(dns.Spec.TTL, 120))))
	} else {
		Expect(rrs.ResourceRecords).To(BeEmpty())
		Expect(rrs.AliasTarget).To(Equal(&route53.AliasTarget{
			DNSName:              pointer.String(ensureTrailingDot(dns.Spec.Values[0])),
			HostedZoneId:         pointer.String("Z2IFOLAFXWLO4F"), // zone ID for elb.eu-west-1.amazonaws.com
			EvaluateTargetHealth: pointer.Bool(true),
		}))
		Expect(rrs.TTL).To(BeNil())
	}
}

func verifyDNSRecordSetDeleted(ctx context.Context, awsClient *awsclient.Client, dns *extensionsv1alpha1.DNSRecord) {
	rrs, err := awsClient.GetDNSRecordSet(ctx, *dns.Status.Zone, dns.Spec.Name, getRecordType(dns))
	Expect(err).NotTo(HaveOccurred())
	Expect(rrs).To(BeNil())
}

func verifyMetaDNSRecordSetDeleted(ctx context.Context, awsClient *awsclient.Client, dns *extensionsv1alpha1.DNSRecord) {
	rrs, err := awsClient.GetDNSRecordSet(ctx, *dns.Status.Zone, "comment-"+dns.Spec.Name, route53.RRTypeTxt)
	Expect(err).NotTo(HaveOccurred())
	Expect(rrs).To(BeNil())
}

func deleteDNSRecordSet(ctx context.Context, awsClient *awsclient.Client, dns *extensionsv1alpha1.DNSRecord) {
	err := awsClient.DeleteDNSRecordSet(ctx, *dns.Status.Zone, dns.Spec.Name, getRecordType(dns), nil, 0)
	Expect(err).NotTo(HaveOccurred())
}

func getRecordType(dns *extensionsv1alpha1.DNSRecord) string {
	if expectAliasTarget(dns) {
		return route53.RRTypeA
	}
	return string(dns.Spec.RecordType)
}

func expectAliasTarget(dns *extensionsv1alpha1.DNSRecord) bool {
	return dns.Spec.RecordType == extensionsv1alpha1.DNSRecordTypeCNAME &&
		strings.HasSuffix(dns.Spec.Values[0], ".elb.eu-west-1.amazonaws.com")
}

func resourceRecords(recordType string, values []string) []*route53.ResourceRecord {
	var resourceRecords []*route53.ResourceRecord
	for _, value := range values {
		if recordType == route53.RRTypeTxt {
			value = ensureQuoted(value)
		}
		resourceRecords = append(resourceRecords, &route53.ResourceRecord{
			Value: pointer.String(value),
		})
	}
	return resourceRecords
}

func ensureTrailingDot(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func ensureQuoted(s string) string {
	if s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}

func normalizeZoneID(zoneID string) string {
	parts := strings.Split(zoneID, "/")
	return parts[len(parts)-1]
}

func randomString() string {
	rs, err := gardenerutils.GenerateRandomStringFromCharset(5, "0123456789abcdefghijklmnopqrstuvwxyz")
	Expect(err).NotTo(HaveOccurred())
	return rs
}
