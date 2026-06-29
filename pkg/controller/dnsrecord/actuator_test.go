// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package dnsrecord_test

import (
	"context"
	"errors"

	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	testutils "github.com/gardener/gardener/pkg/utils/test"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/dnsrecord"
)

const (
	name        = "aws-external"
	namespace   = "shoot--foobar--aws"
	shootDomain = "shoot.example.com"
	domainName  = "api.aws.foobar." + shootDomain
	zone        = "zone"
	address     = "1.2.3.4"

	accessKeyID     = "accessKeyID"
	secretAccessKey = "secretAccessKey"
)

var _ = Describe("Actuator", func() {
	var (
		ctrl             *gomock.Controller
		c                client.Client
		mgr              *testutils.FakeManager
		awsClientFactory *mockawsclient.MockFactory
		awsClient        *mockawsclient.MockInterface
		ctx              context.Context
		logger           logr.Logger
		a                dnsrecord.Actuator
		dns              *extensionsv1alpha1.DNSRecord
		secret           *corev1.Secret
		zones            map[string]string
		authConfig       awsclient.AuthConfig
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())

		scheme := runtime.NewScheme()
		Expect(extensionsv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(corev1.AddToScheme(scheme)).To(Succeed())

		c = fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&extensionsv1alpha1.DNSRecord{}).Build()
		mgr = &testutils.FakeManager{Client: c}

		awsClientFactory = mockawsclient.NewMockFactory(ctrl)
		awsClient = mockawsclient.NewMockInterface(ctrl)

		ctx = context.TODO()
		logger = log.Log.WithName("test")

		a = NewActuator(mgr, awsClientFactory)

		dns = &extensionsv1alpha1.DNSRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: extensionsv1alpha1.DNSRecordSpec{
				DefaultSpec: extensionsv1alpha1.DefaultSpec{
					Type: aws.DNSType,
				},
				SecretRef: corev1.SecretReference{
					Name:      name,
					Namespace: namespace,
				},
				Name:       domainName,
				RecordType: extensionsv1alpha1.DNSRecordTypeA,
				Values:     []string{address},
			},
		}

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				aws.AccessKeyID:     []byte(accessKeyID),
				aws.SecretAccessKey: []byte(secretAccessKey),
			},
		}
		authConfig = awsclient.AuthConfig{
			AccessKey: &awsclient.AccessKey{
				ID:     accessKeyID,
				Secret: secretAccessKey,
			},
			Region: aws.DefaultDNSRegion,
		}

		zones = map[string]string{
			shootDomain:   zone,
			"example.com": "zone2",
			"other.com":   "zone3",
		}
	})

	Describe("#Reconcile", func() {
		BeforeEach(func() {
			Expect(c.Create(ctx, secret)).To(Succeed())
			awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)
		})

		It("should reconcile the DNSRecord", func() {
			awsClient.EXPECT().GetDNSHostedZones(ctx).Return(zones, nil)
			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).Return(nil)

			Expect(c.Create(ctx, dns)).To(Succeed())
			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).NotTo(HaveOccurred())

			updated := &extensionsv1alpha1.DNSRecord{}
			Expect(c.Get(ctx, client.ObjectKeyFromObject(dns), updated)).To(Succeed())
			Expect(updated.Status.Zone).To(Equal(ptr.To(zone)))
		})

		It("should fail if creating the DNS record set failed", func() {
			dns.Spec.Zone = ptr.To(zone)

			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(errors.New("test"))

			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).To(HaveOccurred())
			_, ok := err.(gardencorev1beta1helper.Coder)
			Expect(ok).To(BeFalse())
		})

		It("should fail with ERR_CONFIGURATION_PROBLEM if there is no such hosted zone", func() {
			dns.Spec.Zone = ptr.To(zone)

			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(&route53types.NoSuchHostedZone{})

			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).To(HaveOccurred())
			coder, ok := err.(gardencorev1beta1helper.Coder)
			Expect(ok).To(BeTrue())
			Expect(coder.Codes()).To(Equal([]gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem}))
		})

		It("should fail with ERR_CONFIGURATION_PROBLEM if the domain name is not permitted in the zone", func() {
			dns.Spec.Zone = ptr.To(zone)

			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(&route53types.NoSuchHostedZone{})

			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).To(HaveOccurred())
			coder, ok := err.(gardencorev1beta1helper.Coder)
			Expect(ok).To(BeTrue())
			Expect(coder.Codes()).To(Equal([]gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem}))
		})

		It("should fail with ERR_CONFIGURATION_PROBLEM when there is no such hosted zone", func() {
			dns.Spec.Zone = ptr.To(zone)

			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(&route53types.InvalidChangeBatch{Messages: []string{"RRSet with DNS name api.aws.foobar.shoot.example.com. is not permitted in zone foo.com."}})

			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).To(HaveOccurred())
			coder, ok := err.(gardencorev1beta1helper.Coder)
			Expect(ok).To(BeTrue())
			Expect(coder.Codes()).To(Equal([]gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem}))
		})
	})

	Describe("#Delete", func() {
		BeforeEach(func() {
			Expect(c.Create(ctx, secret)).To(Succeed())
			awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)

		})

		It("should fail with ERR_CONFIGURATION_PROBLEM if the domain name is not permitted in the zone", func() {
			dns.Spec.Zone = ptr.To(zone)

			awsClient.EXPECT().DeleteDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(&route53types.InvalidChangeBatch{Messages: []string{"RRSet with DNS name api.aws.foobar.shoot.example.com. is not permitted in zone foo.com."}})

			err := a.Delete(ctx, logger, dns, nil)
			Expect(err).To(HaveOccurred())

			coder, ok := err.(gardencorev1beta1helper.Coder)
			Expect(ok).To(BeTrue())
			Expect(coder.Codes()).To(Equal([]gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem}))
		})

		It("should not fail when there is no such hosted zone", func() {
			dns.Spec.Zone = ptr.To(zone)

			awsClient.EXPECT().DeleteDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(&route53types.NoSuchHostedZone{})

			err := a.Delete(ctx, logger, dns, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should delete the DNSRecord", func() {
			dns.Status.Zone = ptr.To(zone)

			awsClient.EXPECT().DeleteDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).Return(nil)

			err := a.Delete(ctx, logger, dns, nil)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
