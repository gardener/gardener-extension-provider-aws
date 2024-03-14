// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package dnsrecord_test

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/pkg/mock/controller-runtime/manager"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
		c                *mockclient.MockClient
		mgr              *mockmanager.MockManager
		sw               *mockclient.MockStatusWriter
		awsClientFactory *mockawsclient.MockFactory
		awsClient        *mockawsclient.MockInterface
		ctx              context.Context
		logger           logr.Logger
		a                dnsrecord.Actuator
		dns              *extensionsv1alpha1.DNSRecord
		secret           *corev1.Secret
		zones            map[string]string
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())

		c = mockclient.NewMockClient(ctrl)
		mgr = mockmanager.NewMockManager(ctrl)

		mgr.EXPECT().GetClient().Return(c)

		sw = mockclient.NewMockStatusWriter(ctrl)
		awsClientFactory = mockawsclient.NewMockFactory(ctrl)
		awsClient = mockawsclient.NewMockInterface(ctrl)

		c.EXPECT().Status().Return(sw).AnyTimes()

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

		zones = map[string]string{
			shootDomain:   zone,
			"example.com": "zone2",
			"other.com":   "zone3",
		}
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#Reconcile", func() {
		BeforeEach(func() {
			c.EXPECT().Get(ctx, kutil.Key(namespace, name), gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
				func(_ context.Context, _ client.ObjectKey, obj *corev1.Secret, _ ...client.GetOption) error {
					*obj = *secret
					return nil
				},
			)
			awsClientFactory.EXPECT().NewClient(accessKeyID, secretAccessKey, aws.DefaultDNSRegion).Return(awsClient, nil)
		})

		It("should reconcile the DNSRecord", func() {
			awsClient.EXPECT().GetDNSHostedZones(ctx).Return(zones, nil)
			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).Return(nil)
			sw.EXPECT().Patch(ctx, gomock.AssignableToTypeOf(&extensionsv1alpha1.DNSRecord{}), gomock.Any()).DoAndReturn(
				func(_ context.Context, obj *extensionsv1alpha1.DNSRecord, _ client.Patch, opts ...client.PatchOption) error {
					Expect(obj.Status).To(Equal(extensionsv1alpha1.DNSRecordStatus{
						Zone: pointer.String(zone),
					}))
					return nil
				},
			)

			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should fail if creating the DNS record set failed", func() {
			dns.Spec.Zone = pointer.String(zone)

			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(errors.New("test"))

			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).To(HaveOccurred())
			_, ok := err.(gardencorev1beta1helper.Coder)
			Expect(ok).To(BeFalse())
		})

		It("should fail with ERR_CONFIGURATION_PROBLEM if there is no such hosted zone", func() {
			dns.Spec.Zone = pointer.String(zone)

			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(awserr.New(route53.ErrCodeNoSuchHostedZone, "", nil))

			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).To(HaveOccurred())
			coder, ok := err.(gardencorev1beta1helper.Coder)
			Expect(ok).To(BeTrue())
			Expect(coder.Codes()).To(Equal([]gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem}))
		})

		It("should fail with ERR_CONFIGURATION_PROBLEM if the domain name is not permitted in the zone", func() {
			dns.Spec.Zone = pointer.String(zone)

			awsClient.EXPECT().CreateOrUpdateDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).
				Return(awserr.New(route53.ErrCodeInvalidChangeBatch, "RRSet with DNS name api.aws.foobar.shoot.example.com. is not permitted in zone foo.com.", nil))

			err := a.Reconcile(ctx, logger, dns, nil)
			Expect(err).To(HaveOccurred())
			coder, ok := err.(gardencorev1beta1helper.Coder)
			Expect(ok).To(BeTrue())
			Expect(coder.Codes()).To(Equal([]gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem}))
		})
	})

	Describe("#Delete", func() {
		It("should delete the DNSRecord", func() {
			dns.Status.Zone = pointer.String(zone)

			c.EXPECT().Get(ctx, kutil.Key(namespace, name), gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
				func(_ context.Context, _ client.ObjectKey, obj *corev1.Secret, _ ...client.GetOption) error {
					*obj = *secret
					return nil
				},
			)
			awsClientFactory.EXPECT().NewClient(accessKeyID, secretAccessKey, aws.DefaultDNSRegion).Return(awsClient, nil)
			awsClient.EXPECT().DeleteDNSRecordSet(ctx, zone, domainName, string(extensionsv1alpha1.DNSRecordTypeA), []string{address}, int64(120), awsclient.IPStackIPv4).Return(nil)

			err := a.Delete(ctx, logger, dns, nil)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
