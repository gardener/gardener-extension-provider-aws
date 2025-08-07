// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupentry_test

import (
	"context"

	"github.com/gardener/gardener/extensions/pkg/controller/backupentry/genericactuator"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/logger"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/backupentry"
)

const (
	entryName  = "test-entry"
	region     = "region-1"
	secretName = "secret-1"
	namespace  = "shoot-foo--bar"
)

var _ = Describe("Actuator", func() {
	var (
		fakeClient  client.Client
		fakeManager manager.Manager
		secret      *corev1.Secret
		backupEntry *extensionsv1alpha1.BackupEntry
		actuator    genericactuator.BackupEntryDelegate
		ctx         context.Context
		log         logr.Logger
	)

	BeforeEach(func() {
		ctx = context.Background()
		log = logger.MustNewZapLogger(logger.DebugLevel, logger.FormatJSON, zap.WriteTo(GinkgoWriter))

		fakeClient = fakeclient.NewClientBuilder().Build()
		fakeManager = &test.FakeManager{Client: fakeClient}
		actuator = backupentry.NewActuator(fakeManager)

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      secretName,
			},
		}
		Expect(fakeClient.Create(ctx, secret)).To(Succeed())

		backupEntry = &extensionsv1alpha1.BackupEntry{
			ObjectMeta: metav1.ObjectMeta{
				Name: entryName,
			},
			Spec: extensionsv1alpha1.BackupEntrySpec{
				Region: region,
				SecretRef: corev1.SecretReference{
					Namespace: namespace,
					Name:      secretName,
				},
			},
		}
	})

	Describe("#GetETCDSecretData", func() {
		It("should inject region only", func() {
			data := map[string][]byte{}
			res, err := actuator.GetETCDSecretData(ctx, log, backupEntry, data)

			Expect(err).ToNot(HaveOccurred())
			Expect(res).To(HaveLen(1))
			Expect(res).To(HaveKeyWithValue("region", []byte(region)))
		})

		It("should overwrite role ARN in provided data", func() {
			data := map[string][]byte{"region": []byte("another-region")}
			_, err := actuator.GetETCDSecretData(ctx, log, backupEntry, data)

			Expect(err).ToNot(HaveOccurred())
			Expect(data["region"]).ToNot(BeEquivalentTo("another-region"))
			Expect(data["region"]).To(BeEquivalentTo(region))
		})

		It("should inject role ARN", func() {
			metav1.SetMetaDataLabel(&secret.ObjectMeta, "security.gardener.cloud/purpose", "workload-identity-token-requestor")
			secret.Data = map[string][]byte{
				"config": []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: "foo"`,
				)}
			Expect(fakeClient.Update(ctx, secret)).To(Succeed())

			data := map[string][]byte{}
			res, err := actuator.GetETCDSecretData(ctx, log, backupEntry, data)

			Expect(err).ToNot(HaveOccurred())
			Expect(res).To(HaveLen(2))
			Expect(res).To(HaveKeyWithValue("roleARN", []byte("foo")))
		})

		It("should fail to inject role ARN due to invalid workload identity config", func() {
			metav1.SetMetaDataLabel(&secret.ObjectMeta, "security.gardener.cloud/purpose", "workload-identity-token-requestor")
			secret.Data = map[string][]byte{
				"config": []byte(`apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: FooBar
roleARN: "foo"`,
				)}
			Expect(fakeClient.Update(ctx, secret)).To(Succeed())

			data := map[string][]byte{}
			res, err := actuator.GetETCDSecretData(ctx, log, backupEntry, data)

			Expect(err).To(HaveOccurred())
			Expect(res).To(BeEmpty())
		})

		It("should fail to inject role ARN due to deleted secret", func() {
			Expect(fakeClient.Delete(ctx, secret)).To(Succeed())

			data := map[string][]byte{}
			_, err := actuator.GetETCDSecretData(ctx, log, backupEntry, data)

			Expect(err).To(HaveOccurred())
			Expect(err).To(BeNotFoundError())
		})
	})
})
