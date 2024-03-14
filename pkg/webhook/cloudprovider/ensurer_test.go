// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cloudprovider_test

import (
	"context"
	"testing"

	"github.com/gardener/gardener/extensions/pkg/webhook/cloudprovider"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/webhook/cloudprovider"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CloudProvider Webhook Suite")
}

var _ = Describe("Ensurer", func() {
	var (
		logger = log.Log.WithName("aws-cloudprovider-webhook-test")
		ctx    = context.TODO()

		ensurer cloudprovider.Ensurer

		secret *corev1.Secret
	)

	BeforeEach(func() {
		secret = &corev1.Secret{
			Data: map[string][]byte{
				aws.AccessKeyID:     []byte("access-key-id"),
				aws.SecretAccessKey: []byte("secret-access-key"),
			},
		}

		ensurer = NewEnsurer(logger)
	})

	Describe("#EnsureCloudProviderSecret", func() {
		It("should fail as no accessKeyID is present", func() {
			delete(secret.Data, aws.AccessKeyID)
			err := ensurer.EnsureCloudProviderSecret(ctx, nil, secret, nil)
			Expect(err).To(MatchError(ContainSubstring("could not mutate cloudprovider secret as %q field is missing", aws.AccessKeyID)))
		})
		It("should fail as no secretAccessKey is present", func() {
			delete(secret.Data, aws.SecretAccessKey)
			err := ensurer.EnsureCloudProviderSecret(ctx, nil, secret, nil)
			Expect(err).To(MatchError(ContainSubstring("could not mutate cloudprovider secret as %q field is missing", aws.SecretAccessKey)))
		})
		It("should replace esixting credentials file", func() {
			secret.Data[aws.SharedCredentialsFile] = []byte("shared-credentials-file")

			err := ensurer.EnsureCloudProviderSecret(ctx, nil, secret, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data).To(Equal(map[string][]byte{
				aws.AccessKeyID:     []byte("access-key-id"),
				aws.SecretAccessKey: []byte("secret-access-key"),
				aws.SharedCredentialsFile: []byte(`[default]
aws_access_key_id=access-key-id
aws_secret_access_key=secret-access-key`),
			}))
		})
		It("should add credentials file", func() {
			err := ensurer.EnsureCloudProviderSecret(ctx, nil, secret, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data).To(Equal(map[string][]byte{
				aws.AccessKeyID:     []byte("access-key-id"),
				aws.SecretAccessKey: []byte("secret-access-key"),
				aws.SharedCredentialsFile: []byte(`[default]
aws_access_key_id=access-key-id
aws_secret_access_key=secret-access-key`),
			}))
		})
	})
})
