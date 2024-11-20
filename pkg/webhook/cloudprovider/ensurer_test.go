// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cloudprovider_test

import (
	"context"
	"testing"

	"github.com/gardener/gardener/extensions/pkg/webhook/cloudprovider"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
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

		scheme := kubernetes.SeedScheme
		Expect(install.AddToScheme(scheme)).To(Succeed())

		ensurer = NewEnsurer(scheme, logger)
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

		It("should not add workload identity config to the secret if it is not labeled correctly", func() {
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "foo"}
			expected := secret.DeepCopy()
			Expect(ensurer.EnsureCloudProviderSecret(ctx, nil, secret, nil)).To(Succeed())
			expected.Data = map[string][]byte{
				aws.AccessKeyID:     []byte("access-key-id"),
				aws.SecretAccessKey: []byte("secret-access-key"),
				aws.SharedCredentialsFile: []byte(`[default]
aws_access_key_id=access-key-id
aws_secret_access_key=secret-access-key`),
			}
			Expect(secret).To(Equal(expected))
		})

		It("should error if cloudprovider secret does not contain config data key but is labeled correctly", func() {
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "aws"}
			err := ensurer.EnsureCloudProviderSecret(ctx, nil, secret, nil)
			Expect(err).To(HaveOccurred())

			Expect(err).To(MatchError("cloudprovider secret is missing a 'config' data key"))
		})

		It("should error if cloudprovider secret does not contain a valid WorkloadIdentityConfig", func() {
			secret.Data["config"] = []byte(`
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfigInvalid
`)
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "aws"}
			err := ensurer.EnsureCloudProviderSecret(ctx, nil, secret, nil)
			Expect(err).To(HaveOccurred())

			Expect(err.Error()).To(ContainSubstring("could not decode 'config' as WorkloadIdentityConfig"))
		})

		It("should add config to cloudprovider secret with if it contains WorkloadIdentityConfig", func() {
			secret.Data = map[string][]byte{
				"config": []byte(`
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: "foo"
`)}
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "aws"}
			Expect(ensurer.EnsureCloudProviderSecret(ctx, nil, secret, nil)).To(Succeed())
			Expect(secret.Data).To(Equal(map[string][]byte{
				"config": []byte(`
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: "foo"
`),
				"roleARN":                   []byte("foo"),
				"workloadIdentityTokenFile": []byte("/var/run/secrets/gardener.cloud/workload-identity/token"),
				"credentialsFile": []byte(`[default]
web_identity_token_file=/var/run/secrets/gardener.cloud/workload-identity/token
role_arn=foo`),
			}))
		})
	})
})
