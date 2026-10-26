// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package cloudprovider_test

import (
	"context"
	"testing"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/webhook/cloudprovider"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
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
		gctx   gcontext.GardenContext

		accessKeyID     = "AKIAIOSFODNN7EXAMPLE"
		secretAccessKey = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12"
	)

	BeforeEach(func() {
		secret = &corev1.Secret{
			Data: map[string][]byte{
				aws.AccessKeyID:     []byte(accessKeyID),
				aws.SecretAccessKey: []byte(secretAccessKey),
			},
		}

		gctx = gcontext.NewInternalGardenContext(
			&extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						Region: "eu-west-1",
					},
				},
			},
		)

		ensurer = NewEnsurer(logger)
	})

	Describe("#EnsureCloudProviderSecret", func() {
		It("should fail as no accessKeyID is present", func() {
			delete(secret.Data, aws.AccessKeyID)
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).To(MatchError(ContainSubstring("could not mutate cloudprovider secret as %q field is missing", aws.AccessKeyID)))
		})
		It("should fail as no secretAccessKey is present", func() {
			delete(secret.Data, aws.SecretAccessKey)
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).To(MatchError(ContainSubstring("could not mutate cloudprovider secret as %q field is missing", aws.SecretAccessKey)))
		})
		It("should replace existing credentials file", func() {
			secret.Data[aws.SharedCredentialsFile] = []byte("shared-credentials-file")

			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data).To(Equal(map[string][]byte{
				aws.AccessKeyID:     []byte(accessKeyID),
				aws.SecretAccessKey: []byte(secretAccessKey),
				aws.SharedCredentialsFile: []byte(`[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12
region=eu-west-1`),
			}))
		})
		It("should add credentials file", func() {
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data).To(Equal(map[string][]byte{
				aws.AccessKeyID:     []byte(accessKeyID),
				aws.SecretAccessKey: []byte(secretAccessKey),
				aws.SharedCredentialsFile: []byte(`[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12
region=eu-west-1`),
			}))
		})

		It("should reject access key id containing newlines", func() {
			secret.Data[aws.AccessKeyID] = []byte("AKIATEST\nextra_key=value\nanother_key=value")
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).To(MatchError(ContainSubstring("invalid cloudprovider secret")))
			Expect(secret.Data).NotTo(HaveKey(aws.SharedCredentialsFile))
		})

		It("should reject secret access key containing newlines", func() {
			secret.Data[aws.SecretAccessKey] = []byte("secret\n[section]\nsome_key=some_value")
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).To(MatchError(ContainSubstring("invalid cloudprovider secret")))
			Expect(secret.Data).NotTo(HaveKey(aws.SharedCredentialsFile))
		})

		It("should reject a region containing newlines in the static-credentials path", func() {
			gctx = gcontext.NewInternalGardenContext(
				&extensionscontroller.Cluster{
					Shoot: &gardencorev1beta1.Shoot{
						Spec: gardencorev1beta1.ShootSpec{
							Region: "eu-west-1\n[default]\ncredential_process=malicious",
						},
					},
				},
			)
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).To(MatchError(ContainSubstring("invalid cloudprovider secret")))
			Expect(secret.Data).NotTo(HaveKey(aws.SharedCredentialsFile))
		})

		It("should not add workload identity config to the secret if it is not labeled correctly", func() {
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "foo"}
			expected := secret.DeepCopy()
			Expect(ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)).To(Succeed())
			expected.Data = map[string][]byte{
				aws.AccessKeyID:     []byte(accessKeyID),
				aws.SecretAccessKey: []byte(secretAccessKey),
				aws.SharedCredentialsFile: []byte(`[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12
region=eu-west-1`),
			}
			Expect(secret).To(Equal(expected))
		})

		It("should error if cloudprovider secret does not contain config data key but is labeled correctly", func() {
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "aws"}
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).To(HaveOccurred())

			Expect(err).To(MatchError("cloudprovider secret is missing a 'config' data key"))
		})

		It("should error if cloudprovider secret does not contain a valid WorkloadIdentityConfig", func() {
			secret.Data["config"] = []byte(`
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfigInvalid
`)
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "aws"}
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).To(HaveOccurred())

			Expect(err.Error()).To(ContainSubstring("could not decode 'config' as WorkloadIdentityConfig"))
		})

		It("should add config to cloudprovider secret with if it contains WorkloadIdentityConfig", func() {
			secret.Data = map[string][]byte{
				"config": []byte(`
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: "arn:aws:iam::123456789012:role/foo"
`)}
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "aws"}
			Expect(ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)).To(Succeed())
			Expect(secret.Data).To(Equal(map[string][]byte{
				"config": []byte(`
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkloadIdentityConfig
roleARN: "arn:aws:iam::123456789012:role/foo"
`),
				"roleARN":                   []byte("arn:aws:iam::123456789012:role/foo"),
				"workloadIdentityTokenFile": []byte("/var/run/secrets/gardener.cloud/workload-identity/token"),
				"credentialsFile": []byte(`[default]
web_identity_token_file=/var/run/secrets/gardener.cloud/workload-identity/token
role_arn=arn:aws:iam::123456789012:role/foo
region=eu-west-1`),
			}))
		})

		It("should reject a WorkloadIdentityConfig whose roleARN contains newlines", func() {
			secret.Data = map[string][]byte{
				"config": []byte("\napiVersion: aws.provider.extensions.gardener.cloud/v1alpha1\nkind: WorkloadIdentityConfig\nroleARN: \"arn:aws:iam::123456789012:role/foo\\nsome_key=some_value\"\n")}
			secret.Labels = map[string]string{"workloadidentity.security.gardener.cloud/provider": "aws"}
			err := ensurer.EnsureCloudProviderSecret(ctx, gctx, secret, nil)
			Expect(err).To(MatchError(ContainSubstring("invalid WorkloadIdentityConfig")))
			Expect(secret.Data).NotTo(HaveKey(aws.SharedCredentialsFile))
		})
	})
})
