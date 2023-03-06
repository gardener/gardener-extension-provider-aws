// Copyright (c) 2023 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package cloudprovider_test

import (
	"context"
	"testing"

	"github.com/gardener/gardener/extensions/pkg/webhook/cloudprovider"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"

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
		logger  = log.Log.WithName("aws-cloudprovider-webhook-test")
		ctx     = context.TODO()
		ensurer cloudprovider.Ensurer
		scheme  *runtime.Scheme

		secret *corev1.Secret
	)

	BeforeEach(func() {
		secret = &corev1.Secret{
			Data: map[string][]byte{
				aws.AccessKeyID:     []byte("access-key-id"),
				aws.SecretAccessKey: []byte("secret-access-key"),
			},
		}

		scheme = runtime.NewScheme()
		install.Install(scheme)
		ensurer = NewEnsurer(logger)

		err := ensurer.(inject.Scheme).InjectScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
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
