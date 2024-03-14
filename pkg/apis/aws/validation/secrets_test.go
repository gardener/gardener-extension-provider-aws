// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"

	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

var _ = Describe("Secret validation", func() {

	DescribeTable("#ValidateCloudProviderSecret",
		func(data map[string][]byte, matcher gomegatypes.GomegaMatcher) {
			secret := &corev1.Secret{
				Data: data,
			}
			err := ValidateCloudProviderSecret(secret)

			Expect(err).To(matcher)
		},

		Entry("should return error when the access key field is missing",
			map[string][]byte{
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40)),
			},
			HaveOccurred(),
		),

		Entry("should return error when the access key is empty",
			map[string][]byte{
				aws.AccessKeyID:     {},
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40)),
			},
			HaveOccurred(),
		),

		Entry("should return error when the access key is too short",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 15)),
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40)),
			},
			HaveOccurred(),
		),

		Entry("should return error when the access key is too long",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 129)),
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40)),
			},
			HaveOccurred(),
		),

		Entry("should return error when the access key does not contain only alphanumeric characters",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 20) + " "),
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40)),
			},
			HaveOccurred(),
		),

		Entry("should return error when the secret access key field is missing",
			map[string][]byte{
				aws.AccessKeyID: []byte(strings.Repeat("a", 16)),
			},
			HaveOccurred(),
		),

		Entry("should return error when the secret access key is empty",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 16)),
				aws.SecretAccessKey: {},
			},
			HaveOccurred(),
		),

		Entry("should return error when the secret access key is too short",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 16)),
				aws.SecretAccessKey: []byte(strings.Repeat("b", 39)),
			},
			HaveOccurred(),
		),

		Entry("should return error when the secret access key does not contain only base64 characters",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 16)),
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40) + " "),
			},
			HaveOccurred(),
		),

		Entry("should succeed when the client credentials are valid (shortest possilble access key)",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 16)),
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40)),
			},
			BeNil(),
		),

		Entry("should succeed when the client credentials are valid (longest possilble access key)",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 128)),
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40)),
			},
			BeNil(),
		),
	)
})
