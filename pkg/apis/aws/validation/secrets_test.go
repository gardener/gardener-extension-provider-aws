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

package validation_test

import (
	"strings"

	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
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

		Entry("should succeed when the client credentials are valid  (longest possilble access key)",
			map[string][]byte{
				aws.AccessKeyID:     []byte(strings.Repeat("a", 128)),
				aws.SecretAccessKey: []byte(strings.Repeat("b", 40)),
			},
			BeNil(),
		),
	)
})
