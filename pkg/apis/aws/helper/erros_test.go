// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package helper_test

import (
	"errors"
	"fmt"

	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("errors", func() {
	Describe("#DetermineError", func() {
		It("should return nil for empty error", func() {
			Expect(DetermineError(nil)).To(BeNil())
		})
	})
	DescribeTable("#DetermineError",
		func(err error, expectedErr error) {
			Expect(DetermineError(err)).To(Equal(expectedErr))
		},

		Entry("no wrapped error",
			fmt.Errorf("foo"),
			errors.New("foo"),
		),
		Entry("no code to extract",
			errors.New("foo"),
			errors.New("foo"),
		),
		Entry("unauthenticated",
			errors.New("authentication failed"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("authentication failed"), gardencorev1beta1.ErrorInfraUnauthenticated),
		),
		Entry("unauthenticated",
			errors.New("invalidauthenticationtokentenant"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("invalidauthenticationtokentenant"), gardencorev1beta1.ErrorInfraUnauthenticated),
		),
		Entry("wrapped unauthenticated error with coder",
			fmt.Errorf("%w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("unauthenticated"), gardencorev1beta1.ErrorInfraUnauthenticated)),
			fmt.Errorf("%w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("unauthenticated"), gardencorev1beta1.ErrorInfraUnauthenticated)),
		),
		Entry("unauthorized",
			errors.New("unauthorized"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("unauthorized"), gardencorev1beta1.ErrorInfraUnauthorized),
		),
		Entry("unauthorized with coder",
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("operation not allowed"), gardencorev1beta1.ErrorInfraUnauthorized),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("operation not allowed"), gardencorev1beta1.ErrorInfraUnauthorized),
		),
		Entry("wrapped unauthorized error",
			fmt.Errorf("no sufficient permissions: %w", errors.New("AuthorizationFailed")),
			gardencorev1beta1helper.NewErrorWithCodes(fmt.Errorf("no sufficient permissions: %w", errors.New("AuthorizationFailed")), gardencorev1beta1.ErrorInfraUnauthorized),
		),
		Entry("wrapped unauthorized error with coder",
			fmt.Errorf("%w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("unauthorized"), gardencorev1beta1.ErrorInfraUnauthorized)),
			fmt.Errorf("%w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("unauthorized"), gardencorev1beta1.ErrorInfraUnauthorized)),
		),
		Entry("insufficient privileges",
			errors.New("accessdenied"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("accessdenied"), gardencorev1beta1.ErrorInfraUnauthorized),
		),
		Entry("insufficient privileges with coder",
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("accessdenied"), gardencorev1beta1.ErrorInfraUnauthorized),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("accessdenied"), gardencorev1beta1.ErrorInfraUnauthorized),
		),
		Entry("quota exceeded",
			errors.New("limitexceeded"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("limitexceeded"), gardencorev1beta1.ErrorInfraQuotaExceeded),
		),
		Entry("quota exceeded",
			errors.New("foolimitexceeded"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("foolimitexceeded"), gardencorev1beta1.ErrorInfraQuotaExceeded),
		),
		Entry("quota exceeded",
			errors.New("equestlimitexceeded"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("equestlimitexceeded"), gardencorev1beta1.ErrorInfraQuotaExceeded),
		),
		Entry("quota exceeded",
			errors.New("subnetlimitexceeded"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("subnetlimitexceeded"), gardencorev1beta1.ErrorInfraQuotaExceeded),
		),
		Entry("quota exceeded with coder",
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("limitexceeded"), gardencorev1beta1.ErrorInfraQuotaExceeded),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("limitexceeded"), gardencorev1beta1.ErrorInfraQuotaExceeded),
		),
		Entry("request throttling",
			errors.New("message=cannot get hosted zones: Throttling"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("message=cannot get hosted zones: Throttling"), gardencorev1beta1.ErrorInfraRateLimitsExceeded),
		),
		Entry("request throttling",
			errors.New("requestlimitexceeded"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("requestlimitexceeded"), gardencorev1beta1.ErrorInfraRateLimitsExceeded),
		),
		Entry("request throttling with coder",
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("message=cannot get hosted zones: Throttling"), gardencorev1beta1.ErrorInfraRateLimitsExceeded),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("message=cannot get hosted zones: Throttling"), gardencorev1beta1.ErrorInfraRateLimitsExceeded),
		),
		Entry("infrastructure dependencies",
			errors.New("pendingverification"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("pendingverification"), gardencorev1beta1.ErrorInfraDependencies),
		),
		Entry("infrastructure dependencies with coder",
			fmt.Errorf("error occurred: %w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("pendingverification"), gardencorev1beta1.ErrorInfraDependencies)),
			fmt.Errorf("error occurred: %w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("pendingverification"), gardencorev1beta1.ErrorInfraDependencies)),
		),
		Entry("resources depleted",
			fmt.Errorf("error occurred: not available in the current hardware cluster"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("error occurred: not available in the current hardware cluster"), gardencorev1beta1.ErrorInfraResourcesDepleted),
		),
		Entry("resources depleted with coder",
			fmt.Errorf("error occurred: %w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("not available in the current hardware cluster"), gardencorev1beta1.ErrorInfraResourcesDepleted)),
			fmt.Errorf("error occurred: %w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("not available in the current hardware cluster"), gardencorev1beta1.ErrorInfraResourcesDepleted)),
		),
		Entry("configuration problem",
			fmt.Errorf("error occurred: %w", errors.New("InvalidParameterValue")),
			gardencorev1beta1helper.NewErrorWithCodes(fmt.Errorf("error occurred: %w", errors.New("InvalidParameterValue")), gardencorev1beta1.ErrorConfigurationProblem),
		),
		Entry("configuration problem with coder",
			fmt.Errorf("error occurred: %w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("InvalidParameterValue"), gardencorev1beta1.ErrorConfigurationProblem)),
			fmt.Errorf("error occurred: %w", gardencorev1beta1helper.NewErrorWithCodes(errors.New("InvalidParameterValue"), gardencorev1beta1.ErrorConfigurationProblem)),
		),
		Entry("retryable configuration problem",
			errors.New("pod disruption budget default/pdb is misconfigured and requires zero voluntary evictions"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("pod disruption budget default/pdb is misconfigured and requires zero voluntary evictions"), gardencorev1beta1.ErrorRetryableConfigurationProblem),
		),
		Entry("retryable configuration problem with coder",
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("pod disruption budget default/pdb is misconfigured and requires zero voluntary evictions"), gardencorev1beta1.ErrorRetryableConfigurationProblem),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("pod disruption budget default/pdb is misconfigured and requires zero voluntary evictions"), gardencorev1beta1.ErrorRetryableConfigurationProblem),
		),
		Entry("retryable infrastructure dependencies",
			errors.New("Code=\"RetryableError\" Message=\"A retryable error occurred"),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("Code=\"RetryableError\" Message=\"A retryable error occurred"), gardencorev1beta1.ErrorRetryableInfraDependencies),
		),
		Entry("retryable infrastructure dependencies with coder",
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("Code=\"RetryableError\" Message=\"A retryable error occurred"), gardencorev1beta1.ErrorRetryableInfraDependencies),
			gardencorev1beta1helper.NewErrorWithCodes(errors.New("Code=\"RetryableError\" Message=\"A retryable error occurred"), gardencorev1beta1.ErrorRetryableInfraDependencies)),
	)
})
