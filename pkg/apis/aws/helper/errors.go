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

package helper

import (
	"errors"
	"regexp"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"

	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	unauthenticatedRegexp               = regexp.MustCompile(`(?i)(InvalidAuthenticationTokenTenant|Authentication failed|AuthFailure|invalid character|invalid_client|query returned no results|InvalidAccessKeyId|cannot fetch token|InvalidSecretAccessKey|InvalidSubscriptionId)`)
	unauthorizedRegexp                  = regexp.MustCompile(`(?i)(Unauthorized|InvalidClientTokenId|SignatureDoesNotMatch|AuthorizationFailed|invalid_grant|Authorization Profile was not found|no active subscriptions|UnauthorizedOperation|not authorized|AccessDenied|OperationNotAllowed|Error 403|SERVICE_ACCOUNT_ACCESS_DENIED)`)
	quotaExceededRegexp                 = regexp.MustCompile(`(?i)((?:^|[^t]|(?:[^s]|^)t|(?:[^e]|^)st|(?:[^u]|^)est|(?:[^q]|^)uest|(?:[^e]|^)quest|(?:[^r]|^)equest)LimitExceeded|Quotas|Quota.*exceeded|exceeded quota|Quota has been met|QUOTA_EXCEEDED|Maximum number of ports exceeded|ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS|VolumeSizeExceedsAvailableQuota)`)
	rateLimitsExceededRegexp            = regexp.MustCompile(`(?i)(RequestLimitExceeded|Throttling|Too many requests)`)
	dependenciesRegexp                  = regexp.MustCompile(`(?i)(PendingVerification|Access Not Configured|accessNotConfigured|DependencyViolation|OptInRequired|DeleteConflict|Conflict|inactive billing state|ReadOnlyDisabledSubscription|is already being used|InUseSubnetCannotBeDeleted|VnetInUse|InUseRouteTableCannotBeDeleted|timeout while waiting for state to become|InvalidCidrBlock|already busy for|InsufficientFreeAddressesInSubnet|InternalServerError|internalerror|internal server error|A resource with the ID|VnetAddressSpaceCannotChangeDueToPeerings|InternalBillingError|There are not enough hosts available)`)
	retryableDependenciesRegexp         = regexp.MustCompile(`(?i)(RetryableError)`)
	resourcesDepletedRegexp             = regexp.MustCompile(`(?i)(not available in the current hardware cluster|InsufficientInstanceCapacity|SkuNotAvailable|ZonalAllocationFailed|out of stock|Zone.NotOnSale)`)
	configurationProblemRegexp          = regexp.MustCompile(`(?i)(not supported in your requested Availability Zone|InvalidParameter|InvalidParameterValue|notFound|NetcfgInvalidSubnet|InvalidSubnet|Invalid value|KubeletHasInsufficientMemory|KubeletHasDiskPressure|KubeletHasInsufficientPID|violates constraint|no attached internet gateway found|Your query returned no results|PrivateEndpointNetworkPoliciesCannotBeEnabledOnPrivateEndpointSubnet|invalid VPC attributes|PrivateLinkServiceNetworkPoliciesCannotBeEnabledOnPrivateLinkServiceSubnet|unrecognized feature gate|runtime-config invalid key|LoadBalancingRuleMustDisableSNATSinceSameFrontendIPConfigurationIsReferencedByOutboundRule|strict decoder error|not allowed to configure an unsupported|error during apply of object .* is invalid:|OverconstrainedZonalAllocationRequest|duplicate zones|overlapping zones)`)
	retryableConfigurationProblemRegexp = regexp.MustCompile(`(?i)(is misconfigured and requires zero voluntary evictions|SDK.CanNotResolveEndpoint|The requested configuration is currently not supported)`)
)

// DetermineError determines the Gardener error codes for the given error and returns an ErrorWithCodes with the error and codes.
func DetermineError(err error) error {
	if err == nil {
		return nil
	}

	// try to re-use codes from error
	var coder gardencorev1beta1helper.Coder
	if errors.As(err, &coder) {
		return err
	}

	codes := DetermineErrorCodes(err)
	if len(codes) == 0 {
		return err
	}

	return gardencorev1beta1helper.NewErrorWithCodes(err, codes...)
}

// DetermineErrorCodes determines error codes based on the given error.
func DetermineErrorCodes(err error) []gardencorev1beta1.ErrorCode {
	var (
		coder   gardencorev1beta1helper.Coder
		message = err.Error()
		codes   = sets.NewString()

		knownCodes = map[gardencorev1beta1.ErrorCode]func(string) bool{
			gardencorev1beta1.ErrorInfraUnauthenticated:          unauthenticatedRegexp.MatchString,
			gardencorev1beta1.ErrorInfraUnauthorized:             unauthorizedRegexp.MatchString,
			gardencorev1beta1.ErrorInfraQuotaExceeded:            quotaExceededRegexp.MatchString,
			gardencorev1beta1.ErrorInfraRateLimitsExceeded:       rateLimitsExceededRegexp.MatchString,
			gardencorev1beta1.ErrorInfraDependencies:             dependenciesRegexp.MatchString,
			gardencorev1beta1.ErrorRetryableInfraDependencies:    retryableDependenciesRegexp.MatchString,
			gardencorev1beta1.ErrorInfraResourcesDepleted:        resourcesDepletedRegexp.MatchString,
			gardencorev1beta1.ErrorConfigurationProblem:          configurationProblemRegexp.MatchString,
			gardencorev1beta1.ErrorRetryableConfigurationProblem: retryableConfigurationProblemRegexp.MatchString,
		}
	)

	// try to re-use codes from error
	if errors.As(err, &coder) {
		for _, code := range coder.Codes() {
			codes.Insert(string(code))
			// found codes don't need to be checked any more
			delete(knownCodes, code)
		}
	}

	// determine error codes
	for code, matchFn := range knownCodes {
		if !codes.Has(string(code)) && matchFn(message) {
			codes.Insert(string(code))
		}
	}

	// compute error code list based on code string set
	var out []gardencorev1beta1.ErrorCode
	for _, c := range codes.List() {
		out = append(out, gardencorev1beta1.ErrorCode(c))
	}
	return out
}
