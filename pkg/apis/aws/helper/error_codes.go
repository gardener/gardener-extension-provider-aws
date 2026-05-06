// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"regexp"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
)

var (
	unauthenticatedRegexp               = regexp.MustCompile(`(?i)(AuthFailure|InvalidAccessKeyId|InvalidSecretAccessKey)`)
	unauthorizedRegexp                  = regexp.MustCompile(`(?i)(Unauthorized|InvalidClientTokenId|SignatureDoesNotMatch|UnauthorizedOperation|AccessDenied)`)
	quotaExceededRegexp                 = regexp.MustCompile(`(?i)((?:^|[^t]|(?:[^s]|^)t|(?:[^e]|^)st|(?:[^u]|^)est|(?:[^q]|^)uest|(?:[^e]|^)quest|(?:[^r]|^)equest)LimitExceeded|Quotas|Quota.*exceeded|exceeded quota|Quota has been met|QUOTA_EXCEEDED)`)
	rateLimitsExceededRegexp            = regexp.MustCompile(`(?i)(RequestLimitExceeded|Throttling|Too many requests)`)
	dependenciesRegexp                  = regexp.MustCompile(`(?i)(PendingVerification|Access Not Configured|accessNotConfigured|DependencyViolation|OptInRequired|DeleteConflict|Conflict|inactive billing state|timeout while waiting for state to become|InvalidCidrBlock|already busy for|InsufficientFreeAddressesInSubnet|internal server error|A resource with the ID|currently associated with another service)`)
	// Includes AWS eventual-consistency errors that surface during TGW
	// transitions: when the extension creates a Transit Gateway or
	// attachment and immediately uses it (e.g. ReplaceRoute pointing at
	// the new TGW), AWS may return *.NotFound for the resource we just
	// created because the underlying tag/resource indices haven't fully
	// propagated. These are always transient — the next reconcile will
	// see the resource exists.
	//
	// Without this classification the error would only match the broad
	// `notFound` pattern in configurationProblemRegexp and the shoot
	// would be marked permanently Failed, requiring manual
	// `operation=retry` to recover.
	retryableDependenciesRegexp = regexp.MustCompile(`(?i)(RetryableError|InvalidTransitGatewayID\.NotFound|InvalidTransitGatewayAttachmentID\.NotFound|InvalidTransitGatewayRouteTableID\.NotFound)`)
	resourcesDepletedRegexp             = regexp.MustCompile(`(?i)(not available in the current hardware cluster|InsufficientInstanceCapacity|out of stock)`)
	configurationProblemRegexp          = regexp.MustCompile(`(?i)(not supported in your requested Availability Zone|InvalidParameterValue|notFound|InvalidSubnet|Invalid value|violates constraint|no attached internet gateway found|invalid VPC attributes|unrecognized feature gate|runtime-config invalid key|strict decoder error|not allowed to configure an unsupported|error during apply of object .* is invalid:|duplicate zones|overlapping zones)`)
	retryableConfigurationProblemRegexp = regexp.MustCompile(`(?i)(is misconfigured and requires zero voluntary evictions|SDK.CanNotResolveEndpoint|The requested configuration is currently not supported)`)

	// KnownCodes maps Gardener error codes to respective regex.
	KnownCodes = map[gardencorev1beta1.ErrorCode]func(string) bool{
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
