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

package client

import (
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/route53"
)

func isValuesDoNotMatchError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeInvalidChangeBatch && strings.Contains(aerr.Message(), "the values provided do not match the current values") {
		return true
	}
	return false
}

// IsNoSuchHostedZoneError returns true if the error indicates a non-existing route53 hosted zone.
func IsNoSuchHostedZoneError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeNoSuchHostedZone {
		return true
	}
	return false
}

var notPermittedInZoneRegex = regexp.MustCompile(`RRSet with DNS name [^\ ]+ is not permitted in zone [^\ ]+`)

// IsNotPermittedInZoneError returns true if the error indicates that the DNS name is not permitted in the route53 hosted zone.
func IsNotPermittedInZoneError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeInvalidChangeBatch && notPermittedInZoneRegex.MatchString(aerr.Message()) {
		return true
	}
	return false
}

// IsThrottlingError returns true if the error is a throttling error.
func IsThrottlingError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && strings.Contains(aerr.Message(), "Throttling") {
		return true
	}
	return false
}

// IsDuplicateZonesError returns true if the error indicates that the DNS hosted zones already exists.
func IsDuplicateZonesError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && strings.Contains(aerr.Message(), "duplicate zones") {
		return true
	}
	return false
}

// IsOverlappingZonesError returns true if the error indicates that there are overlapping DNS hosted zones.
func IsOverlappingZonesError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && strings.Contains(aerr.Message(), "overlapping zones") {
		return true
	}
	return false
}
