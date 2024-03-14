// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/awsutil"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/onsi/gomega/format"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
)

// beSemanticallyEqualToIpPermission returns a matcher that tests if actual is semantically
// equal to the given ec2.IpPermission
func beSemanticallyEqualToIpPermission(expected interface{}) types.GomegaMatcher {
	return &ipPermissionMatcher{
		expected: expected,
	}
}

type ipPermissionMatcher struct {
	expected interface{}
}

func (m *ipPermissionMatcher) Match(actual interface{}) (success bool, err error) {
	if actual == nil && m.expected == nil {
		return false, fmt.Errorf("refusing to compare <nil> to <nil>.\nBe explicit and use BeNil() instead. This is to avoid mistakes where both sides of an assertion are erroneously uninitialized")
	}

	expectedPermission, ok := m.expected.(ec2.IpPermission)
	if !ok {
		expectedPermissionPointer, ok2 := m.expected.(*ec2.IpPermission)
		if ok2 {
			expectedPermission = *expectedPermissionPointer
		} else {
			return false, fmt.Errorf("refusing to compare expected which is neither a ec2.IpPermission nor a *ec2.IpPermission")
		}
	}

	actualPermission, ok := actual.(ec2.IpPermission)
	if !ok {
		actualPermissionPointer, ok2 := actual.(*ec2.IpPermission)
		if ok2 {
			actualPermission = *actualPermissionPointer
		} else {
			return false, fmt.Errorf("refusing to compare actual which is neither a ec2.IpPermission nor a *ec2.IpPermission")
		}
	}

	return MatchFields(IgnoreExtras, Fields{
		"FromPort":         genericBeNilOrEquivalentTo(expectedPermission.FromPort),
		"IpProtocol":       genericBeNilOrEqualTo(expectedPermission.IpProtocol),
		"IpRanges":         genericConsistOf(expectedPermission.IpRanges),
		"Ipv6Ranges":       genericConsistOf(expectedPermission.Ipv6Ranges),
		"PrefixListIds":    genericConsistOf(expectedPermission.PrefixListIds),
		"ToPort":           genericBeNilOrEquivalentTo(expectedPermission.ToPort),
		"UserIdGroupPairs": genericConsistOf(expectedPermission.UserIdGroupPairs),
	}).Match(actualPermission)
}

func (m *ipPermissionMatcher) FailureMessage(actual interface{}) (message string) {
	return format.MessageWithDiff(awsutil.Prettify(actual), "to equal", awsutil.Prettify(m.expected))
}

func (m *ipPermissionMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.MessageWithDiff(awsutil.Prettify(actual), "not to equal", awsutil.Prettify(m.expected))
}
