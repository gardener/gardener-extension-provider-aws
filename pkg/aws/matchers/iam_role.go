// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/awsutil"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/onsi/gomega/format"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
)

// beSemanticallyEqualToIamRole returns a matcher that tests if actual is semantically
// equal to the given iam.Role
func beSemanticallyEqualToIamRole(expected interface{}) types.GomegaMatcher {
	return &iamRoleMatcher{
		expected: expected,
	}
}

type iamRoleMatcher struct {
	expected interface{}
}

func (m *iamRoleMatcher) Match(actual interface{}) (success bool, err error) {
	if actual == nil && m.expected == nil {
		return false, fmt.Errorf("refusing to compare <nil> to <nil>.\nBe explicit and use BeNil() instead. This is to avoid mistakes where both sides of an assertion are erroneously uninitialized")
	}

	expectedRole, ok := m.expected.(iam.Role)
	if !ok {
		expectedRolePointer, ok2 := m.expected.(*iam.Role)
		if ok2 {
			expectedRole = *expectedRolePointer
		} else {
			return false, fmt.Errorf("refusing to compare expected which is neither a iam.Role nor a *iam.Role")
		}
	}

	actualRole, ok := actual.(iam.Role)
	if !ok {
		actualRolePointer, ok2 := actual.(*iam.Role)
		if ok2 {
			actualRole = *actualRolePointer
		} else {
			return false, fmt.Errorf("refusing to compare actual which is neither a iam.Role nor a *iam.Role")
		}
	}

	return MatchFields(IgnoreExtras, Fields{
		"Path":                     genericBeNilOrEqualTo(expectedRole.Path),
		"AssumeRolePolicyDocument": PointTo(BeSemanticallyEqualToRolePolicyDocument(*expectedRole.AssumeRolePolicyDocument)),
	}).Match(actualRole)
}

func (m *iamRoleMatcher) FailureMessage(actual interface{}) (message string) {
	return format.MessageWithDiff(awsutil.Prettify(actual), "to equal", awsutil.Prettify(m.expected))
}

func (m *iamRoleMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.MessageWithDiff(awsutil.Prettify(actual), "not to equal", awsutil.Prettify(m.expected))
}
