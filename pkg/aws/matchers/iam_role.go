// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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
