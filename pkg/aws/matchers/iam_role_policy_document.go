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
	"net/url"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
)

func BeSemanticallyEqualToRolePolicyDocument(expected interface{}) types.GomegaMatcher {
	return &rolePolicyDocumentMatcher{
		expected: expected,
	}
}

type rolePolicyDocumentMatcher struct {
	expected interface{}
}

func (m *rolePolicyDocumentMatcher) Match(actual interface{}) (bool, error) {
	if actual == nil && m.expected == nil {
		return false, fmt.Errorf("refusing to compare <nil> to <nil>.\nBe explicit and use BeNil() instead. This is to avoid mistakes where both sides of an assertion are erroneously uninitialized")
	}

	expectedString, ok := m.expected.(string)
	if !ok {
		expectedStringPointer, ok2 := m.expected.(*string)
		if ok2 {
			if expectedStringPointer == nil {
				return false, fmt.Errorf("refusing to compare expected which is a nil string")
			}
			expectedString = *expectedStringPointer
		} else {
			return false, fmt.Errorf("refusing to compare expected which is neither a string nor a *string")
		}
	}

	expectedUnescaped, err := url.QueryUnescape(expectedString)
	if err != nil {
		return false, fmt.Errorf("error url-decoding expected")
	}

	actualString, ok := actual.(string)
	if !ok {
		actualStringPointer, ok2 := actual.(*string)
		if ok2 {
			if actualStringPointer == nil {
				return false, fmt.Errorf("refusing to compare actual which is a nil string")
			}
			actualString = *actualStringPointer
		} else {
			return false, fmt.Errorf("refusing to compare actual which is neither a string nor a *string")
		}
	}

	actualUnescaped, err := url.QueryUnescape(actualString)
	if err != nil {
		return false, fmt.Errorf("error url-decoding actual: %+v", err)
	}

	return MatchJSON(actualUnescaped).Match(expectedUnescaped)
}

func (m *rolePolicyDocumentMatcher) FailureMessage(actual interface{}) (message string) {
	return format.MessageWithDiff(fmt.Sprintf("%+v", actual), "to equal", fmt.Sprintf("%+v", m.expected))
}

func (m *rolePolicyDocumentMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.MessageWithDiff(fmt.Sprintf("%+v", actual), "not to equal", fmt.Sprintf("%+v", m.expected))
}
