// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"fmt"
	"net/url"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
)

// BeSemanticallyEqualToRolePolicyDocument returns a matcher that checks if a role policy document is semantically equal to the given one.
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
