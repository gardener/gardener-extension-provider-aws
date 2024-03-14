// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"fmt"
	"reflect"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

// BeSemanticallyEqualTo returns a matcher that tests if actual is semantically
// equal to the given value from the aws sdk.
// This is useful for checking equalities on values returned by the aws API more easily.
// For example: ec2.IpPermission contains multiple arrays which might not be in the same order
// each time you retrieve the object from the AWS API. Therefore the returned matcher does not
// test for deep equality but rather uses the ConsistOf matcher for nested arrays.
// Another example is iam.Role which contains a field `AssumeRolePolicyDocument` which is urlencoded
// when returned by the AWS API. The return matcher therefore decodes the policy document before
// comparing it to expected via the MatchJSON matcher to make the test more readable.
func BeSemanticallyEqualTo(expected interface{}) types.GomegaMatcher {
	if expected == nil {
		return BeNil()
	}

	switch expected.(type) {
	case ec2.IpPermission, *ec2.IpPermission:
		return beSemanticallyEqualToIpPermission(expected)
	case []ec2.IpPermission, []*ec2.IpPermission:
		return genericConsistOfSemanticallyEqual(expected)
	case iam.Role, *iam.Role:
		return beSemanticallyEqualToIamRole(expected)
	case []iam.Role, []*iam.Role:
		return genericConsistOfSemanticallyEqual(expected)
	default:
		panic(fmt.Errorf("unknown type for aws matcher BeSemanticallyEqualTo(): %T", expected))
	}
}

func genericBeNilOrEqualTo(expected interface{}) types.GomegaMatcher {
	if expected == nil {
		return BeNil()
	}

	return Equal(expected)
}

func genericBeNilOrEquivalentTo(expected interface{}) types.GomegaMatcher {
	if expected == nil {
		return BeNil()
	}

	return BeEquivalentTo(expected)
}

func genericConsistOf(expected interface{}) types.GomegaMatcher {
	value := reflect.ValueOf(expected)
	if value.Kind() != reflect.Slice {
		panic(fmt.Errorf("invalid type of expected passed to genericConsistOf, only accepting slices: %s", value.Type().String()))
	}

	if value.Len() == 0 {
		return BeEmpty()
	}

	var expectedElements []interface{}

	for i := 0; i < value.Len(); i++ {
		expectedElement := value.Index(i)
		if expectedElement.IsNil() {
			expectedElements = append(expectedElements, BeNil())
		} else {
			expectedElements = append(expectedElements, Equal(expectedElement.Interface()))
		}
	}

	return ConsistOf(expectedElements)
}

func genericConsistOfSemanticallyEqual(expected interface{}) types.GomegaMatcher {
	value := reflect.ValueOf(expected)
	if value.Kind() != reflect.Slice {
		panic(fmt.Errorf("invalid type of expected passed to genericConsistOfSemanticallyEqual, only accepting slices: %s", value.Type().String()))
	}

	if value.Len() == 0 {
		return BeEmpty()
	}

	var expectedElements []interface{}

	for i := 0; i < value.Len(); i++ {
		expectedElement := value.Index(i)
		if expectedElement.IsNil() {
			expectedElements = append(expectedElements, BeNil())
		} else {
			expectedElements = append(expectedElements, BeSemanticallyEqualTo(expectedElement.Interface()))
		}
	}

	return ConsistOf(expectedElements)
}
