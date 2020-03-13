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
	"reflect"

	"github.com/aws/aws-sdk-go/service/ec2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

// BeSemanticallyEqualTo returns a matcher that tests if actual is semantically
// equal to the given value from the aws sdk
func BeSemanticallyEqualTo(expected interface{}) types.GomegaMatcher {
	if expected == nil {
		return BeNil()
	}

	switch expected.(type) {
	case ec2.IpPermission, *ec2.IpPermission:
		return beSemanticallyEqualToIpPermission(expected)
	case []ec2.IpPermission, []*ec2.IpPermission:
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
