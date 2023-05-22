package integration

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/onsi/gomega/format"
	gomegatypes "github.com/onsi/gomega/types"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

// EqualInfrastructureStatus is a gomega matcher that allows comparison between InfrastructureStatus'es after sorting slices or other fields that
// could fail a DeepEqual check.
func EqualInfrastructureStatus(expected *v1alpha1.InfrastructureStatus) gomegatypes.GomegaMatcher {
	return &equalInfrastructureStatusMatcher{
		expected: expected,
	}
}

type equalInfrastructureStatusMatcher struct {
	expected *v1alpha1.InfrastructureStatus
}

func (matcher *equalInfrastructureStatusMatcher) Match(actual interface{}) (success bool, err error) {
	status, ok := actual.(*v1alpha1.InfrastructureStatus)
	if !ok {
		return false, fmt.Errorf("only %s/%s is supported for this matcher", v1alpha1.SchemeGroupVersion.String(), "InfrastructureStatus")
	}

	sort.Slice(status.VPC.Subnets, func(i, j int) bool {
		return status.VPC.Subnets[i].ID < status.VPC.Subnets[j].ID
	})
	sort.Slice(matcher.expected.VPC.Subnets, func(i, j int) bool {
		return matcher.expected.VPC.Subnets[i].ID < matcher.expected.VPC.Subnets[j].ID
	})

	return reflect.DeepEqual(status, matcher.expected), nil
}

func (matcher *equalInfrastructureStatusMatcher) FailureMessage(actual interface{}) (message string) {
	actualString, actualOK := actual.(string)
	expected := interface{}(matcher.expected)
	expectedString, expectedOK := expected.(string)
	if actualOK && expectedOK {
		return format.MessageWithDiff(actualString, "to equal", expectedString)
	}

	return format.Message(actual, "to equal", expectedString)
}

func (matcher *equalInfrastructureStatusMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "not to equal", matcher.expected)
}
