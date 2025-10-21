// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"regexp"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	// k8s resource names have max 253 characters, consist of lower case alphanumeric characters, '-' or '.'
	k8sResourceNameRegex = `^[a-z0-9.-]+$`
	// VpcIDRegex matches e.g. vpc-064b5b7771f6331aa
	VpcIDRegex = `^vpc-[a-z0-9]+$`
	// EipAllocationIDRegex matches e.g. eipalloc-0676786f3e288044c
	EipAllocationIDRegex = `^eipalloc-[a-z0-9]+$`
	// SnapshotIDRegex matches e.g. snap-0676786f3e288044c
	SnapshotIDRegex = `^snap-[a-z0-9]+$`
	// IamInstanceProfileNameRegex matches https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-instanceprofile.html#:~:text=Properties-,InstanceProfileName,-The%20name%20of
	IamInstanceProfileNameRegex = `^[\w+=,.@-]+$`
	// IamInstanceProfileArnRegex matches arn:aws:iam::<account-id>:instance-profile/<path>/<profile-name>
	// Note: for china landscapes it's arn:aws-cn:iam::<account-id>:instance-profile/<path>/<profile-name>
	IamInstanceProfileArnRegex = `^arn:[\w +=,.@\-/:]+$`
	// ZoneNameRegex matches e.g. us-east-1a
	ZoneNameRegex = `^[a-z0-9-]+$`
	// TagKeyRegex matches Letters (a–z, A–Z), numbers (0–9), spaces, and the following symbols: + - = . _ : / @
	TagKeyRegex = `^[\w +\-=\.:/@]+$`
	// CapacityReservationIDRegex matches IDs of Capacity Reservations. Example: // cr-1234abcd56example
	CapacityReservationIDRegex = `^cr-[a-z0-9]+$`
	// CapacityReservationGroupRegex matches resource-group ARNs, e.g.: arn:aws:resource-groups:eu-west-2:123456789012:group/example-cr-group

	CapacityReservationGroupRegex    = `^arn:[\w-]+:resource-groups:[\w +=,.@\-\/:]+$`
	validateK8sResourceName          = combineValidationFuncs(regex(k8sResourceNameRegex), notEmpty, maxLength(253))
	validateVpcID                    = combineValidationFuncs(regex(VpcIDRegex), notEmpty, maxLength(255))
	validateEipAllocationID          = combineValidationFuncs(regex(EipAllocationIDRegex), maxLength(255))
	validateSnapshotID               = combineValidationFuncs(regex(SnapshotIDRegex), maxLength(255))
	validateIamInstanceProfileName   = combineValidationFuncs(regex(IamInstanceProfileNameRegex), notEmpty, maxLength(128))
	validateIamInstanceProfileArn    = combineValidationFuncs(regex(IamInstanceProfileArnRegex), maxLength(255))
	validateZoneName                 = combineValidationFuncs(regex(ZoneNameRegex), maxLength(255))
	validateTagKey                   = combineValidationFuncs(regex(TagKeyRegex), notEmpty, maxLength(128))
	validateCapacityReservationID    = combineValidationFuncs(regex(CapacityReservationIDRegex), notEmpty, maxLength(255))
	validateCapacityReservationGroup = combineValidationFuncs(regex(CapacityReservationGroupRegex), notEmpty, maxLength(255))
)

type validateFunc[T any] func(T, *field.Path) field.ErrorList

// combineValidationFuncs validates a value against a list of filters.
func combineValidationFuncs[T any](filters ...validateFunc[T]) validateFunc[T] {
	return func(t T, fld *field.Path) field.ErrorList {
		var allErrs field.ErrorList
		for _, f := range filters {
			allErrs = append(allErrs, f(t, fld)...)
		}
		return allErrs
	}
}

// regex returns a filterFunc that validates a string against a regular expression.
func regex(regex string) validateFunc[string] {
	compiled := regexp.MustCompile(regex)
	return func(name string, fld *field.Path) field.ErrorList {
		var allErrs field.ErrorList
		if name == "" {
			return allErrs // Allow empty strings to pass through
		}
		if !compiled.MatchString(name) {
			allErrs = append(allErrs, field.Invalid(fld, name, fmt.Sprintf("does not match expected regex %s", compiled.String())))
		}
		return allErrs
	}
}

func notEmpty(name string, fld *field.Path) field.ErrorList {
	if utf8.RuneCountInString(name) == 0 {
		return field.ErrorList{field.Required(fld, "cannot be empty")}
	}
	return nil
}

func maxLength(max int) validateFunc[string] {
	return func(name string, fld *field.Path) field.ErrorList {
		var allErrs field.ErrorList
		if l := utf8.RuneCountInString(name); l > max {
			return field.ErrorList{field.Invalid(fld, name, fmt.Sprintf("must not be more than %d characters, got %d", max, l))}
		}
		return allErrs
	}
}
