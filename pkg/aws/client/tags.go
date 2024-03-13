// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// Tags is map of string key to string values. Duplicate keys are not supported in AWS.
type Tags map[string]string

// FromTags creates a Tags map from the given EC2 tag array.
func FromTags(ec2Tags []*ec2.Tag) Tags {
	tags := Tags{}
	for _, et := range ec2Tags {
		tags[aws.StringValue(et.Key)] = aws.StringValue(et.Value)
	}
	return tags
}

// ToTagSpecification exports the tags map as a EC2 TagSpecification for the given resource type.
func (tags Tags) ToTagSpecification(resourceType string) *ec2.TagSpecification {
	tagspec := &ec2.TagSpecification{
		ResourceType: aws.String(resourceType),
	}
	for k, v := range tags {
		tagspec.Tags = append(tagspec.Tags, &ec2.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return tagspec
}

// ToTagSpecifications exports the tags map as a EC2 TagSpecification array for the given resource type.
func (tags Tags) ToTagSpecifications(resourceType string) []*ec2.TagSpecification {
	if tags == nil {
		return nil
	}
	return []*ec2.TagSpecification{tags.ToTagSpecification(resourceType)}
}

// ToEC2Tags exports the tags map as a EC2 Tag array.
func (tags Tags) ToEC2Tags() []*ec2.Tag {
	var cp []*ec2.Tag
	for k, v := range tags {
		cp = append(cp, &ec2.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return cp
}

// ToFilters exports the tags map as a EC2 Filter array.
func (tags Tags) ToFilters() []*ec2.Filter {
	if tags == nil {
		return nil
	}
	var filters []*ec2.Filter
	for k, v := range tags {
		filters = append(filters, &ec2.Filter{Name: aws.String(fmt.Sprintf("tag:%s", k)), Values: []*string{aws.String(v)}})
	}
	return filters
}

// Clone creates a copy of the tags aps
func (tags Tags) Clone() Tags {
	cp := Tags{}
	for k, v := range tags {
		cp[k] = v
	}
	return cp
}
