// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
)

// Tags is map of string key to string values. Duplicate keys are not supported in AWS.
type Tags map[string]string

// FromTags creates a Tags map from the given EC2 tag array.
func FromTags(ec2Tags []ec2types.Tag) Tags {
	tags := Tags{}
	for _, et := range ec2Tags {
		tags[aws.ToString(et.Key)] = aws.ToString(et.Value)
	}
	return tags
}

// ToTagSpecification exports the tags map as a EC2 TagSpecification for the given resource type.
func (tags Tags) ToTagSpecification(resourceType ec2types.ResourceType) ec2types.TagSpecification {
	tagspec := ec2types.TagSpecification{
		ResourceType: resourceType,
	}
	for k, v := range tags {
		tagspec.Tags = append(tagspec.Tags, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return tagspec
}

// ToTagSpecifications exports the tags map as a EC2 TagSpecification array for the given resource type.
func (tags Tags) ToTagSpecifications(resourceType ec2types.ResourceType) []ec2types.TagSpecification {
	if tags == nil {
		return nil
	}
	return []ec2types.TagSpecification{tags.ToTagSpecification(resourceType)}
}

// ToEC2Tags exports the tags map as a EC2 Tag array.
func (tags Tags) ToEC2Tags() []ec2types.Tag {
	var cp []ec2types.Tag
	for k, v := range tags {
		cp = append(cp, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return cp
}

// ToEfsTags exports the tags map as a EFS Tag array.
func (tags Tags) ToEfsTags() []efstypes.Tag {
	var cp []efstypes.Tag
	for k, v := range tags {
		cp = append(cp, efstypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return cp
}

// ContainEfsTags checks if the tags map contains all the key-value pairs from the given EFS tags.
func (tags Tags) ContainEfsTags(efsTags []efstypes.Tag) bool {
	efsTagMap := make(map[string]string)
	for _, tag := range efsTags {
		efsTagMap[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}

	for k, v := range tags {
		if efsTagMap[k] != v {
			return false
		}
	}

	return true
}

// AddManagedTag adds the "managed-by-gardener" tag to the tags map if it does not already exist.
func (tags Tags) AddManagedTag() Tags {
	if tags == nil {
		tags = Tags{}
	}
	if _, exists := tags["managed-by-gardener"]; !exists {
		tags["managed-by-gardener"] = "true"
	}
	return tags
}

// ToFilters exports the tags map as a EC2 Filter array.
func (tags Tags) ToFilters() []ec2types.Filter {
	if tags == nil {
		return nil
	}
	var filters []ec2types.Filter
	for k, v := range tags {
		filters = append(filters, ec2types.Filter{Name: aws.String(fmt.Sprintf("tag:%s", k)), Values: []string{v}})
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
