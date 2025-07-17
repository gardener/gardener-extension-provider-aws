// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	// FilterVpcID is the name of the VPC ID filter.
	FilterVpcID = "vpc-id"
)

type filterBuilder struct {
	filters []ec2types.Filter
}

// WithFilters creates a new filter builder.
func WithFilters() *filterBuilder {
	return &filterBuilder{}
}

// WithVpcId adds a VPC ID filter to the builder.
func (f filterBuilder) WithVpcId(vpcId string) filterBuilder {
	f.filters = append(f.filters, filter(FilterVpcID, vpcId)...)
	return f
}

// WithTags adds a tags filter to the builder.
func (f filterBuilder) WithTags(tags Tags) filterBuilder {
	f.filters = append(f.filters, tags.ToFilters()...)
	return f
}

// Build builds the filters and returns them.
func (f filterBuilder) Build() []ec2types.Filter {
	return f.filters
}

func filter(key string, values ...string) []ec2types.Filter {
	if len(values) == 0 {
		return nil
	}

	f := ec2types.Filter{
		Name:   aws.String(key),
		Values: make([]string, 0, len(values)),
	}
	f.Values = append(f.Values, values...)
	return []ec2types.Filter{f}
}
