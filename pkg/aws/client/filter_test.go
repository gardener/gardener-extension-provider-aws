// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var _ = Describe("Client Filter", func() {

	It("#WithVpcId", func() {
		var vpcID = "test-vpc-id"

		a := awsclient.WithFilters().WithVpcId(vpcID).Build()

		Expect(a).To(ConsistOf(ec2types.Filter{
			Name:   aws.String(awsclient.FilterVpcID),
			Values: []string{vpcID},
		}))
	})

	It("#WithTags", func() {
		var tagTest = "test-tag"
		var tagValue = "test-tag-value"

		a := awsclient.WithFilters().WithTags(awsclient.Tags{tagTest: tagValue}).Build()

		Expect(a).To(ConsistOf(ec2types.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", tagTest)),
			Values: []string{tagValue},
		}))
	})
})
