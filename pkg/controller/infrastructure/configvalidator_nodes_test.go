// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apiaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
)

var _ = Describe("validateNodesCIDRInSubnet", func() {
	var fldPath *field.Path

	BeforeEach(func() {
		fldPath = field.NewPath("networks", "zones").Index(0).Child("workersSubnetID")
	})

	DescribeTable("subnet CIDR containment within nodes CIDR",
		func(subnetCIDR, nodesCIDR string, expectErr bool) {
			subnet := &awsclient.Subnet{
				SubnetId:  "subnet-test",
				CidrBlock: subnetCIDR,
			}
			errs := validateNodesCIDRInSubnet(subnet, fldPath, "subnet-test", nodesCIDR)
			if expectErr {
				Expect(errs).NotTo(BeEmpty())
			} else {
				Expect(errs).To(BeEmpty())
			}
		},
		Entry("subnet CIDR contained in nodes CIDR", "10.0.0.0/19", "10.0.0.0/16", false),
		Entry("subnet CIDR equals nodes CIDR (exact match)", "10.0.0.0/19", "10.0.0.0/19", false),
		Entry("subnet CIDR larger than nodes CIDR (not contained)", "10.0.0.0/16", "10.0.0.0/24", true),
		Entry("subnet CIDR outside nodes CIDR range", "192.168.0.0/24", "10.0.0.0/24", true),
		Entry("subnet CIDR partially overlaps but not contained", "10.0.0.128/23", "10.0.0.0/24", true),
		Entry("empty nodes CIDR (no check)", "10.0.0.0/24", "", false),
		Entry("IPv6 subnet CIDR is skipped", "2001:db8::/48", "10.0.0.0/16", false),
		Entry("empty subnet CIDR (IPv6-native, skip check)", "", "10.0.0.0/24", false),
		Entry("IPv4 subnet CIDR against IPv6 nodes CIDR (skip check)", "10.0.0.0/28", "2a05:d018:800:9d00::/56", false),
	)
})

var _ = Describe("validateBYOSubnets", func() {
	var (
		ctrl      *gomock.Controller
		awsClient *mockawsclient.MockInterface
		cv        *configValidator
		ctx       context.Context
		vpcID     string
		nodesCIDR string
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		awsClient = mockawsclient.NewMockInterface(ctrl)
		cv = &configValidator{}
		ctx = context.Background()
		vpcID = "vpc-12345"
		nodesCIDR = "10.0.0.0/16"
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Context("multi-zone nodes CIDR validation", func() {
		It("should pass when all zone worker subnets are contained within nodes CIDR", func() {
			config := &apiaws.InfrastructureConfig{
				Networks: apiaws.Networks{
					VPC: apiaws.VPC{ID: ptr.To(vpcID)},
					Zones: []apiaws.Zone{
						{Name: "eu-west-1a", WorkersSubnetID: ptr.To("subnet-zone-a")},
						{Name: "eu-west-1b", WorkersSubnetID: ptr.To("subnet-zone-b")},
						{Name: "eu-west-1c", WorkersSubnetID: ptr.To("subnet-zone-c")},
					},
				},
			}

			awsClient.EXPECT().GetSubnets(ctx, []string{"subnet-zone-a"}).Return([]*awsclient.Subnet{
				{SubnetId: "subnet-zone-a", CidrBlock: "10.0.0.0/19", VpcId: ptr.To(vpcID), AvailabilityZone: "eu-west-1a"},
			}, nil)
			awsClient.EXPECT().GetSubnets(ctx, []string{"subnet-zone-b"}).Return([]*awsclient.Subnet{
				{SubnetId: "subnet-zone-b", CidrBlock: "10.0.32.0/19", VpcId: ptr.To(vpcID), AvailabilityZone: "eu-west-1b"},
			}, nil)
			awsClient.EXPECT().GetSubnets(ctx, []string{"subnet-zone-c"}).Return([]*awsclient.Subnet{
				{SubnetId: "subnet-zone-c", CidrBlock: "10.0.64.0/19", VpcId: ptr.To(vpcID), AvailabilityZone: "eu-west-1c"},
			}, nil)

			errs := cv.validateBYOSubnets(ctx, awsClient, config, vpcID, false, nodesCIDR)
			Expect(errs).To(BeEmpty())
		})

		It("should fail when one zone's worker subnet is outside the nodes CIDR", func() {
			config := &apiaws.InfrastructureConfig{
				Networks: apiaws.Networks{
					VPC: apiaws.VPC{ID: ptr.To(vpcID)},
					Zones: []apiaws.Zone{
						{Name: "eu-west-1a", WorkersSubnetID: ptr.To("subnet-zone-a")},
						{Name: "eu-west-1b", WorkersSubnetID: ptr.To("subnet-zone-b")},
					},
				},
			}

			awsClient.EXPECT().GetSubnets(ctx, []string{"subnet-zone-a"}).Return([]*awsclient.Subnet{
				{SubnetId: "subnet-zone-a", CidrBlock: "10.0.0.0/19", VpcId: ptr.To(vpcID), AvailabilityZone: "eu-west-1a"},
			}, nil)
			// subnet-zone-b is in a completely different range, outside 10.0.0.0/16
			awsClient.EXPECT().GetSubnets(ctx, []string{"subnet-zone-b"}).Return([]*awsclient.Subnet{
				{SubnetId: "subnet-zone-b", CidrBlock: "192.168.0.0/24", VpcId: ptr.To(vpcID), AvailabilityZone: "eu-west-1b"},
			}, nil)

			errs := cv.validateBYOSubnets(ctx, awsClient, config, vpcID, false, nodesCIDR)
			Expect(errs).NotTo(BeEmpty())
			Expect(errs[0].Field).To(Equal("networks.zones[1].workersSubnetID"))
		})
	})
})
