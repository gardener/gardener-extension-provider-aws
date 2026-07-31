// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// CreateSubnet creates a new subnet and waits for it to become available.
func CreateSubnet(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcID string, cidr string, name string) (string, error) {
	return CreateSubnetInZone(ctx, log, awsClient, vpcID, cidr, name, "")
}

// CreateSubnetInZone creates a new subnet in a specific availability zone and waits for it to become available.
// If availabilityZone is empty, AWS picks the default AZ.
func CreateSubnetInZone(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcID string, cidr string, name string, availabilityZone string) (string, error) {
	return createSubnet(ctx, log, awsClient, vpcID, cidr, "", name, availabilityZone, false)
}

// CreateDualStackSubnetInZone creates a new subnet with both an IPv4 CIDR and an IPv6 CIDR, in a specific availability
// zone, and waits for it to become available. The IPv6 CIDR must be a valid /64 within the VPC's /56 IPv6 pool. If
// assignIpv6OnCreation is true, the subnet is configured to auto-assign IPv6 addresses to instances at launch — used
// for workers subnets in BYO+IPv6 scenarios.
func CreateDualStackSubnetInZone(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcID string, cidr string, ipv6Cidr string, name string, availabilityZone string, assignIpv6OnCreation bool) (string, error) {
	return createSubnet(ctx, log, awsClient, vpcID, cidr, ipv6Cidr, name, availabilityZone, assignIpv6OnCreation)
}

func createSubnet(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcID string, cidr string, ipv6Cidr string, name string, availabilityZone string, assignIpv6OnCreation bool) (string, error) {
	input := &ec2.CreateSubnetInput{
		CidrBlock: aws.String(cidr),
		VpcId:     aws.String(vpcID),
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeSubnet,
				Tags: []ec2types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(name),
					},
				},
			},
		},
	}
	if availabilityZone != "" {
		input.AvailabilityZone = aws.String(availabilityZone)
	}
	if ipv6Cidr != "" {
		input.Ipv6CidrBlock = aws.String(ipv6Cidr)
	}

	output, err := awsClient.EC2.CreateSubnet(ctx, input)
	if err != nil {
		return "", err
	}

	subnetID := output.Subnet.SubnetId

	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until subnet is available...", "subnetID", *subnetID)

		output, err := awsClient.EC2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			SubnetIds: []string{*subnetID},
		})
		if err != nil {
			return false, err
		}

		subnet := output.Subnets[0]
		if subnet.State != ec2types.SubnetStateAvailable {
			return false, nil
		}

		return true, nil
	}); err != nil {
		return "", err
	}

	if assignIpv6OnCreation {
		if _, err := awsClient.EC2.ModifySubnetAttribute(ctx, &ec2.ModifySubnetAttributeInput{
			SubnetId:                    subnetID,
			AssignIpv6AddressOnCreation: &ec2types.AttributeBooleanValue{Value: aws.Bool(true)},
		}); err != nil {
			return "", err
		}
	}

	return *subnetID, nil
}

// DestroySubnet deletes an existing subnet.
func DestroySubnet(ctx context.Context, _ logr.Logger, awsClient *awsclient.Client, subnetID string) error {
	_, err := awsClient.EC2.DeleteSubnet(ctx, &ec2.DeleteSubnetInput{
		SubnetId: aws.String(subnetID),
	})

	return err
}
