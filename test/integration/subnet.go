// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// CreateSubnet creates a new subnet and waits for it to become available.
func CreateSubnet(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcID string, cidr string, name string) (string, error) {
	output, err := awsClient.EC2.CreateSubnet(&ec2.CreateSubnetInput{
		CidrBlock: awssdk.String(cidr),
		VpcId:     awssdk.String(vpcID),
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: awssdk.String("subnet"),
				Tags: []*ec2.Tag{
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(name),
					},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	subnetID := output.Subnet.SubnetId

	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until subnet is available...", "subnetID", *subnetID)

		output, err := awsClient.EC2.DescribeSubnets(&ec2.DescribeSubnetsInput{
			SubnetIds: []*string{subnetID},
		})
		if err != nil {
			return false, err
		}

		subnet := output.Subnets[0]
		if *subnet.State != "available" {
			return false, nil
		}

		return true, nil
	}); err != nil {
		return "", err
	}

	return *subnetID, nil
}

// DestroySubnet deletes an existing subnet.
func DestroySubnet(_ context.Context, _ logr.Logger, awsClient *awsclient.Client, subnetID string) error {
	_, err := awsClient.EC2.DeleteSubnet(&ec2.DeleteSubnetInput{
		SubnetId: awssdk.String(subnetID),
	})

	return err
}
