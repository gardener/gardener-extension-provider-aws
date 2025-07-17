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
	output, err := awsClient.EC2.CreateSubnet(ctx, &ec2.CreateSubnetInput{
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
	})
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

	return *subnetID, nil
}

// DestroySubnet deletes an existing subnet.
func DestroySubnet(ctx context.Context, _ logr.Logger, awsClient *awsclient.Client, subnetID string) error {
	_, err := awsClient.EC2.DeleteSubnet(ctx, &ec2.DeleteSubnetInput{
		SubnetId: aws.String(subnetID),
	})

	return err
}
