// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/go-logr/logr"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// CreateSecurityGroup creates a new security group.
func CreateSecurityGroup(ctx context.Context, awsClient *awsclient.Client, groupName string, vpcID string) (string, error) {
	output, err := awsClient.EC2.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		Description: aws.String("group for worker nodes"),
		GroupName:   aws.String(groupName),
		VpcId:       aws.String(vpcID),
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeSecurityGroup,
				Tags: []ec2types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(groupName),
					},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	return *output.GroupId, nil
}

// DestroySecurityGroup deletes an existing security group.
func DestroySecurityGroup(ctx context.Context, _ logr.Logger, awsClient *awsclient.Client, securityGroupID string) error {
	_, err := awsClient.EC2.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(securityGroupID),
	})

	return err
}
