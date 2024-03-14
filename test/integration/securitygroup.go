// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/go-logr/logr"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// CreateSecurityGroup creates a new security group.
func CreateSecurityGroup(ctx context.Context, awsClient *awsclient.Client, groupName string, vpcID string) (string, error) {
	output, err := awsClient.EC2.CreateSecurityGroupWithContext(ctx, &ec2.CreateSecurityGroupInput{
		Description: awssdk.String("group for worker nodes"),
		GroupName:   awssdk.String(groupName),
		VpcId:       awssdk.String(vpcID),
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: awssdk.String("security-group"),
				Tags: []*ec2.Tag{
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(groupName),
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
func DestroySecurityGroup(_ context.Context, _ logr.Logger, awsClient *awsclient.Client, securityGroupID string) error {
	_, err := awsClient.EC2.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
		GroupId: awssdk.String(securityGroupID),
	})

	return err
}
