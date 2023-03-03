// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
func DestroySecurityGroup(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, securityGroupID string) error {
	_, err := awsClient.EC2.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
		GroupId: awssdk.String(securityGroupID),
	})

	return err
}
