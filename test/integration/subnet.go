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
	"time"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

func CreateSubnet(ctx context.Context, logger *logrus.Entry, awsClient *awsclient.Client, vpcID string, cidr string, name string) (string, error) {
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

	if err := wait.PollUntil(5*time.Second, func() (bool, error) {
		logger.Infof("Waiting until subnet '%s' is available...", *subnetID)

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
	}, ctx.Done()); err != nil {
		return "", err
	}

	return *subnetID, nil
}

func DestroySubnet(ctx context.Context, logger *logrus.Entry, awsClient *awsclient.Client, subnetID string) error {
	_, err := awsClient.EC2.DeleteSubnet(&ec2.DeleteSubnetInput{
		SubnetId: awssdk.String(subnetID),
	})

	return err
}
