// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// CreateVPC creates a new VPC and waits for it to become available. It returns
// the VPC ID, the Internet Gateway ID or an error in case something unexpected happens.
func CreateVPC(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcCIDR string, enableDnsHostnames, dualstack bool) (string, string, error) {
	createVpcOutput, err := awsClient.EC2.CreateVpc(&ec2.CreateVpcInput{
		TagSpecifications:           awsclient.Tags{"Name": "aws-infrastructure-it-create-vpc"}.ToTagSpecifications(ec2.ResourceTypeVpc),
		CidrBlock:                   awssdk.String(vpcCIDR),
		AmazonProvidedIpv6CidrBlock: awssdk.Bool(dualstack),
	})
	if err != nil {
		return "", "", err
	}
	vpcID := createVpcOutput.Vpc.VpcId

	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until vpc is available...", "vpcID", *vpcID)

		describeVpcOutput, err := awsClient.EC2.DescribeVpcs(&ec2.DescribeVpcsInput{
			VpcIds: []*string{vpcID},
		})
		if err != nil {
			return false, err
		}

		vpc := describeVpcOutput.Vpcs[0]
		if *vpc.State != "available" {
			return false, nil
		}

		return true, nil
	}); err != nil {
		return "", "", err
	}

	if enableDnsHostnames {
		_, err = awsClient.EC2.ModifyVpcAttribute(&ec2.ModifyVpcAttributeInput{
			EnableDnsHostnames: &ec2.AttributeBooleanValue{
				Value: awssdk.Bool(true),
			},
			VpcId: vpcID,
		})
		if err != nil {
			return "", "", err
		}
	}

	_, err = awsClient.EC2.ModifyVpcAttribute(&ec2.ModifyVpcAttributeInput{
		EnableDnsSupport: &ec2.AttributeBooleanValue{
			Value: awssdk.Bool(true),
		},
		VpcId: vpcID,
	})
	if err != nil {
		return "", "", err
	}

	createIgwOutput, err := awsClient.EC2.CreateInternetGateway(&ec2.CreateInternetGatewayInput{
		TagSpecifications: awsclient.Tags{"Name": "aws-infrastructure-it-create-vpc"}.ToTagSpecifications(ec2.ResourceTypeInternetGateway),
	})
	if err != nil {
		return "", "", err
	}
	igwID := createIgwOutput.InternetGateway.InternetGatewayId

	_, err = awsClient.EC2.AttachInternetGateway(&ec2.AttachInternetGatewayInput{
		InternetGatewayId: igwID,
		VpcId:             vpcID,
	})
	if err != nil {
		return "", "", err
	}

	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until internet gateway is attached to vpc...", "internetGatewayID", *igwID, "vpcID", *vpcID)

		describeIgwOutput, err := awsClient.EC2.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{
			InternetGatewayIds: []*string{igwID},
		})
		if err != nil {
			return false, err
		}

		igw := describeIgwOutput.InternetGateways[0]
		if len(igw.Attachments) == 0 {
			return false, nil
		}
		if *igw.Attachments[0].State != "available" {
			return false, nil
		}

		return true, nil
	}); err != nil {
		return "", "", err
	}

	return *vpcID, *igwID, nil
}

// DestroyVPC deletes the Internet Gateway and the VPC itself.
func DestroyVPC(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcID string) error {
	describeInternetGatewaysOutput, err := awsClient.EC2.DescribeInternetGatewaysWithContext(ctx, &ec2.DescribeInternetGatewaysInput{Filters: []*ec2.Filter{
		{
			Name: awssdk.String("attachment.vpc-id"),
			Values: []*string{
				awssdk.String(vpcID),
			},
		},
	}})
	if err != nil {
		return err
	}
	igwID := describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId

	_, err = awsClient.EC2.DetachInternetGateway(&ec2.DetachInternetGatewayInput{
		InternetGatewayId: igwID,
		VpcId:             awssdk.String(vpcID),
	})
	if err != nil {
		return err
	}

	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until internet gateway is detached from vpc...", "internetGatewayID", *igwID, "vpcID", vpcID)

		describeIgwOutput, err := awsClient.EC2.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{
			InternetGatewayIds: []*string{igwID},
		})
		if err != nil {
			return false, err
		}
		igw := describeIgwOutput.InternetGateways[0]

		return len(igw.Attachments) == 0, nil
	}); err != nil {
		return err
	}

	_, err = awsClient.EC2.DeleteInternetGateway(&ec2.DeleteInternetGatewayInput{
		InternetGatewayId: igwID,
	})
	if err != nil {
		return err
	}

	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until internet gateway is deleted...", "internetGatewayID", *igwID)

		_, err := awsClient.EC2.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{
			InternetGatewayIds: []*string{igwID},
		})
		if err != nil {
			ec2err, ok := err.(awserr.Error)
			if ok && ec2err.Code() == "InvalidInternetGatewayID.NotFound" {
				return true, nil
			}

			return true, err
		}

		return false, nil
	}); err != nil {
		return err
	}

	_, err = awsClient.EC2.DeleteVpc(&ec2.DeleteVpcInput{
		VpcId: &vpcID,
	})
	if err != nil {
		return err
	}

	return wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until vpc is deleted...", "vpcID", vpcID)

		_, err := awsClient.EC2.DescribeVpcs(&ec2.DescribeVpcsInput{
			VpcIds: []*string{&vpcID},
		})
		if err != nil {
			ec2err, ok := err.(awserr.Error)
			if ok && ec2err.Code() == "InvalidVpcID.NotFound" {
				return true, nil
			}

			return true, err
		}

		return false, nil
	})
}
