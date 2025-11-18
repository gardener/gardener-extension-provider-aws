// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// CreateVPC creates a new VPC and waits for it to become available. It returns
// the VPC ID, the Internet Gateway ID or an error in case something unexpected happens.
func CreateVPC(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcCIDR string, enableDnsHostnames, dualstack bool, egressOnlyIG bool) (string, string, string, error) {
	createVpcOutput, err := awsClient.EC2.CreateVpc(ctx, &ec2.CreateVpcInput{
		TagSpecifications:           awsclient.Tags{"Name": "aws-infrastructure-it-create-vpc"}.ToTagSpecifications(ec2types.ResourceTypeVpc),
		CidrBlock:                   aws.String(vpcCIDR),
		AmazonProvidedIpv6CidrBlock: aws.Bool(dualstack),
	})
	if err != nil {
		return "", "", "", err
	}
	vpcID := createVpcOutput.Vpc.VpcId

	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until vpc is available...", "vpcID", *vpcID)

		describeVpcOutput, err := awsClient.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
			VpcIds: []string{*vpcID},
		})
		if err != nil {
			return false, err
		}

		vpc := describeVpcOutput.Vpcs[0]
		if vpc.State != ec2types.VpcStateAvailable {
			return false, nil
		}

		return true, nil
	}); err != nil {
		return "", "", "", err
	}

	_, err = awsClient.EC2.ModifyVpcAttribute(ctx, &ec2.ModifyVpcAttributeInput{
		EnableDnsSupport: &ec2types.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
		VpcId: vpcID,
	})
	if err != nil {
		return "", "", "", err
	}

	if enableDnsHostnames {
		_, err = awsClient.EC2.ModifyVpcAttribute(ctx, &ec2.ModifyVpcAttributeInput{
			EnableDnsHostnames: &ec2types.AttributeBooleanValue{
				Value: aws.Bool(true),
			},
			VpcId: vpcID,
		})
		if err != nil {
			return "", "", "", err
		}
	}

	createIgwOutput, err := awsClient.EC2.CreateInternetGateway(ctx, &ec2.CreateInternetGatewayInput{
		TagSpecifications: awsclient.Tags{"Name": "aws-infrastructure-it-create-vpc"}.ToTagSpecifications(ec2types.ResourceTypeInternetGateway),
	})
	if err != nil {
		return "", "", "", err
	}
	igwID := createIgwOutput.InternetGateway.InternetGatewayId

	_, err = awsClient.EC2.AttachInternetGateway(ctx, &ec2.AttachInternetGatewayInput{
		InternetGatewayId: igwID,
		VpcId:             vpcID,
	})
	if err != nil {
		return "", "", "", err
	}

	if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until internet gateway is attached to vpc...", "internetGatewayID", *igwID, "vpcID", *vpcID)

		describeIgwOutput, err := awsClient.EC2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
			InternetGatewayIds: []string{*igwID},
		})
		if err != nil {
			return false, err
		}

		igw := describeIgwOutput.InternetGateways[0]
		if len(igw.Attachments) == 0 {
			return false, nil
		}
		if string(igw.Attachments[0].State) != "available" { // There is no fitting ec2types.AttachementStatus yet
			return false, nil
		}
		return true, nil
	}); err != nil {
		return "", "", "", err
	}

	egressOnlyIGID := ""
	if egressOnlyIG {
		createEoIgwOutput, err := awsClient.EC2.CreateEgressOnlyInternetGateway(ctx, &ec2.CreateEgressOnlyInternetGatewayInput{
			TagSpecifications: awsclient.Tags{"Name": "aws-infrastructure-it-create-vpc"}.ToTagSpecifications(ec2types.ResourceTypeEgressOnlyInternetGateway),
			VpcId:             vpcID,
		})
		if err != nil {
			return "", "", "", err
		}

		egressOnlyIGID = *createEoIgwOutput.EgressOnlyInternetGateway.EgressOnlyInternetGatewayId
	}

	return *vpcID, *igwID, egressOnlyIGID, nil
}

// DestroyVPC deletes the Internet Gateway and the VPC itself.
func DestroyVPC(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, vpcID string) error {
	describeInternetGatewaysOutput, err := awsClient.EC2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{Filters: []ec2types.Filter{
		{
			Name:   aws.String("attachment.vpc-id"),
			Values: []string{vpcID},
		},
	}})
	if err != nil {
		return err
	}
	if len(describeInternetGatewaysOutput.InternetGateways) > 0 {
		igwID := describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId

		_, err = awsClient.EC2.DetachInternetGateway(ctx, &ec2.DetachInternetGatewayInput{
			InternetGatewayId: igwID,
			VpcId:             aws.String(vpcID),
		})
		if err != nil {
			return err
		}

		if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
			log.Info("Waiting until internet gateway is detached from vpc...", "internetGatewayID", *igwID, "vpcID", vpcID)

			describeIgwOutput, err := awsClient.EC2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
				InternetGatewayIds: []string{*igwID},
			})
			if err != nil {
				return false, err
			}
			igw := describeIgwOutput.InternetGateways[0]

			return len(igw.Attachments) == 0, nil
		}); err != nil {
			return err
		}

		_, err = awsClient.EC2.DeleteInternetGateway(ctx, &ec2.DeleteInternetGatewayInput{
			InternetGatewayId: igwID,
		})
		if err != nil {
			return err
		}

		if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
			log.Info("Waiting until internet gateway is deleted...", "internetGatewayID", *igwID)

			_, err := awsClient.EC2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
				InternetGatewayIds: []string{*igwID},
			})
			if err != nil {
				var awserr smithy.APIError
				if errors.As(err, &awserr) && strings.EqualFold(awserr.ErrorCode(), "InvalidInternetGatewayID.NotFound") {
					return true, nil
				}
				return true, err
			}
			return false, nil
		}); err != nil {
			return err
		}
	}
	describeEgressOnlyInternetGatewaysOutput, err := awsClient.EC2.DescribeEgressOnlyInternetGateways(ctx, &ec2.DescribeEgressOnlyInternetGatewaysInput{})
	if err != nil {
		return err
	}

	var eoigs []ec2types.EgressOnlyInternetGateway
	for _, item := range describeEgressOnlyInternetGatewaysOutput.EgressOnlyInternetGateways {
		if *item.Attachments[0].VpcId == vpcID {
			eoigs = append(eoigs, item)
		}
	}

	if eoigs != nil {
		eoigwID := eoigs[0].EgressOnlyInternetGatewayId

		_, err = awsClient.EC2.DeleteEgressOnlyInternetGateway(ctx, &ec2.DeleteEgressOnlyInternetGatewayInput{
			EgressOnlyInternetGatewayId: eoigwID,
		})
		if err != nil {
			return err
		}

		if err := wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
			log.Info("Waiting until egress only internet gateway is deleted...", "internetGatewayID", *eoigwID)

			eogw, err := awsClient.EC2.DescribeEgressOnlyInternetGateways(ctx, &ec2.DescribeEgressOnlyInternetGatewaysInput{
				EgressOnlyInternetGatewayIds: []string{*eoigwID},
			})
			if err != nil {
				var awserr smithy.APIError
				if errors.As(err, &awserr) && strings.EqualFold(awserr.ErrorCode(), "InvalidEgressOnlyInternetGatewayID.NotFound") { // No modeled error type yet
					return true, nil
				}
				return true, err
			}
			// I didn't see a NotFound error, however EgressOnlyInternetGateways is empty when the gateway is not found.
			if eogw != nil && len(eogw.EgressOnlyInternetGateways) == 0 {
				return true, nil
			}
			return false, nil
		}); err != nil {
			return err
		}
	}
	vpcs, err := awsClient.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{
			{
				Name:   ptr.To(awsclient.FilterVpcID),
				Values: []string{vpcID},
			},
		},
	})
	if err != nil {
		return err
	}
	if len(vpcs.Vpcs) == 0 {
		return nil
	}

	_, err = awsClient.EC2.DeleteVpc(ctx, &ec2.DeleteVpcInput{
		VpcId: &vpcID,
	})
	if err != nil {
		return err
	}

	return wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(_ context.Context) (bool, error) {
		log.Info("Waiting until vpc is deleted...", "vpcID", vpcID)

		_, err := awsClient.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
			VpcIds: []string{vpcID},
		})
		if err != nil {
			var awserr smithy.APIError
			if errors.As(err, &awserr) && strings.EqualFold(awserr.ErrorCode(), "InvalidVpcID.NotFound") { // No modeled error type yet
				return true, nil
			}
			return true, err
		}

		return false, nil
	})
}

// GetIntegrationTestIPAMPoolID queries IPAM pools for the tag key 'purpose' with value 'integration-test'.
func GetIntegrationTestIPAMPoolID(ctx context.Context, awsClient *awsclient.Client) (string, error) {
	resp, err := awsClient.EC2.DescribeIpamPools(ctx, &ec2.DescribeIpamPoolsInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("tag:purpose"),
			Values: []string{"integration-test"},
		}},
	})
	if err != nil {
		return "", err
	}
	if len(resp.IpamPools) == 0 {
		return "", fmt.Errorf("no IPAM pool found with tag 'purpose=integration-test'")	
	}
	return aws.ToString(resp.IpamPools[0].IpamPoolId), nil
}
