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

// GetIPAM retrieves the existing IPAM and its private scope ID.
func GetIPAM(ctx context.Context, awsClient *awsclient.Client) (ipamID, privateScopeID string, err error) {
	// Get all IPAMs, since there can be only one per account per region
	ipamsOut, err := awsClient.EC2.DescribeIpams(ctx, nil)
	if err != nil {
		return "", "", err
	}

	if len(ipamsOut.Ipams) == 0 {
		return "", "", nil
	}

	privateScopeID = aws.ToString(ipamsOut.Ipams[0].PrivateDefaultScopeId)
	ipamID = aws.ToString(ipamsOut.Ipams[0].IpamId)
	return ipamID, privateScopeID, nil
}

// CreateIPAM creates an IPAM with tag 'purpose' and value 'integration-test'.
func CreateIPAM(ctx context.Context, awsClient *awsclient.Client, region, namespace string) (ipamID, privateScopeID string, err error) {
	createIpamOut, err := awsClient.EC2.CreateIpam(ctx, &ec2.CreateIpamInput{
		Description: aws.String("aws-infrastructure-it-ipam"),
		OperatingRegions: []ec2types.AddIpamOperatingRegion{
			{
				RegionName: aws.String(region),
			},
		},
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeIpam,
				Tags: []ec2types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String("aws-infrastructure-it-ipam"),
					},
					{
						Key:   aws.String("purpose"),
						Value: aws.String("integration-test"),
					},
					{
						Key:   aws.String("namespace"),
						Value: aws.String(namespace),
					},
				},
			},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to create IPAM: %w", err)
	}

	ipamID = aws.ToString(createIpamOut.Ipam.IpamId)

	var ipamsOut = &ec2.DescribeIpamsOutput{}
	ctxTimeout, cancel := context.WithTimeout(ctx, time.Minute*10)
	defer cancel()
	// Wait until the IPAM is available
	err = wait.PollUntilContextCancel(ctxTimeout, 5*time.Second, false, func(_ context.Context) (bool, error) {
		ipamsOut, err = awsClient.EC2.DescribeIpams(ctx, &ec2.DescribeIpamsInput{
			IpamIds: []string{ipamID},
		})
		if err != nil {
			return false, err
		}
		if len(ipamsOut.Ipams) == 0 {
			return false, nil
		}
		if ipamsOut.Ipams[0].State == ec2types.IpamStateCreateComplete {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to wait for IPAM to become available: %w", err)
	}

	privateScopeID = aws.ToString(ipamsOut.Ipams[0].PrivateDefaultScopeId)
	return ipamID, privateScopeID, nil
}

// DeleteIPAM deletes an IPAM with the given id.
func DeleteIPAM(ctx context.Context, awsClient *awsclient.Client, id string) error {
	_, err := awsClient.EC2.DeleteIpam(ctx, &ec2.DeleteIpamInput{
		IpamId:  aws.String(id),
		Cascade: aws.Bool(true),
	})
	return err
}

// CreateIPv6IPAMPool creates an IPv6 IPAM pool with tag 'purpose' and value 'integration-test'.
func CreateIPv6IPAMPool(ctx context.Context, awsClient *awsclient.Client, region, privateScopeID, namespace string) (string, error) {
	// Create new IPAM pool for integration tests
	createResp, err := awsClient.EC2.CreateIpamPool(ctx, &ec2.CreateIpamPoolInput{
		Description:   aws.String("aws-infrastructure-it-ipam-pool"),
		Locale:        aws.String(region),
		AddressFamily: ec2types.AddressFamilyIpv6,
		IpamScopeId:   aws.String(privateScopeID),
		TagSpecifications: awsclient.Tags{
			"Name":      "aws-infrastructure-it-ipam-pool",
			"purpose":   "integration-test",
			"namespace": namespace,
		}.ToTagSpecifications(ec2types.ResourceTypeIpamPool),
	})
	if err != nil {
		return "", err
	}

	ipamPoolID := aws.ToString(createResp.IpamPool.IpamPoolId)

	ctxTimeout, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()
	// Wait until the IPAM pool is available
	err = wait.PollUntilContextCancel(ctxTimeout, 5*time.Second, false, func(_ context.Context) (bool, error) {
		describeResp, err := awsClient.EC2.DescribeIpamPools(ctx, &ec2.DescribeIpamPoolsInput{
			IpamPoolIds: []string{ipamPoolID},
		})
		if err != nil {
			return false, err
		}
		if len(describeResp.IpamPools) == 0 {
			return false, nil
		}
		if describeResp.IpamPools[0].State == ec2types.IpamPoolStateCreateComplete {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return "", err
	}

	// Provision a CIDR to the IPAM pool
	err = ipamProvisionIPv6CIDR(ctx, awsClient, ipamPoolID)
	return ipamPoolID, err
}

// DeleteIPAMPool deletes an IPv6 IPAM pool with given id.
func DeleteIPAMPool(ctx context.Context, awsClient *awsclient.Client, id string) error {
	_, err := awsClient.EC2.DeleteIpamPool(ctx, &ec2.DeleteIpamPoolInput{
		IpamPoolId: aws.String(id),
		Cascade:    aws.Bool(true),
	})
	return err
}

func ipamProvisionIPv6CIDR(ctx context.Context, awsClient *awsclient.Client, ipamPoolID string) error {
	_, err := awsClient.EC2.ProvisionIpamPoolCidr(ctx, &ec2.ProvisionIpamPoolCidrInput{
		IpamPoolId:    aws.String(ipamPoolID),
		NetmaskLength: aws.Int32(56),
	})
	if err != nil {
		return err
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	err = wait.PollUntilContextCancel(ctxTimeout, 5*time.Second, false, func(_ context.Context) (bool, error) {
		out, err := awsClient.EC2.GetIpamPoolCidrs(ctx, &ec2.GetIpamPoolCidrsInput{
			IpamPoolId: aws.String(ipamPoolID),
		})
		if err != nil {
			return false, err
		}
		if len(out.IpamPoolCidrs) == 0 {
			return false, nil
		}
		switch out.IpamPoolCidrs[0].State {
		case ec2types.IpamPoolCidrStateProvisioned:
			return true, nil
		case ec2types.IpamPoolCidrStateFailedProvision:
			return false, fmt.Errorf("IPAM pool CIDR provisioning failed for %s", *out.IpamPoolCidrs[0].Cidr)
		default:
			return false, nil
		}
	})
	return err
}
