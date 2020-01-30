// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package client

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elb/elbiface"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/pkg/errors"
)

// Client is a struct containing several clients for the different AWS services it needs to interact with.
// * EC2 is the standard client for the EC2 service.
// * STS is the standard client for the STS service.
// * S3 is the standard client for the S3 service.
// * ELB is the standard client for the ELB service.
// * ELBv2 is the standard client for the ELBv2 service.
type Client struct {
	EC2 ec2iface.EC2API
	STS stsiface.STSAPI
	S3  s3iface.S3API

	ELB   elbiface.ELBAPI
	ELBv2 elbv2iface.ELBV2API
}

// LoadBalancer is a struct wrapper that holds loadbalancer metadata such as name, type, and arn.
type LoadBalancer struct {
	Name *string
	Type *string
	Arn  *string
}

// NewClient creates a new Client for the given AWS credentials <accessKeyID>, <secretAccessKey>, and
// the AWS region <region>.
// It initializes the clients for the various services like EC2, ELB, etc.
func NewClient(accessKeyID, secretAccessKey, region string) (Interface, error) {
	var (
		awsConfig = &aws.Config{
			Credentials: credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
		}
		config = &aws.Config{Region: aws.String(region)}
	)

	s, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	return &Client{
		EC2:   ec2.New(s, config),
		ELB:   elb.New(s, config),
		ELBv2: elbv2.New(s, config),
		STS:   sts.New(s, config),
		S3:    s3.New(s, config),
	}, nil
}

// GetAccountID returns the ID of the AWS account the Client is interacting with.
func (c *Client) GetAccountID(ctx context.Context) (string, error) {
	getCallerIdentityOutput, err := c.STS.GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return *getCallerIdentityOutput.Account, nil
}

// GetInternetGateway returns the ID of the internet gateway attached to the given VPC <vpcID>.
// If there is no internet gateway attached, the returned string will be empty.
func (c *Client) GetInternetGateway(ctx context.Context, vpcID string) (string, error) {
	describeInternetGatewaysInput := &ec2.DescribeInternetGatewaysInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("attachment.vpc-id"),
				Values: []*string{
					aws.String(vpcID),
				},
			},
		},
	}
	describeInternetGatewaysOutput, err := c.EC2.DescribeInternetGatewaysWithContext(ctx, describeInternetGatewaysInput)
	if err != nil {
		return "", err
	}

	if describeInternetGatewaysOutput.InternetGateways != nil {
		if *describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId == "" {
			return "", fmt.Errorf("no attached internet gateway found for vpc %s", vpcID)
		}
		return *describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId, nil
	}
	return "", fmt.Errorf("no attached internet gateway found for vpc %s", vpcID)
}

// The following functions are only temporary needed due to https://github.com/gardener/gardener/issues/129.

// ListKubernetesELBs returns the list of ELB loadbalancers in the given <vpcID> tagged with <clusterName>.
func (c *Client) ListKubernetesELBs(ctx context.Context, vpcID, clusterName string) ([]string, error) {
	var (
		results       []string
		describeLBErr error
	)

	if err := c.ELB.DescribeLoadBalancersPagesWithContext(ctx, &elb.DescribeLoadBalancersInput{}, func(page *elb.DescribeLoadBalancersOutput, lastPage bool) bool {
		for _, lb := range page.LoadBalancerDescriptions {
			if lb.VPCId != nil && *lb.VPCId == vpcID {
				// TODO: DescribeTagsWithContext can take multiple LoadBalancers,  make just 1 call to collect all Tags
				tags, err := c.ELB.DescribeTagsWithContext(ctx, &elb.DescribeTagsInput{
					LoadBalancerNames: []*string{lb.LoadBalancerName},
				})
				if err != nil {
					describeLBErr = err
					return false
				}

				for _, description := range tags.TagDescriptions {
					for _, tag := range description.Tags {
						if tag.Key != nil && *tag.Key == fmt.Sprintf("kubernetes.io/cluster/%s", clusterName) && tag.Value != nil && *tag.Value == "owned" {
							results = append(results, *lb.LoadBalancerName)
						}
					}
				}
			}
		}

		return !lastPage
	}); err != nil {
		return nil, err
	}

	if describeLBErr != nil {
		return nil, describeLBErr
	}

	return results, nil
}

// The following functions are only temporary needed due to https://github.com/gardener/gardener/issues/129.

// ListKubernetesELBsV2 returns a slice of loadbalancer tuples (of types either NLB or ALB) in the given <vpcID> tagged with <clusterName>.
func (c *Client) ListKubernetesELBsV2(ctx context.Context, vpcID, clusterName string) ([]LoadBalancer, error) {
	var (
		results       []LoadBalancer
		describeLBErr error
	)

	if err := c.ELBv2.DescribeLoadBalancersPagesWithContext(ctx, &elbv2.DescribeLoadBalancersInput{}, func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
		for _, lb := range page.LoadBalancers {
			if lb.VpcId != nil && *lb.VpcId == vpcID {
				// TODO: DescribeTagsWithContext can take multiple LoadBalancers,  make just 1 call to collect all Tags
				tags, err := c.ELBv2.DescribeTagsWithContext(ctx, &elbv2.DescribeTagsInput{
					ResourceArns: []*string{lb.LoadBalancerArn},
				})
				if err != nil {
					describeLBErr = err
					return false
				}

				for _, description := range tags.TagDescriptions {
					for _, tag := range description.Tags {
						if tag.Key != nil && *tag.Key == fmt.Sprintf("kubernetes.io/cluster/%s", clusterName) && tag.Value != nil && *tag.Value == "owned" {
							results = append(results, LoadBalancer{
								Name: lb.LoadBalancerName,
								Type: lb.Type,
								Arn:  lb.LoadBalancerArn,
							})
						}
					}
				}
			}
		}

		return !lastPage
	}); err != nil {
		return nil, err
	}

	if describeLBErr != nil {
		return nil, describeLBErr
	}

	return results, nil
}

// DeleteELB deletes the loadbalancer with the specific <name>. If it does not exist,
// no error is returned.
func (c *Client) DeleteELB(ctx context.Context, name string) error {
	if _, err := c.ELB.DeleteLoadBalancerWithContext(ctx, &elb.DeleteLoadBalancerInput{LoadBalancerName: aws.String(name)}); err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == elb.ErrCodeAccessPointNotFoundException {
			return nil
		}
		return err
	}
	return nil
}

// DeleteELBV2 deletes the loadbalancer (NLB or ALB) as well as its target groups with its Amazon Resource Name (ARN) . If it does not exist,
// no error is returned.
func (c *Client) DeleteELBV2(ctx context.Context, arn *string) error {
	targetGroups, err := c.ELBv2.DescribeTargetGroups(
		&elbv2.DescribeTargetGroupsInput{LoadBalancerArn: arn},
	)
	if err != nil {
		return errors.Wrap(err, "could not list loadbalancer target groups")
	}

	if _, err := c.ELBv2.DeleteLoadBalancerWithContext(ctx, &elbv2.DeleteLoadBalancerInput{LoadBalancerArn: arn}); err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == elb.ErrCodeAccessPointNotFoundException {
			return nil
		}
		return err
	}

	for _, group := range targetGroups.TargetGroups {
		_, err := c.ELBv2.DeleteTargetGroup(
			&elbv2.DeleteTargetGroupInput{TargetGroupArn: group.TargetGroupArn},
		)
		if err != nil {
			return errors.Wrap(err, "could not delete target groups after deleting loadbalancer")
		}
	}

	return nil
}

// ListKubernetesSecurityGroups returns the list of security groups in the given <vpcID> tagged with <clusterName>.
func (c *Client) ListKubernetesSecurityGroups(ctx context.Context, vpcID, clusterName string) ([]string, error) {
	groups, err := c.EC2.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(vpcID)},
			},
			{
				Name:   aws.String("tag-key"),
				Values: []*string{aws.String(fmt.Sprintf("kubernetes.io/cluster/%s", clusterName))},
			},
			{
				Name:   aws.String("tag-value"),
				Values: []*string{aws.String("owned")},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	var results []string
	for _, group := range groups.SecurityGroups {
		results = append(results, *group.GroupId)
	}

	return results, nil
}

// DeleteSecurityGroup deletes the security group with the specific <id>. If it does not exist,
// no error is returned.
func (c *Client) DeleteSecurityGroup(ctx context.Context, id string) error {
	if _, err := c.EC2.DeleteSecurityGroupWithContext(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(id)}); err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "InvalidGroup.NotFound" {
			return nil
		}
		return err
	}
	return nil
}

// DeleteObjectsWithPrefix deletes the s3 objects with the specific <prefix> from <bucket>. If it does not exist,
// no error is returned.
func (c *Client) DeleteObjectsWithPrefix(ctx context.Context, bucket, prefix string) error {
	in := &s3.ListObjectsInput{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	var delErr error
	if err := c.S3.ListObjectsPagesWithContext(ctx, in, func(page *s3.ListObjectsOutput, lastPage bool) bool {
		objectIDs := make([]*s3.ObjectIdentifier, 0)
		for _, key := range page.Contents {
			obj := &s3.ObjectIdentifier{
				Key: key.Key,
			}
			objectIDs = append(objectIDs, obj)
		}

		if len(objectIDs) != 0 {
			if _, delErr = c.S3.DeleteObjectsWithContext(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(bucket),
				Delete: &s3.Delete{
					Objects: objectIDs,
					Quiet:   aws.Bool(true),
				},
			}); delErr != nil {
				return false
			}
		}
		return !lastPage
	}); err != nil {
		return err
	}

	if delErr != nil {
		if aerr, ok := delErr.(awserr.Error); ok && aerr.Code() == s3.ErrCodeNoSuchKey {
			return nil
		}
		return delErr
	}
	return nil
}

// CreateBucketIfNotExists creates the s3 bucket with name <bucket> in <region>. If it already exist,
// no error is returned.
func (c *Client) CreateBucketIfNotExists(ctx context.Context, bucket, region string) error {
	createBucketInput := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
		ACL:    aws.String(s3.BucketCannedACLPrivate),
		CreateBucketConfiguration: &s3.CreateBucketConfiguration{
			LocationConstraint: aws.String(region),
		},
	}

	if region == "us-east-1" {
		createBucketInput.CreateBucketConfiguration = nil
	}

	if _, err := c.S3.CreateBucketWithContext(ctx, createBucketInput); err != nil {
		if aerr, ok := err.(awserr.Error); !ok {
			return err
		} else if aerr.Code() != s3.ErrCodeBucketAlreadyExists && aerr.Code() != s3.ErrCodeBucketAlreadyOwnedByYou {
			return err
		}
	}

	// Set lifecycle rule to purge incomplete multipart upload orphaned because of force shutdown or rescheduling or networking issue with etcd-backup-restore.
	putBucketLifecycleConfigurationInput := &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
		LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
			Rules: []*s3.LifecycleRule{
				{
					// Note: Though as per documentation at https://docs.aws.amazon.com/AmazonS3/latest/API/API_LifecycleRule.html the Filter field is
					// optional, if not specified the SDK API fails with `Malformed XML` error code. Cross verified same behavior with aws-cli client as well.
					// Please do not remove it.
					Filter: &s3.LifecycleRuleFilter{
						Prefix: aws.String(""),
					},
					AbortIncompleteMultipartUpload: &s3.AbortIncompleteMultipartUpload{
						DaysAfterInitiation: aws.Int64(7),
					},
					Status: aws.String(s3.ExpirationStatusEnabled),
				},
			},
		},
	}

	_, err := c.S3.PutBucketLifecycleConfigurationWithContext(ctx, putBucketLifecycleConfigurationInput)
	return err
}

// DeleteBucketIfExists deletes the s3 bucket with name <bucket>. If it does not exist,
// no error is returned.
func (c *Client) DeleteBucketIfExists(ctx context.Context, bucket string) error {
	if _, err := c.S3.DeleteBucketWithContext(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == s3.ErrCodeNoSuchBucket {
				return nil
			}
			if aerr.Code() == errCodeBucketNotEmpty {
				if err := c.DeleteObjectsWithPrefix(ctx, bucket, ""); err != nil {
					return err
				}
				return c.DeleteBucketIfExists(ctx, bucket)
			}
		}
		return err
	}
	return nil
}
