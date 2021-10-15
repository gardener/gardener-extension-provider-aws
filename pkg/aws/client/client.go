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
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Client is a struct containing several clients for the different AWS services it needs to interact with.
// * EC2 is the standard client for the EC2 service.
// * STS is the standard client for the STS service.
// * IAM is the standard client for the IAM service.
// * S3 is the standard client for the S3 service.
// * ELB is the standard client for the ELB service.
// * ELBv2 is the standard client for the ELBv2 service.
// * Route53 is the standard client for the Route53 service.
type Client struct {
	EC2                ec2iface.EC2API
	STS                stsiface.STSAPI
	IAM                iamiface.IAMAPI
	S3                 s3iface.S3API
	ELB                elbiface.ELBAPI
	ELBv2              elbv2iface.ELBV2API
	Route53            route53iface.Route53API
	Route53RateLimiter *rate.Limiter
	Logger             logr.Logger
}

// NewInterface creates a new instance of Interface for the given AWS credentials and region.
func NewInterface(accessKeyID, secretAccessKey, region string) (Interface, error) {
	return NewClient(accessKeyID, secretAccessKey, region)
}

// NewClient creates a new Client for the given AWS credentials <accessKeyID>, <secretAccessKey>, and
// the AWS region <region>.
// It initializes the clients for the various services like EC2, ELB, etc.
func NewClient(accessKeyID, secretAccessKey, region string) (*Client, error) {
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
		EC2:                ec2.New(s, config),
		ELB:                elb.New(s, config),
		ELBv2:              elbv2.New(s, config),
		IAM:                iam.New(s, config),
		STS:                sts.New(s, config),
		S3:                 s3.New(s, config),
		Route53:            route53.New(s, config),
		Route53RateLimiter: rate.NewLimiter(rate.Inf, 0),
		Logger:             log.Log.WithName("aws-client"),
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

// GetVPCInternetGateway returns the ID of the internet gateway attached to the given VPC <vpcID>.
// If there is no internet gateway attached, the returned string will be empty.
func (c *Client) GetVPCInternetGateway(ctx context.Context, vpcID string) (string, error) {
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

	if len(describeInternetGatewaysOutput.InternetGateways) > 0 {
		return aws.StringValue(describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId), nil
	}
	return "", nil
}

// GetVPCAttribute returns the value of the specified VPC attribute.
func (c *Client) GetVPCAttribute(ctx context.Context, vpcID string, attribute string) (bool, error) {
	vpcAttribute, err := c.EC2.DescribeVpcAttributeWithContext(ctx, &ec2.DescribeVpcAttributeInput{VpcId: &vpcID, Attribute: aws.String(attribute)})
	if err != nil {
		return false, err
	}

	switch attribute {
	case "enableDnsSupport":
		return vpcAttribute.EnableDnsSupport != nil && vpcAttribute.EnableDnsSupport.Value != nil && *vpcAttribute.EnableDnsSupport.Value, nil
	case "enableDnsHostnames":
		return vpcAttribute.EnableDnsHostnames != nil && vpcAttribute.EnableDnsHostnames.Value != nil && *vpcAttribute.EnableDnsHostnames.Value, nil
	default:
		return false, nil
	}
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

	// Enable default server side encryption using AES256 algorithm. Key will be managed by S3
	if _, err := c.S3.PutBucketEncryptionWithContext(ctx, &s3.PutBucketEncryptionInput{
		Bucket: aws.String(bucket),
		ServerSideEncryptionConfiguration: &s3.ServerSideEncryptionConfiguration{
			Rules: []*s3.ServerSideEncryptionRule{
				{
					ApplyServerSideEncryptionByDefault: &s3.ServerSideEncryptionByDefault{
						SSEAlgorithm: aws.String("AES256"),
					},
				},
			},
		},
	}); err != nil {
		return err
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

// The following functions are only temporary needed due to https://github.com/gardener/gardener/issues/129.

// ListKubernetesELBs returns the list of ELB loadbalancers in the given <vpcID> tagged with <clusterName>.
func (c *Client) ListKubernetesELBs(ctx context.Context, vpcID, clusterName string) ([]string, error) {
	var (
		loadBalancerNamesInVPC      []*string
		loadBalancerNamesForCluster []string
	)

	if err := c.ELB.DescribeLoadBalancersPagesWithContext(ctx, &elb.DescribeLoadBalancersInput{}, func(page *elb.DescribeLoadBalancersOutput, lastPage bool) bool {
		for _, lb := range page.LoadBalancerDescriptions {
			if lb.VPCId != nil && *lb.VPCId == vpcID {
				loadBalancerNamesInVPC = append(loadBalancerNamesInVPC, lb.LoadBalancerName)
			}
		}
		return !lastPage
	}); err != nil {
		return nil, err
	}

	if len(loadBalancerNamesInVPC) == 0 {
		return nil, nil
	}

	const chunkSize = 20
	loadBalancerNamesChunks := chunkSlice(loadBalancerNamesInVPC, chunkSize)
	for _, loadBalancerNamesChunk := range loadBalancerNamesChunks {
		tags, err := c.ELB.DescribeTagsWithContext(ctx, &elb.DescribeTagsInput{LoadBalancerNames: loadBalancerNamesChunk})
		if err != nil {
			return nil, err
		}

		for _, description := range tags.TagDescriptions {
			for _, tag := range description.Tags {
				if tag.Key != nil && *tag.Key == fmt.Sprintf("kubernetes.io/cluster/%s", clusterName) &&
					tag.Value != nil && *tag.Value == "owned" &&
					description.LoadBalancerName != nil {
					loadBalancerNamesForCluster = append(loadBalancerNamesForCluster, *description.LoadBalancerName)
					break
				}
			}
		}
	}

	return loadBalancerNamesForCluster, nil
}

// DeleteELB deletes the loadbalancer with the specific <name>. If it does not exist,
// no error is returned.
func (c *Client) DeleteELB(ctx context.Context, name string) error {
	_, err := c.ELB.DeleteLoadBalancerWithContext(ctx, &elb.DeleteLoadBalancerInput{LoadBalancerName: aws.String(name)})
	return ignoreNotFound(err)
}

// ListKubernetesELBsV2 returns the list of ELBv2 loadbalancers in the given <vpcID> tagged with <clusterName>.
func (c *Client) ListKubernetesELBsV2(ctx context.Context, vpcID, clusterName string) ([]string, error) {
	var (
		loadBalancerARNsInVPC      []*string
		loadBalancerARNsForCluster []string
	)

	if err := c.ELBv2.DescribeLoadBalancersPagesWithContext(ctx, &elbv2.DescribeLoadBalancersInput{}, func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
		for _, lb := range page.LoadBalancers {
			if lb.VpcId != nil && *lb.VpcId == vpcID {
				loadBalancerARNsInVPC = append(loadBalancerARNsInVPC, lb.LoadBalancerArn)
			}
		}
		return !lastPage
	}); err != nil {
		return nil, err
	}

	if len(loadBalancerARNsInVPC) == 0 {
		return nil, nil
	}

	const chunkSize = 20
	loadBalancerARNsChunks := chunkSlice(loadBalancerARNsInVPC, chunkSize)
	for _, loadBalancerARNsChunk := range loadBalancerARNsChunks {
		tags, err := c.ELBv2.DescribeTagsWithContext(ctx, &elbv2.DescribeTagsInput{ResourceArns: loadBalancerARNsChunk})
		if err != nil {
			return nil, err
		}

		for _, description := range tags.TagDescriptions {
			for _, tag := range description.Tags {
				if tag.Key != nil && *tag.Key == fmt.Sprintf("kubernetes.io/cluster/%s", clusterName) &&
					tag.Value != nil && *tag.Value == "owned" &&
					description.ResourceArn != nil {
					loadBalancerARNsForCluster = append(loadBalancerARNsForCluster, *description.ResourceArn)
				}
			}
		}
	}

	return loadBalancerARNsForCluster, nil
}

// DeleteELBV2 deletes the loadbalancer (NLB or ALB) as well as its target groups with its Amazon Resource Name (ARN). If it does not exist,
// no error is returned.
func (c *Client) DeleteELBV2(ctx context.Context, arn string) error {
	targetGroups, err := c.ELBv2.DescribeTargetGroups(&elbv2.DescribeTargetGroupsInput{LoadBalancerArn: &arn})
	if err != nil {
		return fmt.Errorf("could not list loadbalancer target groups for arn %s: %w", arn, err)
	}

	if _, err := c.ELBv2.DeleteLoadBalancerWithContext(ctx, &elbv2.DeleteLoadBalancerInput{LoadBalancerArn: &arn}); ignoreNotFound(err) != nil {
		return fmt.Errorf("could not delete loadbalancer for arn %s: %w", arn, err)
	}

	for _, group := range targetGroups.TargetGroups {
		if _, err := c.ELBv2.DeleteTargetGroup(&elbv2.DeleteTargetGroupInput{TargetGroupArn: group.TargetGroupArn}); err != nil {
			return fmt.Errorf("could not delete target groups after deleting loadbalancer for arn %s: %w", arn, err)
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

// DeleteSecurityGroup deletes the security group with the specific <id>. If it does not exist, no error is returned.
func (c *Client) DeleteSecurityGroup(ctx context.Context, id string) error {
	_, err := c.EC2.DeleteSecurityGroupWithContext(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(id)})
	return ignoreNotFound(err)
}

// IsNotFoundError returns true if the given error is a awserr.Error indicating that a AWS resource was not found.
func IsNotFoundError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && (aerr.Code() == elb.ErrCodeAccessPointNotFoundException || aerr.Code() == "InvalidGroup.NotFound" || aerr.Code() == "InvalidVpcID.NotFound") {
		return true
	}
	return false
}

func ignoreNotFound(err error) error {
	if err == nil || IsNotFoundError(err) {
		return nil
	}
	return err
}

func chunkSlice(slice []*string, chunkSize int) [][]*string {
	var chunks [][]*string
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}
