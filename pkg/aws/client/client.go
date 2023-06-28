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
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/pointer"
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
	EC2                           ec2iface.EC2API
	STS                           stsiface.STSAPI
	IAM                           iamiface.IAMAPI
	S3                            s3iface.S3API
	ELB                           elbiface.ELBAPI
	ELBv2                         elbv2iface.ELBV2API
	Route53                       route53iface.Route53API
	Route53RateLimiter            *rate.Limiter
	Route53RateLimiterWaitTimeout time.Duration
	Logger                        logr.Logger
	PollInterval                  time.Duration
}

var _ Interface = &Client{}

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
		EC2:                           ec2.New(s, config),
		ELB:                           elb.New(s, config),
		ELBv2:                         elbv2.New(s, config),
		IAM:                           iam.New(s, config),
		STS:                           sts.New(s, config),
		S3:                            s3.New(s, config),
		Route53:                       route53.New(s, config),
		Route53RateLimiter:            rate.NewLimiter(rate.Inf, 0),
		Route53RateLimiterWaitTimeout: 1 * time.Second,
		Logger:                        log.Log.WithName("aws-client"),
		PollInterval:                  5 * time.Second,
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
		return "", ignoreNotFound(err)
	}

	if len(describeInternetGatewaysOutput.InternetGateways) > 0 {
		return aws.StringValue(describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId), nil
	}
	return "", nil
}

// GetElasticIPsAssociationIDForAllocationIDs list existing elastic IP addresses for the given allocationIDs.
// returns a map[elasticIPAllocationID]elasticIPAssociationID or an error
func (c *Client) GetElasticIPsAssociationIDForAllocationIDs(ctx context.Context, allocationIDs []string) (map[string]*string, error) {
	describeAddressesInput := &ec2.DescribeAddressesInput{
		AllocationIds: aws.StringSlice(allocationIDs),
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("domain"),
				Values: aws.StringSlice([]string{"vpc"}),
			},
		},
	}

	describeAddressesOutput, err := c.EC2.DescribeAddressesWithContext(ctx, describeAddressesInput)
	if err != nil {
		return nil, ignoreNotFound(err)
	}

	if len(describeAddressesOutput.Addresses) == 0 {
		return nil, nil
	}

	result := make(map[string]*string, len(describeAddressesOutput.Addresses))
	for _, addr := range describeAddressesOutput.Addresses {
		if addr.AllocationId == nil {
			continue
		}
		result[*addr.AllocationId] = addr.AssociationId
	}

	return result, nil
}

// GetNATGatewayAddressAllocations get the allocation IDs for the NAT Gateway addresses for each existing NAT Gateway in the vpc
// returns a slice of allocation IDs or an error
func (c *Client) GetNATGatewayAddressAllocations(ctx context.Context, shootNamespace string) (sets.Set[string], error) {
	describeAddressesInput := &ec2.DescribeNatGatewaysInput{
		Filter: []*ec2.Filter{{
			Name: aws.String(fmt.Sprintf("tag:kubernetes.io/cluster/%s", shootNamespace)),
			Values: []*string{
				aws.String("1"),
			},
		}},
	}

	describeNatGatewaysOutput, err := c.EC2.DescribeNatGatewaysWithContext(ctx, describeAddressesInput)
	if err != nil {
		return nil, ignoreNotFound(err)
	}

	result := sets.New[string]()
	if len(describeNatGatewaysOutput.NatGateways) == 0 {
		return result, nil
	}

	for _, natGateway := range describeNatGatewaysOutput.NatGateways {
		if natGateway.NatGatewayAddresses == nil || len(natGateway.NatGatewayAddresses) == 0 {
			continue
		}

		// add all allocation IDS for the addresses for this NAT Gateway
		// these are the allocation IDS which identify the associated EIP
		for _, address := range natGateway.NatGatewayAddresses {
			if address == nil {
				continue
			}
			result.Insert(*address.AllocationId)
		}
	}

	return result, nil
}

// GetVPCAttribute returns the value of the specified VPC attribute.
func (c *Client) GetVPCAttribute(ctx context.Context, vpcID string, attribute string) (bool, error) {
	vpcAttribute, err := c.EC2.DescribeVpcAttributeWithContext(ctx, &ec2.DescribeVpcAttributeInput{VpcId: &vpcID, Attribute: aws.String(attribute)})
	if err != nil {
		return false, ignoreNotFound(err)
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

// GetDHCPOptions returns DHCP options for the specified VPC ID.
func (c *Client) GetDHCPOptions(ctx context.Context, vpcID string) (map[string]string, error) {
	describeVpcsInput := &ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("vpc-id"),
				Values: []*string{
					aws.String(vpcID),
				},
			},
		},
	}

	describeVpcsOutput, err := c.EC2.DescribeVpcsWithContext(ctx, describeVpcsInput)
	if err != nil {
		return nil, err
	}
	if len(describeVpcsOutput.Vpcs) == 0 {
		return nil, fmt.Errorf("could not find VPC %s", vpcID)
	}
	if describeVpcsOutput.Vpcs[0].DhcpOptionsId == nil {
		return nil, nil
	}

	describeDhcpOptionsInput := &ec2.DescribeDhcpOptionsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("dhcp-options-id"),
				Values: []*string{
					aws.String(*describeVpcsOutput.Vpcs[0].DhcpOptionsId),
				},
			},
		},
	}
	describeDhcpOptionsOutput, err := c.EC2.DescribeDhcpOptionsWithContext(ctx, describeDhcpOptionsInput)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	if len(describeDhcpOptionsOutput.DhcpOptions) > 0 {
		for _, dhcpConfiguration := range describeDhcpOptionsOutput.DhcpOptions[0].DhcpConfigurations {
			if dhcpConfiguration.Key != nil && *dhcpConfiguration.Key == "domain-name" && len(dhcpConfiguration.Values) > 0 && dhcpConfiguration.Values[0].Value != nil {
				result[*dhcpConfiguration.Key] = *dhcpConfiguration.Values[0].Value
			}
		}
	}
	return result, nil
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

// CreateBucketIfNotExists creates the s3 bucket with name <bucket> in <region>. If it already exists,
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

	// Block public access to the bucket
	if _, err := c.S3.PutPublicAccessBlockWithContext(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(bucket),
		PublicAccessBlockConfiguration: &s3.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	}); err != nil {
		return err
	}

	// Handle bucket policy IAM ARN for different partitions (AWS region groups)
	// Different available partitions in AWS are defined at
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
	arnPartition := "aws"
	if strings.HasPrefix(region, "cn-") {
		arnPartition = "aws-cn" // China regions
	} else if strings.HasPrefix(region, "us-gov-") {
		arnPartition = "aws-us-gov" // AWS GovCloud (US) regions
	}

	// Set bucket policy to deny non-HTTPS requests
	bucketPolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect":    "Deny",
				"Principal": "*",
				"Action":    "s3:*",
				"Resource": []string{
					fmt.Sprintf("arn:%s:s3:::%s", arnPartition, bucket),
					fmt.Sprintf("arn:%s:s3:::%s/*", arnPartition, bucket),
				},
				"Condition": map[string]interface{}{
					"Bool": map[string]string{
						"aws:SecureTransport": "false",
					},
					"NumericLessThan": map[string]string{
						"s3:TlsVersion": "1.2",
					},
				},
			},
		},
	}

	bucketPolicyJSON, err := json.Marshal(bucketPolicy)
	if err != nil {
		return err
	}

	if _, err := c.S3.PutBucketPolicyWithContext(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucket),
		Policy: aws.String(string(bucketPolicyJSON)),
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

	_, err = c.S3.PutBucketLifecycleConfigurationWithContext(ctx, putBucketLifecycleConfigurationInput)
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
				Values: aws.StringSlice([]string{vpcID}),
			},
			{
				Name:   aws.String("tag-key"),
				Values: aws.StringSlice([]string{fmt.Sprintf("kubernetes.io/cluster/%s", clusterName)}),
			},
			{
				Name:   aws.String("tag-value"),
				Values: aws.StringSlice([]string{"owned"}),
			},
		},
	})
	if err != nil {
		return nil, ignoreNotFound(err)
	}

	var results []string
	for _, group := range groups.SecurityGroups {
		results = append(results, *group.GroupId)
	}

	return results, nil
}

// CreateVpcDhcpOptions creates a DHCP option resource.
func (c *Client) CreateVpcDhcpOptions(ctx context.Context, options *DhcpOptions) (*DhcpOptions, error) {
	var newConfigs []*ec2.NewDhcpConfiguration

	for key, values := range options.DhcpConfigurations {
		newConfigs = append(newConfigs, &ec2.NewDhcpConfiguration{
			Key:    aws.String(key),
			Values: aws.StringSlice(values),
		})
	}
	input := &ec2.CreateDhcpOptionsInput{
		DhcpConfigurations: newConfigs,
		TagSpecifications:  options.ToTagSpecifications(ec2.ResourceTypeDhcpOptions),
	}
	output, err := c.EC2.CreateDhcpOptionsWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return fromDhcpOptions(output.DhcpOptions), nil
}

// GetVpcDhcpOptions gets a DHCP option resource by identifier.
func (c *Client) GetVpcDhcpOptions(ctx context.Context, id string) (*DhcpOptions, error) {
	input := &ec2.DescribeDhcpOptionsInput{DhcpOptionsIds: aws.StringSlice([]string{id})}
	output, err := c.describeVpcDhcpOptions(ctx, input)
	return single(output, err)
}

// FindVpcDhcpOptionsByTags finds DHCP option resources matching the given tag map.
func (c *Client) FindVpcDhcpOptionsByTags(ctx context.Context, tags Tags) ([]*DhcpOptions, error) {
	input := &ec2.DescribeDhcpOptionsInput{Filters: tags.ToFilters()}
	return c.describeVpcDhcpOptions(ctx, input)
}

func (c *Client) describeVpcDhcpOptions(ctx context.Context, input *ec2.DescribeDhcpOptionsInput) ([]*DhcpOptions, error) {
	output, err := c.EC2.DescribeDhcpOptionsWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var options []*DhcpOptions
	for _, item := range output.DhcpOptions {
		options = append(options, fromDhcpOptions(item))
	}
	return options, nil
}

// DeleteVpcDhcpOptions deletes a DHCP option resource by identifier.
// Returns nil, if the resource is not found.
func (c *Client) DeleteVpcDhcpOptions(ctx context.Context, id string) error {
	_, err := c.EC2.DeleteDhcpOptionsWithContext(ctx, &ec2.DeleteDhcpOptionsInput{DhcpOptionsId: aws.String(id)})
	return ignoreNotFound(err)
}

// CreateVpc creates a VPC resource.
func (c *Client) CreateVpc(ctx context.Context, desired *VPC) (*VPC, error) {
	input := &ec2.CreateVpcInput{
		CidrBlock:                   aws.String(desired.CidrBlock),
		AmazonProvidedIpv6CidrBlock: aws.Bool(desired.AssignGeneratedIPv6CidrBlock),
		TagSpecifications:           desired.ToTagSpecifications(ec2.ResourceTypeVpc),
	}
	output, err := c.EC2.CreateVpc(input)
	if err != nil {
		return nil, err
	}
	vpcID := *output.Vpc.VpcId
	if desired.AssignGeneratedIPv6CidrBlock {
		// Custom waiting loop
		waitInput := &ec2.DescribeVpcsInput{
			VpcIds: []*string{aws.String(vpcID)},
		}
		var ipv6CidrBlock string
		maxRetries := 30
		waitInterval := 10 * time.Second
		for i := 0; i < maxRetries; i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitInterval):
				resp, err := c.EC2.DescribeVpcs(waitInput)
				if err != nil {
					return nil, fmt.Errorf("error describing VPC: %v", err)
				}

				if len(resp.Vpcs) > 0 {
					for _, assoc := range resp.Vpcs[0].Ipv6CidrBlockAssociationSet {
						if assoc != nil && aws.StringValue(assoc.Ipv6CidrBlockState.State) == "associated" {
							ipv6CidrBlock = *assoc.Ipv6CidrBlock
							vpc, err := c.GetVpc(ctx, vpcID)
							if err != nil {
								return nil, err
							}
							vpc.IPv6CidrBlock = ipv6CidrBlock
							return vpc, nil
						}
					}
				}
			}
		}
		return nil, fmt.Errorf("No IPv6 CIDR Block was assigned to VPC")
	}
	return c.GetVpc(ctx, vpcID)
}

// UpdateVpcAttribute sets/updates a VPC attribute if needed.
// Supported attribute names are
// `enableDnsSupport` (const ec2.VpcAttributeNameEnableDnsSupport) and
// `enableDnsHostnames` (const ec2.VpcAttributeNameEnableDnsHostnames) and
func (c *Client) UpdateVpcAttribute(ctx context.Context, vpcId, attributeName string, value bool) error {
	switch attributeName {
	case ec2.VpcAttributeNameEnableDnsSupport:
		input := &ec2.ModifyVpcAttributeInput{
			EnableDnsSupport: &ec2.AttributeBooleanValue{
				Value: aws.Bool(value),
			},
			VpcId: aws.String(vpcId),
		}
		if _, err := c.EC2.ModifyVpcAttribute(input); err != nil {
			return err
		}
		if err := c.PollImmediateUntil(ctx, func(ctx context.Context) (bool, error) {
			b, err := c.describeVpcAttributeWithContext(ctx, aws.String(vpcId), ec2.VpcAttributeNameEnableDnsSupport)
			return b == value, err
		}); err != nil {
			return err
		}
		return nil
	case ec2.VpcAttributeNameEnableDnsHostnames:
		input := &ec2.ModifyVpcAttributeInput{
			EnableDnsHostnames: &ec2.AttributeBooleanValue{
				Value: aws.Bool(value),
			},
			VpcId: aws.String(vpcId),
		}
		if _, err := c.EC2.ModifyVpcAttribute(input); err != nil {
			return err
		}
		if err := c.PollImmediateUntil(ctx, func(ctx context.Context) (bool, error) {
			b, err := c.describeVpcAttributeWithContext(ctx, aws.String(vpcId), ec2.VpcAttributeNameEnableDnsHostnames)
			return b == value, err
		}); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown attribute name: %s", attributeName)
	}
}

// CheckVpcIPv6Cidr checks if the vpc has an IPv6 CIDR block assigned
func (c *Client) CheckVpcIPv6Cidr(vpcID string) (bool, error) {
	input := &ec2.DescribeVpcsInput{
		VpcIds: []*string{
			aws.String(vpcID),
		},
	}
	output, err := c.EC2.DescribeVpcs(input)
	if err != nil {
		return false, err
	}
	if len(output.Vpcs) == 0 {
		return false, fmt.Errorf("VPC not found")
	}
	vpc := output.Vpcs[0]
	for _, cidr := range vpc.Ipv6CidrBlockAssociationSet {
		if *cidr.Ipv6CidrBlockState.State == "associated" {
			return true, nil
		}
	}
	return false, nil
}

// UpdateAmazonProvidedIPv6CidrBlock sets/updates the amazon provided IPv6 blocks.
func (c *Client) UpdateAmazonProvidedIPv6CidrBlock(ctx context.Context, desired *VPC, current *VPC) (string, bool, error) {
	ipv6CidrBlock := ""
	modified := false
	if current.VpcId != "" && (desired.AssignGeneratedIPv6CidrBlock != current.AssignGeneratedIPv6CidrBlock) {
		ipv6CidrBlockAssociated, err := c.CheckVpcIPv6Cidr(current.VpcId)
		if err != nil {
			return ipv6CidrBlock, modified, err
		}
		if !ipv6CidrBlockAssociated {

			input := &ec2.AssociateVpcCidrBlockInput{
				VpcId: aws.String(current.VpcId),
			}
			input.AmazonProvidedIpv6CidrBlock = aws.Bool(desired.AssignGeneratedIPv6CidrBlock)
			_, err := c.EC2.AssociateVpcCidrBlockWithContext(ctx, input)
			if err != nil {
				return ipv6CidrBlock, modified, err
			}
			modified = true
			// Custom waiting loop
			waitInput := &ec2.DescribeVpcsInput{
				VpcIds: []*string{aws.String(current.VpcId)},
			}
			maxRetries := 30
			waitInterval := 10 * time.Second
			for i := 0; i < maxRetries; i++ {
				select {
				case <-ctx.Done():
					return ipv6CidrBlock, modified, ctx.Err()
				case <-time.After(waitInterval):
					resp, err := c.EC2.DescribeVpcs(waitInput)
					if err != nil {
						return ipv6CidrBlock, modified, fmt.Errorf("error describing VPC: %v", err)
					}

					if len(resp.Vpcs) > 0 {
						for _, assoc := range resp.Vpcs[0].Ipv6CidrBlockAssociationSet {
							if assoc != nil && aws.StringValue(assoc.Ipv6CidrBlockState.State) == "associated" {
								ipv6CidrBlock = *assoc.Ipv6CidrBlock
								return ipv6CidrBlock, modified, nil
							}
						}
					}
				}
			}
			return ipv6CidrBlock, modified, fmt.Errorf("No IPv6 CIDR Block was assigned to VPC")
		}
	}
	return ipv6CidrBlock, modified, nil
}

// AddVpcDhcpOptionAssociation associates existing DHCP options resource to VPC resource, both identified by id.
func (c *Client) AddVpcDhcpOptionAssociation(vpcId string, dhcpOptionsId *string) error {
	if dhcpOptionsId == nil {
		// AWS does not provide an API to disassociate a DHCP Options set from a VPC.
		// So, we do this by setting the VPC to the default DHCP Options Set.
		dhcpOptionsId = aws.String("default")
	}
	_, err := c.EC2.AssociateDhcpOptions(&ec2.AssociateDhcpOptionsInput{
		DhcpOptionsId: dhcpOptionsId,
		VpcId:         aws.String(vpcId),
	})
	return err
}

// DeleteVpc deletes a VPC resource by identifier.
// Returns nil, if the resource is not found.
func (c *Client) DeleteVpc(ctx context.Context, id string) error {
	_, err := c.EC2.DeleteVpcWithContext(ctx, &ec2.DeleteVpcInput{VpcId: aws.String(id)})
	return ignoreNotFound(err)
}

// GetVpc gets a VPC resource by identifier.
// Returns nil, if the resource is not found.
func (c *Client) GetVpc(ctx context.Context, id string) (*VPC, error) {
	input := &ec2.DescribeVpcsInput{VpcIds: aws.StringSlice([]string{id})}
	output, err := c.describeVpcs(ctx, input)
	return single(output, err)
}

// FindVpcsByTags finds VPC resources matching the given tag map.
func (c *Client) FindVpcsByTags(ctx context.Context, tags Tags) ([]*VPC, error) {
	input := &ec2.DescribeVpcsInput{Filters: tags.ToFilters()}
	return c.describeVpcs(ctx, input)
}

func (c *Client) describeVpcs(ctx context.Context, input *ec2.DescribeVpcsInput) ([]*VPC, error) {
	output, err := c.EC2.DescribeVpcs(input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var vpcList []*VPC
	for _, item := range output.Vpcs {
		vpc, err := c.fromVpc(ctx, item, true)
		if err != nil {
			return nil, err
		}
		vpcList = append(vpcList, vpc)
	}
	return vpcList, nil
}

func (c *Client) fromVpc(ctx context.Context, item *ec2.Vpc, withAttributes bool) (*VPC, error) {
	vpc := &VPC{
		VpcId:     aws.StringValue(item.VpcId),
		Tags:      FromTags(item.Tags),
		CidrBlock: aws.StringValue(item.CidrBlock),
		IPv6CidrBlock: func() string {
			if item.Ipv6CidrBlockAssociationSet != nil {
				return aws.StringValue(item.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock)
			}
			return ""
		}(),
		DhcpOptionsId:   item.DhcpOptionsId,
		InstanceTenancy: item.InstanceTenancy,
		State:           item.State,
	}
	var err error
	if withAttributes {
		if vpc.EnableDnsHostnames, err = c.describeVpcAttributeWithContext(ctx, item.VpcId, ec2.VpcAttributeNameEnableDnsHostnames); err != nil {
			return nil, err
		}
		if vpc.EnableDnsSupport, err = c.describeVpcAttributeWithContext(ctx, item.VpcId, ec2.VpcAttributeNameEnableDnsSupport); err != nil {
			return nil, err
		}
	}
	return vpc, nil
}

func (c *Client) describeVpcAttributeWithContext(ctx context.Context, vpcId *string, attributeName string) (bool, error) {
	output, err := c.EC2.DescribeVpcAttributeWithContext(ctx, &ec2.DescribeVpcAttributeInput{
		Attribute: aws.String(attributeName),
		VpcId:     vpcId,
	})
	if err != nil {
		return false, ignoreNotFound(err)
	}
	switch attributeName {
	case ec2.VpcAttributeNameEnableDnsHostnames:
		return *output.EnableDnsHostnames.Value, nil
	case ec2.VpcAttributeNameEnableDnsSupport:
		return *output.EnableDnsSupport.Value, nil
	default:
		return false, fmt.Errorf("unknown attribute: %s", attributeName)
	}
}

// CreateSecurityGroup creates a security group. Note that the rules of the input object are ignored.
// Use the AuthorizeSecurityGroupRules method to add rules.
func (c *Client) CreateSecurityGroup(ctx context.Context, sg *SecurityGroup) (*SecurityGroup, error) {
	input := &ec2.CreateSecurityGroupInput{
		GroupName:         aws.String(sg.GroupName),
		TagSpecifications: sg.ToTagSpecifications(ec2.ResourceTypeSecurityGroup),
		VpcId:             sg.VpcId,
		Description:       sg.Description,
	}
	output, err := c.EC2.CreateSecurityGroupWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	created := *sg
	created.Rules = nil
	created.GroupId = *output.GroupId
	return &created, nil
}

// AuthorizeSecurityGroupRules adds security group rules for the security group identified by the groupId.
func (c *Client) AuthorizeSecurityGroupRules(ctx context.Context, groupId string, rules []*SecurityGroupRule) error {
	ingressPermissions, egressPermissions, err := c.prepareRules(groupId, rules)
	if err != nil {
		return err
	}
	if len(ingressPermissions) > 0 {
		input := &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(groupId),
			IpPermissions: ingressPermissions,
		}
		if _, err := c.EC2.AuthorizeSecurityGroupIngressWithContext(ctx, input); err != nil {
			return err
		}
	}
	if len(egressPermissions) > 0 {
		input := &ec2.AuthorizeSecurityGroupEgressInput{
			GroupId:       aws.String(groupId),
			IpPermissions: egressPermissions,
		}
		if _, err := c.EC2.AuthorizeSecurityGroupEgressWithContext(ctx, input); err != nil {
			return err
		}
	}
	return nil
}

// RevokeSecurityGroupRules removes security group rules for the security group identified by the groupId.
func (c *Client) RevokeSecurityGroupRules(ctx context.Context, groupId string, rules []*SecurityGroupRule) error {
	ingressPermissions, egressPermissions, err := c.prepareRules(groupId, rules)
	if err != nil {
		return err
	}
	if len(ingressPermissions) > 0 {
		input := &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(groupId),
			IpPermissions: ingressPermissions,
		}
		if _, err := c.EC2.RevokeSecurityGroupIngressWithContext(ctx, input); err != nil {
			return err
		}
	}
	if len(egressPermissions) > 0 {
		input := &ec2.RevokeSecurityGroupEgressInput{
			GroupId:       aws.String(groupId),
			IpPermissions: egressPermissions,
		}
		if _, err := c.EC2.RevokeSecurityGroupEgressWithContext(ctx, input); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) prepareRules(groupId string, rules []*SecurityGroupRule) (ingressPermissions, egressPermissions []*ec2.IpPermission, err error) {
	for _, rule := range rules {
		var ipPerm *ec2.IpPermission
		if rule.Foreign != nil {
			ipPerm = &ec2.IpPermission{}
			if err = json.Unmarshal([]byte(*rule.Foreign), ipPerm); err != nil {
				return
			}
		} else {
			ipPerm = &ec2.IpPermission{
				IpProtocol:       aws.String(rule.Protocol),
				IpRanges:         nil,
				PrefixListIds:    nil,
				UserIdGroupPairs: nil,
			}
			if rule.FromPort != 0 {
				ipPerm.FromPort = aws.Int64(int64(rule.FromPort))
			}
			if rule.ToPort != 0 {
				ipPerm.ToPort = aws.Int64(int64(rule.ToPort))
			}
			for _, block := range rule.CidrBlocks {
				ipPerm.IpRanges = append(ipPerm.IpRanges, &ec2.IpRange{CidrIp: aws.String(block)})
			}
			if rule.Self {
				ipPerm.UserIdGroupPairs = []*ec2.UserIdGroupPair{
					{GroupId: aws.String(groupId)},
				}
			}
		}
		switch rule.Type {
		case SecurityGroupRuleTypeIngress:
			ingressPermissions = append(ingressPermissions, ipPerm)
		case SecurityGroupRuleTypeEgress:
			egressPermissions = append(egressPermissions, ipPerm)
		default:
			err = fmt.Errorf("unknown security group rule type: %s", rule.Type)
			return
		}
	}
	return
}

// GetSecurityGroup gets a security group by identifier. Ingress and egress rules are fetched, too.
func (c *Client) GetSecurityGroup(ctx context.Context, id string) (*SecurityGroup, error) {
	input := &ec2.DescribeSecurityGroupsInput{GroupIds: aws.StringSlice([]string{id})}
	output, err := c.describeSecurityGroups(ctx, input)
	return single(output, err)
}

// FindSecurityGroupsByTags finds security group matching the given tag map.
// Ingress and egress rules are fetched, too.
func (c *Client) FindSecurityGroupsByTags(ctx context.Context, tags Tags) ([]*SecurityGroup, error) {
	input := &ec2.DescribeSecurityGroupsInput{Filters: tags.ToFilters()}
	return c.describeSecurityGroups(ctx, input)
}

func (c *Client) describeSecurityGroups(ctx context.Context, input *ec2.DescribeSecurityGroupsInput) ([]*SecurityGroup, error) {
	output, err := c.EC2.DescribeSecurityGroupsWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var sgList []*SecurityGroup
	for _, item := range output.SecurityGroups {
		sg := &SecurityGroup{
			Tags:        FromTags(item.Tags),
			GroupId:     aws.StringValue(item.GroupId),
			GroupName:   aws.StringValue(item.GroupName),
			VpcId:       item.VpcId,
			Description: item.Description,
		}
		for _, ipPerm := range item.IpPermissions {
			rule, err := fromIpPermission(aws.StringValue(item.GroupId), ipPerm, SecurityGroupRuleTypeIngress)
			if err != nil {
				return nil, err
			}
			sg.Rules = append(sg.Rules, rule)
		}
		for _, ipPerm := range item.IpPermissionsEgress {
			rule, err := fromIpPermission(aws.StringValue(item.GroupId), ipPerm, SecurityGroupRuleTypeEgress)
			if err != nil {
				return nil, err
			}
			sg.Rules = append(sg.Rules, rule)
		}
		sgList = append(sgList, sg)
	}
	return sgList, nil
}

// FindDefaultSecurityGroupByVpcId finds the default security group for the given VPC identifier.
func (c *Client) FindDefaultSecurityGroupByVpcId(ctx context.Context, vpcId string) (*SecurityGroup, error) {
	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{Name: aws.String("vpc-id"), Values: aws.StringSlice([]string{vpcId})},
		},
	}
	groups, err := c.describeSecurityGroups(ctx, input)
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if group.GroupName == "default" {
			return group, nil
		}
	}
	return nil, nil
}

// DeleteSecurityGroup deletes a security group resource by identifier.
// Returns nil, if the resource is not found.
func (c *Client) DeleteSecurityGroup(ctx context.Context, id string) error {
	_, err := c.EC2.DeleteSecurityGroupWithContext(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(id)})
	return ignoreNotFound(err)
}

// CreateInternetGateway creates an internet gateway.
func (c *Client) CreateInternetGateway(ctx context.Context, gateway *InternetGateway) (*InternetGateway, error) {
	input := &ec2.CreateInternetGatewayInput{
		TagSpecifications: gateway.ToTagSpecifications(ec2.ResourceTypeInternetGateway),
	}
	output, err := c.EC2.CreateInternetGatewayWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return &InternetGateway{
		Tags:              FromTags(output.InternetGateway.Tags),
		InternetGatewayId: aws.StringValue(output.InternetGateway.InternetGatewayId),
	}, nil
}

// AttachInternetGateway attaches an internet gateway to a VPC.
// Returns no error, if the internet gateway is already attached to the VPC.
func (c *Client) AttachInternetGateway(ctx context.Context, vpcId, internetGatewayId string) error {
	input := &ec2.AttachInternetGatewayInput{
		InternetGatewayId: aws.String(internetGatewayId),
		VpcId:             aws.String(vpcId),
	}
	_, err := c.EC2.AttachInternetGatewayWithContext(ctx, input)
	return ignoreAlreadyAssociated(err)
}

// DetachInternetGateway detaches an internet gateway to a VPC.
// Returns no error, if the internet gateway is already detached.
func (c *Client) DetachInternetGateway(ctx context.Context, vpcId, internetGatewayId string) error {
	input := &ec2.DetachInternetGatewayInput{
		InternetGatewayId: aws.String(internetGatewayId),
		VpcId:             aws.String(vpcId),
	}
	_, err := c.EC2.DetachInternetGatewayWithContext(ctx, input)
	return err
}

// GetInternetGateway gets an internet gateway resource by identifier.
func (c *Client) GetInternetGateway(ctx context.Context, id string) (*InternetGateway, error) {
	input := &ec2.DescribeInternetGatewaysInput{InternetGatewayIds: aws.StringSlice([]string{id})}
	output, err := c.describeInternetGateways(ctx, input)
	return single(output, err)
}

// FindInternetGatewaysByTags finds internet gateway resources matching the given tag map.
func (c *Client) FindInternetGatewaysByTags(ctx context.Context, tags Tags) ([]*InternetGateway, error) {
	input := &ec2.DescribeInternetGatewaysInput{Filters: tags.ToFilters()}
	return c.describeInternetGateways(ctx, input)
}

// FindInternetGatewayByVPC finds an internet gateway resource attached to the given VPC.
func (c *Client) FindInternetGatewayByVPC(ctx context.Context, vpcId string) (*InternetGateway, error) {
	input := &ec2.DescribeInternetGatewaysInput{Filters: []*ec2.Filter{{
		Name:   aws.String("attachment.vpc-id"),
		Values: aws.StringSlice([]string{vpcId}),
	}}}
	output, err := c.describeInternetGateways(ctx, input)
	return single(output, err)
}

func (c *Client) describeInternetGateways(ctx context.Context, input *ec2.DescribeInternetGatewaysInput) ([]*InternetGateway, error) {
	output, err := c.EC2.DescribeInternetGatewaysWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var gateways []*InternetGateway
	for _, item := range output.InternetGateways {
		gw := &InternetGateway{
			Tags:              FromTags(item.Tags),
			InternetGatewayId: aws.StringValue(item.InternetGatewayId),
		}
		for _, attachment := range item.Attachments {
			gw.VpcId = attachment.VpcId
			break
		}
		gateways = append(gateways, gw)
	}
	return gateways, nil
}

// DeleteInternetGateway deletes an internet gateway resource.
// Returns nil, if the resource is not found.
func (c *Client) DeleteInternetGateway(ctx context.Context, id string) error {
	input := &ec2.DeleteInternetGatewayInput{
		InternetGatewayId: aws.String(id),
	}
	_, err := c.EC2.DeleteInternetGatewayWithContext(ctx, input)
	return ignoreNotFound(err)
}

// CreateVpcEndpoint creates an EC2 VPC endpoint resource.
func (c *Client) CreateVpcEndpoint(ctx context.Context, endpoint *VpcEndpoint) (*VpcEndpoint, error) {
	input := &ec2.CreateVpcEndpointInput{
		ServiceName: aws.String(endpoint.ServiceName),
		//TagSpecifications: endpoint.ToTagSpecifications(ec2.ResourceTypeClientVpnEndpoint),
		VpcId: endpoint.VpcId,
	}
	output, err := c.EC2.CreateVpcEndpointWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return &VpcEndpoint{
		//Tags:          FromTags(output.VpcEndpoint.Tags),
		VpcEndpointId: aws.StringValue(output.VpcEndpoint.VpcEndpointId),
		VpcId:         output.VpcEndpoint.VpcId,
		ServiceName:   aws.StringValue(output.VpcEndpoint.ServiceName),
	}, nil
}

// GetVpcEndpoints gets VPC endpoint resources by identifiers.
// Non-existing identifiers are silently ignored.
func (c *Client) GetVpcEndpoints(ctx context.Context, ids []string) ([]*VpcEndpoint, error) {
	input := &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: aws.StringSlice(ids)}
	return c.describeVpcEndpoints(ctx, input)
}

// FindVpcEndpointsByTags finds VPC endpoint resources matching the given tag map.
func (c *Client) FindVpcEndpointsByTags(ctx context.Context, tags Tags) ([]*VpcEndpoint, error) {
	input := &ec2.DescribeVpcEndpointsInput{Filters: tags.ToFilters()}
	return c.describeVpcEndpoints(ctx, input)
}

func (c *Client) describeVpcEndpoints(ctx context.Context, input *ec2.DescribeVpcEndpointsInput) ([]*VpcEndpoint, error) {
	output, err := c.EC2.DescribeVpcEndpointsWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var endpoints []*VpcEndpoint
	for _, item := range output.VpcEndpoints {
		endpoint := &VpcEndpoint{
			Tags:          FromTags(item.Tags),
			VpcEndpointId: aws.StringValue(item.VpcEndpointId),
			VpcId:         item.VpcId,
			ServiceName:   aws.StringValue(item.ServiceName),
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

// DeleteVpcEndpoint deletes a VPC endpoint by id.
// Returns nil if resource is not found.
func (c *Client) DeleteVpcEndpoint(ctx context.Context, id string) error {
	input := &ec2.DeleteVpcEndpointsInput{
		VpcEndpointIds: []*string{&id},
	}
	_, err := c.EC2.DeleteVpcEndpointsWithContext(ctx, input)
	return ignoreNotFound(err)
}

// CreateVpcEndpointRouteTableAssociation creates a route for a VPC endpoint.
// Itempotent, i.e. does nothing if the route is already existing.
func (c *Client) CreateVpcEndpointRouteTableAssociation(ctx context.Context, routeTableId, vpcEndpointId string) error {
	routeTable, err := c.GetRouteTable(ctx, routeTableId)
	if err != nil {
		return err
	}
	for _, route := range routeTable.Routes {
		if route.GatewayId != nil && *route.GatewayId == vpcEndpointId {
			return nil // already existing
		}
	}

	input := &ec2.ModifyVpcEndpointInput{
		VpcEndpointId:    aws.String(vpcEndpointId),
		AddRouteTableIds: aws.StringSlice([]string{routeTableId}),
	}
	_, err = c.EC2.ModifyVpcEndpointWithContext(ctx, input)
	return err
}

// DeleteVpcEndpointRouteTableAssociation deletes the route to a VPC endpoint
// Returns nil not found
func (c *Client) DeleteVpcEndpointRouteTableAssociation(ctx context.Context, routeTableId, vpcEndpointId string) error {
	routeTable, err := c.GetRouteTable(ctx, routeTableId)
	if err != nil {
		return err
	}
	for _, route := range routeTable.Routes {
		if route.GatewayId != nil && *route.GatewayId == vpcEndpointId {
			input := &ec2.ModifyVpcEndpointInput{
				VpcEndpointId:       aws.String(vpcEndpointId),
				RemoveRouteTableIds: aws.StringSlice([]string{routeTableId}),
			}
			_, err = c.EC2.ModifyVpcEndpointWithContext(ctx, input)
			return err
		}
	}
	return nil
}

// CreateRouteTable creates an EC2 route table resource.
// Routes specified in the input object are ignored.
func (c *Client) CreateRouteTable(ctx context.Context, routeTable *RouteTable) (*RouteTable, error) {
	input := &ec2.CreateRouteTableInput{
		TagSpecifications: routeTable.ToTagSpecifications(ec2.ResourceTypeRouteTable),
		VpcId:             routeTable.VpcId,
	}
	output, err := c.EC2.CreateRouteTableWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	created := &RouteTable{
		Tags:         FromTags(output.RouteTable.Tags),
		RouteTableId: aws.StringValue(output.RouteTable.RouteTableId),
		VpcId:        output.RouteTable.VpcId,
	}

	return created, nil
}

// CreateRoute creates a route for the given route table.
func (c *Client) CreateRoute(ctx context.Context, routeTableId string, route *Route) error {
	input := &ec2.CreateRouteInput{
		DestinationCidrBlock:     route.DestinationCidrBlock,
		DestinationIpv6CidrBlock: route.DestinationIpv6CidrBlock,
		DestinationPrefixListId:  route.DestinationPrefixListId,
		GatewayId:                route.GatewayId,
		NatGatewayId:             route.NatGatewayId,
		RouteTableId:             aws.String(routeTableId),
	}
	_, err := c.EC2.CreateRouteWithContext(ctx, input)
	return err
}

// DeleteRoute deletes a route from the given route table.
func (c *Client) DeleteRoute(ctx context.Context, routeTableId string, route *Route) error {
	input := &ec2.DeleteRouteInput{
		DestinationCidrBlock:     route.DestinationCidrBlock,
		DestinationIpv6CidrBlock: route.DestinationIpv6CidrBlock,
		DestinationPrefixListId:  route.DestinationPrefixListId,
		RouteTableId:             aws.String(routeTableId),
	}
	_, err := c.EC2.DeleteRouteWithContext(ctx, input)
	return err
}

// GetRouteTable gets a route table by the identifier.
func (c *Client) GetRouteTable(ctx context.Context, id string) (*RouteTable, error) {
	input := &ec2.DescribeRouteTablesInput{RouteTableIds: aws.StringSlice([]string{id})}
	output, err := c.describeRouteTables(ctx, input)
	return single(output, err)
}

// FindRouteTablesByTags finds routing table resources matching the given tag map.
func (c *Client) FindRouteTablesByTags(ctx context.Context, tags Tags) ([]*RouteTable, error) {
	input := &ec2.DescribeRouteTablesInput{Filters: tags.ToFilters()}
	return c.describeRouteTables(ctx, input)
}

func (c *Client) describeRouteTables(ctx context.Context, input *ec2.DescribeRouteTablesInput) ([]*RouteTable, error) {
	output, err := c.EC2.DescribeRouteTablesWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var tables []*RouteTable
	for _, item := range output.RouteTables {
		table := &RouteTable{
			Tags:         FromTags(item.Tags),
			RouteTableId: aws.StringValue(item.RouteTableId),
			VpcId:        item.VpcId,
		}
		for _, route := range item.Routes {
			table.Routes = append(table.Routes, &Route{
				DestinationCidrBlock:    route.DestinationCidrBlock,
				GatewayId:               route.GatewayId,
				NatGatewayId:            route.NatGatewayId,
				DestinationPrefixListId: route.DestinationPrefixListId,
			})
		}
		for _, assoc := range item.Associations {
			table.Associations = append(table.Associations, &RouteTableAssociation{
				RouteTableAssociationId: aws.StringValue(assoc.RouteTableAssociationId),
				Main:                    aws.BoolValue(assoc.Main),
				GatewayId:               assoc.GatewayId,
				SubnetId:                assoc.SubnetId,
			})
		}
		tables = append(tables, table)
	}
	return tables, nil
}

// DeleteRouteTable delete a route table by identifier.
// Returns nil if the resource is not found.
func (c *Client) DeleteRouteTable(ctx context.Context, id string) error {
	input := &ec2.DeleteRouteTableInput{
		RouteTableId: aws.String(id),
	}
	_, err := c.EC2.DeleteRouteTableWithContext(ctx, input)
	return ignoreNotFound(err)
}

// CreateSubnet creates an EC2 subnet resource.
func (c *Client) CreateSubnet(ctx context.Context, subnet *Subnet) (*Subnet, error) {
	input := &ec2.CreateSubnetInput{
		AvailabilityZone:  aws.String(subnet.AvailabilityZone),
		CidrBlock:         aws.String(subnet.CidrBlock),
		TagSpecifications: subnet.ToTagSpecifications(ec2.ResourceTypeSubnet),
		VpcId:             subnet.VpcId,
	}
	if subnet.Ipv6CidrBlocks != nil && subnet.Ipv6CidrBlocks[0] != "" {
		input.Ipv6CidrBlock = aws.String(subnet.Ipv6CidrBlocks[0])
	}
	output, err := c.EC2.CreateSubnetWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return fromSubnet(output.Subnet), nil
}

// GetSubnets gets subnets for the given identifiers.
// Non-existing identifiers are ignored silently.
func (c *Client) GetSubnets(ctx context.Context, ids []string) ([]*Subnet, error) {
	input := &ec2.DescribeSubnetsInput{SubnetIds: aws.StringSlice(ids)}
	return c.describeSubnets(ctx, input)
}

// FindSubnetsByTags finds subnet resources matching the given tag map.
func (c *Client) FindSubnetsByTags(ctx context.Context, tags Tags) ([]*Subnet, error) {
	input := &ec2.DescribeSubnetsInput{Filters: tags.ToFilters()}
	return c.describeSubnets(ctx, input)
}

func (c *Client) describeSubnets(ctx context.Context, input *ec2.DescribeSubnetsInput) ([]*Subnet, error) {
	output, err := c.EC2.DescribeSubnetsWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var subnets []*Subnet
	for _, item := range output.Subnets {
		subnets = append(subnets, fromSubnet(item))
	}
	return subnets, nil
}

// CheckSubnetIPv6Cidr checks if the subnet has an IPv6 CIDR block assigned
func (c *Client) CheckSubnetIPv6Cidr(subnetID string) (bool, error) {
	input := &ec2.DescribeSubnetsInput{
		SubnetIds: []*string{
			aws.String(subnetID),
		},
	}
	output, err := c.EC2.DescribeSubnets(input)
	if err != nil {
		return false, err
	}
	if len(output.Subnets) == 0 {
		return false, fmt.Errorf("Subnet not found")
	}
	subnet := output.Subnets[0]
	for _, cidr := range subnet.Ipv6CidrBlockAssociationSet {
		if *cidr.Ipv6CidrBlockState.State == "associated" {
			return true, nil
		}
	}
	return false, nil
}

// UpdateSubnetAttributes updates attributes of the given subnet
func (c *Client) UpdateSubnetAttributes(ctx context.Context, desired, current *Subnet) (bool, error) {
	modified := false
	if trueOrFalse(current.AssignIpv6AddressOnCreation) != trueOrFalse(desired.AssignIpv6AddressOnCreation) {
		input := &ec2.ModifySubnetAttributeInput{
			AssignIpv6AddressOnCreation: toAttributeBooleanValue(desired.AssignIpv6AddressOnCreation),
			SubnetId:                    aws.String(current.SubnetId),
		}
		associated, _ := c.CheckSubnetIPv6Cidr(current.SubnetId)
		if trueOrFalse(desired.AssignIpv6AddressOnCreation) && current.Ipv6CidrBlocks != nil && associated {
			if _, err := c.EC2.ModifySubnetAttributeWithContext(ctx, input); err != nil {
				return false, fmt.Errorf("updating AssignIpv6AddressOnCreation failed: %w", err)
			}
			modified = true
		}
	}
	if trueOrFalse(current.EnableDns64) != trueOrFalse(desired.EnableDns64) {
		input := &ec2.ModifySubnetAttributeInput{
			EnableDns64: toAttributeBooleanValue(desired.EnableDns64),
			SubnetId:    aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttributeWithContext(ctx, input); err != nil {
			return false, fmt.Errorf("updating EnableDns64 failed: %w", err)
		}
		modified = true
	}
	if trueOrFalse(current.EnableResourceNameDnsAAAARecordOnLaunch) != trueOrFalse(desired.EnableResourceNameDnsAAAARecordOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			EnableResourceNameDnsAAAARecordOnLaunch: toAttributeBooleanValue(desired.EnableResourceNameDnsAAAARecordOnLaunch),
			SubnetId:                                aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttributeWithContext(ctx, input); err != nil {
			return false, fmt.Errorf("updating EnableResourceNameDnsAAAARecordOnLaunch failed: %w", err)
		}
		modified = true
	}
	if trueOrFalse(current.EnableResourceNameDnsARecordOnLaunch) != trueOrFalse(desired.EnableResourceNameDnsARecordOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			EnableResourceNameDnsARecordOnLaunch: toAttributeBooleanValue(desired.EnableResourceNameDnsARecordOnLaunch),
			SubnetId:                             aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttributeWithContext(ctx, input); err != nil {
			return false, fmt.Errorf("updating EnableResourceNameDnsARecordOnLaunch failed: %w", err)
		}
		modified = true
	}
	if trueOrFalse(current.MapCustomerOwnedIpOnLaunch) != trueOrFalse(desired.MapCustomerOwnedIpOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			MapCustomerOwnedIpOnLaunch: toAttributeBooleanValue(desired.MapCustomerOwnedIpOnLaunch),
			SubnetId:                   aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttributeWithContext(ctx, input); err != nil {
			return false, fmt.Errorf("updating MapCustomerOwnedIpOnLaunch failed: %w", err)
		}
		modified = true
	}
	if trueOrFalse(current.MapPublicIpOnLaunch) != trueOrFalse(desired.MapPublicIpOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			MapPublicIpOnLaunch: toAttributeBooleanValue(desired.MapPublicIpOnLaunch),
			SubnetId:            aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttributeWithContext(ctx, input); err != nil {
			return false, fmt.Errorf("updating MapPublicIpOnLaunch failed: %w", err)
		}
		modified = true
	}
	if desired.Ipv6CidrBlocks != nil && (current.Ipv6CidrBlocks == nil || current.Ipv6CidrBlocks[0] != desired.Ipv6CidrBlocks[0]) {
		ipv6CidrBlockAssociated, err := c.CheckSubnetIPv6Cidr(current.SubnetId)
		if err != nil {
			return modified, err
		}
		if !ipv6CidrBlockAssociated && desired.Ipv6CidrBlocks[0] != "" {
			input := &ec2.AssociateSubnetCidrBlockInput{
				Ipv6CidrBlock: &desired.Ipv6CidrBlocks[0],
				SubnetId:      aws.String(current.SubnetId),
			}
			if _, err := c.EC2.AssociateSubnetCidrBlock(input); err != nil {
				return false, fmt.Errorf("IPv6 CIDR block association failed: %w", err)
			}
			modified = true
		}
	}

	if !reflect.DeepEqual(current.CustomerOwnedIpv4Pool, desired.CustomerOwnedIpv4Pool) {
		input := &ec2.ModifySubnetAttributeInput{
			CustomerOwnedIpv4Pool: desired.CustomerOwnedIpv4Pool,
			SubnetId:              aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttributeWithContext(ctx, input); err != nil {
			return false, fmt.Errorf("updating CustomerOwnedIpv4Pool failed: %w", err)
		}
		modified = true
	}
	privateDnsHostnameTypeOnLaunch := desired.PrivateDnsHostnameTypeOnLaunch
	if privateDnsHostnameTypeOnLaunch == nil {
		privateDnsHostnameTypeOnLaunch = aws.String(ec2.HostnameTypeIpName)
	}
	if !reflect.DeepEqual(current.PrivateDnsHostnameTypeOnLaunch, privateDnsHostnameTypeOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			PrivateDnsHostnameTypeOnLaunch: privateDnsHostnameTypeOnLaunch,
			SubnetId:                       aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttributeWithContext(ctx, input); err != nil {
			return false, fmt.Errorf("updating PrivateDnsHostnameTypeOnLaunch failed: %w", err)
		}
		modified = true
	}
	return modified, nil
}

// DeleteSubnet delete a subnet by identifier.
// Returns nil if the resource is not found.
func (c *Client) DeleteSubnet(ctx context.Context, id string) error {
	input := &ec2.DeleteSubnetInput{
		SubnetId: aws.String(id),
	}
	var realErr error
	err := c.PollImmediateUntil(ctx, func(ctx context.Context) (done bool, err error) {
		_, realErr = c.EC2.DeleteSubnetWithContext(ctx, input)
		return ignoreNotFound(realErr) == nil, nil
	})
	if err != nil {
		if realErr != nil {
			return realErr
		}
	}
	return err
}

// CreateElasticIP creates an EC2 elastip IP resource.
func (c *Client) CreateElasticIP(ctx context.Context, eip *ElasticIP) (*ElasticIP, error) {
	domainOpt := ""
	if eip.Vpc {
		domainOpt = ec2.DomainTypeVpc
	}
	input := &ec2.AllocateAddressInput{
		Domain:            aws.String(domainOpt),
		TagSpecifications: eip.ToTagSpecifications(ec2.ResourceTypeElasticIp),
	}
	output, err := c.EC2.AllocateAddressWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return &ElasticIP{
		Tags:         eip.Tags.Clone(),
		Vpc:          eip.Vpc,
		AllocationId: aws.StringValue(output.AllocationId),
		PublicIp:     aws.StringValue(output.PublicIp),
	}, nil
}

// GetElasticIP gets an elastic IP resource by identifier.
func (c *Client) GetElasticIP(ctx context.Context, id string) (*ElasticIP, error) {
	input := &ec2.DescribeAddressesInput{AllocationIds: aws.StringSlice([]string{id})}
	output, err := c.describeElasticIPs(ctx, input)
	return single(output, err)
}

// FindElasticIPsByTags finds elastic IP resources matching the given tag map.
func (c *Client) FindElasticIPsByTags(ctx context.Context, tags Tags) ([]*ElasticIP, error) {
	input := &ec2.DescribeAddressesInput{Filters: tags.ToFilters()}
	return c.describeElasticIPs(ctx, input)
}

func (c *Client) describeElasticIPs(ctx context.Context, input *ec2.DescribeAddressesInput) ([]*ElasticIP, error) {
	output, err := c.EC2.DescribeAddressesWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var eips []*ElasticIP
	for _, item := range output.Addresses {
		eips = append(eips, fromAddress(item))
	}
	return eips, nil
}

// DeleteElasticIP deletes an elastic IP resource by identifier.
// Returns nil if the resource is not found.
func (c *Client) DeleteElasticIP(ctx context.Context, id string) error {
	input := &ec2.ReleaseAddressInput{
		AllocationId: aws.String(id),
	}
	var realErr error
	err := c.PollImmediateUntil(ctx, func(ctx context.Context) (done bool, err error) {
		_, realErr = c.EC2.ReleaseAddressWithContext(ctx, input)
		return ignoreNotFound(realErr) == nil, nil
	})
	if err != nil {
		if realErr != nil {
			return realErr
		}
	}
	return err
}

// CreateNATGateway creates an EC2 NAT gateway resource.
// The method does NOT wait until the NAT gateway is available.
func (c *Client) CreateNATGateway(ctx context.Context, gateway *NATGateway) (*NATGateway, error) {
	input := &ec2.CreateNatGatewayInput{
		AllocationId:      aws.String(gateway.EIPAllocationId),
		SubnetId:          aws.String(gateway.SubnetId),
		TagSpecifications: gateway.ToTagSpecifications(ec2.ResourceTypeNatgateway),
	}
	output, err := c.EC2.CreateNatGatewayWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return fromNatGateway(output.NatGateway), nil
}

// WaitForNATGatewayAvailable waits until the NAT gateway has state "available" or the context is cancelled.
func (c *Client) WaitForNATGatewayAvailable(ctx context.Context, id string) error {
	return c.PollImmediateUntil(ctx, func(ctx context.Context) (done bool, err error) {
		if item, err := c.GetNATGateway(ctx, id); err != nil {
			return false, err
		} else {
			return strings.EqualFold(item.State, ec2.StateAvailable), nil
		}
	})
}

// GetNATGateway gets an NAT gateway by identifier.
// If the resource is not found or in state "deleted", nil is returned
func (c *Client) GetNATGateway(ctx context.Context, id string) (*NATGateway, error) {
	input := &ec2.DescribeNatGatewaysInput{NatGatewayIds: aws.StringSlice([]string{id})}
	output, err := c.describeNATGateways(ctx, input)
	gw, err := single(output, err)
	if gw != nil && strings.EqualFold(gw.State, ec2.StateDeleted) {
		return nil, nil
	}
	return gw, err
}

// FindNATGatewaysByTags finds NAT gateway resources matching the given tag map.
func (c *Client) FindNATGatewaysByTags(ctx context.Context, tags Tags) ([]*NATGateway, error) {
	input := &ec2.DescribeNatGatewaysInput{Filter: tags.ToFilters()}
	return c.describeNATGateways(ctx, input)
}

func (c *Client) describeNATGateways(ctx context.Context, input *ec2.DescribeNatGatewaysInput) ([]*NATGateway, error) {
	output, err := c.EC2.DescribeNatGatewaysWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var gateways []*NATGateway
	for _, item := range output.NatGateways {
		gw := fromNatGateway(item)
		if gw != nil {
			gateways = append(gateways, gw)
		}
	}
	return gateways, nil
}

// DeleteNATGateway deletes a NAT gateway by identifier.
// Returns nil if the resource is not found.
func (c *Client) DeleteNATGateway(ctx context.Context, id string) error {
	input := &ec2.DeleteNatGatewayInput{
		NatGatewayId: aws.String(id),
	}
	_, err := c.EC2.DeleteNatGatewayWithContext(ctx, input)
	if err != nil {
		return ignoreNotFound(err)
	}
	err = c.PollUntil(ctx, func(ctx context.Context) (done bool, err error) {
		if item, err := c.GetNATGateway(ctx, id); err != nil {
			return false, err
		} else {
			return item == nil, nil
		}
	})
	return ignoreNotFound(err)
}

// ImportKeyPair creates a EC2 key pair.
func (c *Client) ImportKeyPair(ctx context.Context, keyName string, publicKey []byte, tags Tags) (*KeyPairInfo, error) {
	input := &ec2.ImportKeyPairInput{
		KeyName:           aws.String(keyName),
		PublicKeyMaterial: publicKey,
		TagSpecifications: tags.ToTagSpecifications(ec2.ResourceTypeKeyPair),
	}
	output, err := c.EC2.ImportKeyPairWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return &KeyPairInfo{
		Tags:           FromTags(output.Tags),
		KeyName:        aws.StringValue(output.KeyName),
		KeyFingerprint: aws.StringValue(output.KeyFingerprint),
	}, nil
}

// GetKeyPair gets a EC2 key pair by its key name.
func (c *Client) GetKeyPair(ctx context.Context, keyName string) (*KeyPairInfo, error) {
	input := &ec2.DescribeKeyPairsInput{KeyNames: aws.StringSlice([]string{keyName})}
	output, err := c.describeKeyPairs(ctx, input)
	return single(output, err)
}

// FindKeyPairsByTags finds EC key pair resources matching the given tag map.
func (c *Client) FindKeyPairsByTags(ctx context.Context, tags Tags) ([]*KeyPairInfo, error) {
	input := &ec2.DescribeKeyPairsInput{Filters: tags.ToFilters()}
	return c.describeKeyPairs(ctx, input)
}

func (c *Client) describeKeyPairs(ctx context.Context, input *ec2.DescribeKeyPairsInput) ([]*KeyPairInfo, error) {
	output, err := c.EC2.DescribeKeyPairsWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var pairs []*KeyPairInfo
	for _, item := range output.KeyPairs {
		pairs = append(pairs, fromKeyPairInfo(item))
	}
	return pairs, nil
}

// DeleteKeyPair deletes an EC2 key pair given by the key name.
// Returns nil if resource is not found.
func (c *Client) DeleteKeyPair(ctx context.Context, keyName string) error {
	input := &ec2.DeleteKeyPairInput{
		KeyName: aws.String(keyName),
	}
	_, err := c.EC2.DeleteKeyPairWithContext(ctx, input)
	return ignoreNotFound(err)
}

// CreateRouteTableAssociation associates a route table with a subnet.
// Returns association id and error.
func (c *Client) CreateRouteTableAssociation(ctx context.Context, routeTableId, subnetId string) (*string, error) {
	input := &ec2.AssociateRouteTableInput{
		RouteTableId: aws.String(routeTableId),
		SubnetId:     aws.String(subnetId),
	}
	output, err := c.EC2.AssociateRouteTableWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return output.AssociationId, nil
}

// DeleteRouteTableAssociation deletes the route table association by the assocation identifier.
// Returns nil if the resource is not found.
func (c *Client) DeleteRouteTableAssociation(ctx context.Context, associationId string) error {
	input := &ec2.DisassociateRouteTableInput{
		AssociationId: aws.String(associationId),
	}
	_, err := c.EC2.DisassociateRouteTableWithContext(ctx, input)
	return ignoreNotFound(err)
}

// CreateIAMRole creates an IAM role resource.
func (c *Client) CreateIAMRole(ctx context.Context, role *IAMRole) (*IAMRole, error) {
	input := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(role.AssumeRolePolicyDocument),
		Path:                     aws.String(role.Path),
		RoleName:                 aws.String(role.RoleName),
	}
	output, err := c.IAM.CreateRoleWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	return fromIAMRole(output.Role), nil
}

// GetIAMRole gets an IAM role by role name.
func (c *Client) GetIAMRole(ctx context.Context, roleName string) (*IAMRole, error) {
	input := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}
	output, err := c.IAM.GetRoleWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	return fromIAMRole(output.Role), nil
}

// DeleteIAMRole deletes an IAM role by role name.
// Returns nil if the resource is not found.
func (c *Client) DeleteIAMRole(ctx context.Context, roleName string) error {
	input := &iam.DeleteRoleInput{
		RoleName: aws.String(roleName),
	}
	_, err := c.IAM.DeleteRoleWithContext(ctx, input)
	return ignoreNotFound(err)
}

// UpdateAssumeRolePolicy updates the assumeRolePolicy of an IAM role.
func (c *Client) UpdateAssumeRolePolicy(ctx context.Context, roleName, assumeRolePolicy string) error {
	input := &iam.UpdateAssumeRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyDocument: aws.String(assumeRolePolicy),
	}
	_, err := c.IAM.UpdateAssumeRolePolicyWithContext(ctx, input)
	return err
}

// CreateIAMInstanceProfile creates an IAM instance profile.
func (c *Client) CreateIAMInstanceProfile(ctx context.Context, profile *IAMInstanceProfile) (*IAMInstanceProfile, error) {
	input := &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String(profile.InstanceProfileName),
		Path:                aws.String(profile.Path),
	}
	output, err := c.IAM.CreateInstanceProfileWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	profileName := aws.StringValue(output.InstanceProfile.InstanceProfileName)
	if err = c.PollImmediateUntil(ctx, func(ctx context.Context) (done bool, err error) {
		if item, err := c.GetIAMInstanceProfile(ctx, profileName); err != nil {
			return false, err
		} else {
			return item != nil, nil
		}
	}); err != nil {
		return nil, err
	}
	return c.GetIAMInstanceProfile(ctx, profileName)
}

// GetIAMInstanceProfile gets an IAM instance profile by profile name.
func (c *Client) GetIAMInstanceProfile(ctx context.Context, profileName string) (*IAMInstanceProfile, error) {
	input := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	}
	output, err := c.IAM.GetInstanceProfileWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	return fromIAMInstanceProfile(output.InstanceProfile), nil
}

// AddRoleToIAMInstanceProfile adds a role to an instance profile.
func (c *Client) AddRoleToIAMInstanceProfile(ctx context.Context, profileName, roleName string) error {
	input := &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
		RoleName:            aws.String(roleName),
	}
	_, err := c.IAM.AddRoleToInstanceProfileWithContext(ctx, input)
	return err
}

// RemoveRoleFromIAMInstanceProfile removes a role from an instance profile.
func (c *Client) RemoveRoleFromIAMInstanceProfile(ctx context.Context, profileName, roleName string) error {
	input := &iam.RemoveRoleFromInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
		RoleName:            aws.String(roleName),
	}
	_, err := c.IAM.RemoveRoleFromInstanceProfileWithContext(ctx, input)
	return ignoreNotFound(err)
}

// DeleteIAMInstanceProfile deletes an IAM instance profile by profile name.
// Returns nil if the resource is not found.
func (c *Client) DeleteIAMInstanceProfile(ctx context.Context, profileName string) error {
	input := &iam.DeleteInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	}
	_, err := c.IAM.DeleteInstanceProfileWithContext(ctx, input)
	return ignoreNotFound(err)
}

// PutIAMRolePolicy creates or updates an IAM role policy.
func (c *Client) PutIAMRolePolicy(ctx context.Context, policy *IAMRolePolicy) error {
	input := &iam.PutRolePolicyInput{
		PolicyDocument: aws.String(policy.PolicyDocument),
		PolicyName:     aws.String(policy.PolicyName),
		RoleName:       aws.String(policy.RoleName),
	}
	_, err := c.IAM.PutRolePolicyWithContext(ctx, input)
	return err
}

// GetIAMRolePolicy gets an IAM role policy by policy name and role name.
func (c *Client) GetIAMRolePolicy(ctx context.Context, policyName, roleName string) (*IAMRolePolicy, error) {
	input := &iam.GetRolePolicyInput{
		PolicyName: aws.String(policyName),
		RoleName:   aws.String(roleName),
	}
	output, err := c.IAM.GetRolePolicyWithContext(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	return &IAMRolePolicy{
		PolicyName:     aws.StringValue(output.PolicyName),
		RoleName:       aws.StringValue(output.RoleName),
		PolicyDocument: aws.StringValue(output.PolicyDocument),
	}, nil
}

// DeleteIAMRolePolicy deletes an IAM role policy by policy name and role name.
// Returns nil if the resource is not found.
func (c *Client) DeleteIAMRolePolicy(ctx context.Context, policyName, roleName string) error {
	input := &iam.DeleteRolePolicyInput{
		PolicyName: aws.String(policyName),
		RoleName:   aws.String(roleName),
	}
	_, err := c.IAM.DeleteRolePolicyWithContext(ctx, input)
	return ignoreNotFound(err)
}

// CreateEC2Tags creates the tags for the given EC2 resource identifiers
func (c *Client) CreateEC2Tags(ctx context.Context, resources []string, tags Tags) error {
	input := &ec2.CreateTagsInput{
		Resources: aws.StringSlice(resources),
		Tags:      tags.ToEC2Tags(),
	}
	_, err := c.EC2.CreateTagsWithContext(ctx, input)
	return err
}

// DeleteEC2Tags deletes the tags for the given EC2 resource identifiers
func (c *Client) DeleteEC2Tags(ctx context.Context, resources []string, tags Tags) error {
	input := &ec2.DeleteTagsInput{
		Resources: aws.StringSlice(resources),
		Tags:      tags.ToEC2Tags(),
	}
	_, err := c.EC2.DeleteTagsWithContext(ctx, input)
	return err
}

// PollImmediateUntil runs the 'condition' before waiting for the interval.
// 'condition' will always be invoked at least once.
func (c *Client) PollImmediateUntil(ctx context.Context, condition wait.ConditionWithContextFunc) error {
	return wait.PollImmediateUntilWithContext(ctx, c.PollInterval, condition)
}

// PollUntil tries a condition func until it returns true,
// an error or the specified context is cancelled or expired.
func (c *Client) PollUntil(ctx context.Context, condition wait.ConditionWithContextFunc) error {
	return wait.PollUntilWithContext(ctx, c.PollInterval, condition)
}

// IsNotFoundError returns true if the given error is a awserr.Error indicating that an AWS resource was not found.
func IsNotFoundError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && (aerr.Code() == elb.ErrCodeAccessPointNotFoundException ||
		aerr.Code() == iam.ErrCodeNoSuchEntityException || aerr.Code() == "NatGatewayNotFound" ||
		strings.HasSuffix(aerr.Code(), ".NotFound")) {
		return true
	}
	return false
}

// IsAlreadyAssociatedError returns true if the given error is a awserr.Error indicating that an AWS resource was already associated.
func IsAlreadyAssociatedError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "Resource.AlreadyAssociated" {
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

func ignoreAlreadyAssociated(err error) error {
	if err == nil || IsAlreadyAssociatedError(err) {
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

func fromDhcpOptions(item *ec2.DhcpOptions) *DhcpOptions {
	config := map[string][]string{}
	for _, cfg := range item.DhcpConfigurations {
		var values []string
		for _, av := range cfg.Values {
			values = append(values, *av.Value)
		}
		config[*cfg.Key] = values
	}
	return &DhcpOptions{
		Tags:               FromTags(item.Tags),
		DhcpOptionsId:      aws.StringValue(item.DhcpOptionsId),
		DhcpConfigurations: config,
	}
}

func fromIpPermission(groupId string, ipPerm *ec2.IpPermission, ruleType SecurityGroupRuleType) (*SecurityGroupRule, error) {
	var foreign bool
	var blocks []string
	for _, block := range ipPerm.IpRanges {
		blocks = append(blocks, *block.CidrIp)
	}
	rule := &SecurityGroupRule{
		Type:       ruleType,
		Protocol:   aws.StringValue(ipPerm.IpProtocol),
		CidrBlocks: blocks,
	}
	if ipPerm.FromPort != nil {
		rule.FromPort = int(*ipPerm.FromPort)
	}
	if ipPerm.ToPort != nil {
		rule.ToPort = int(*ipPerm.ToPort)
	}
	if len(ipPerm.UserIdGroupPairs) == 1 && ipPerm.UserIdGroupPairs[0].GroupId != nil && *ipPerm.UserIdGroupPairs[0].GroupId == groupId {
		rule.Self = true
	} else if len(ipPerm.UserIdGroupPairs) != 0 {
		foreign = true
	}
	if len(ipPerm.Ipv6Ranges) > 0 || len(ipPerm.PrefixListIds) > 0 {
		foreign = true
	}
	if foreign {
		data, err := json.Marshal(ipPerm)
		if err != nil {
			return nil, err
		}
		rule.Foreign = pointer.String(string(data))
	}
	return rule, nil
}

func fromSubnet(item *ec2.Subnet) *Subnet {
	s := &Subnet{
		Tags:                        FromTags(item.Tags),
		SubnetId:                    aws.StringValue(item.SubnetId),
		VpcId:                       item.VpcId,
		CidrBlock:                   aws.StringValue(item.CidrBlock),
		AvailabilityZone:            aws.StringValue(item.AvailabilityZone),
		AssignIpv6AddressOnCreation: trueOrNil(item.AssignIpv6AddressOnCreation),
		CustomerOwnedIpv4Pool:       item.CustomerOwnedIpv4Pool,
		EnableDns64:                 trueOrNil(item.EnableDns64),
		Ipv6Native:                  trueOrNil(item.Ipv6Native),
		MapCustomerOwnedIpOnLaunch:  trueOrNil(item.MapCustomerOwnedIpOnLaunch),
		MapPublicIpOnLaunch:         trueOrNil(item.MapPublicIpOnLaunch),
		OutpostArn:                  item.OutpostArn,
	}
	if item.PrivateDnsNameOptionsOnLaunch != nil {
		s.EnableResourceNameDnsAAAARecordOnLaunch = trueOrNil(item.PrivateDnsNameOptionsOnLaunch.EnableResourceNameDnsAAAARecord)
		s.EnableResourceNameDnsARecordOnLaunch = trueOrNil(item.PrivateDnsNameOptionsOnLaunch.EnableResourceNameDnsARecord)
		s.PrivateDnsHostnameTypeOnLaunch = item.PrivateDnsNameOptionsOnLaunch.HostnameType
	}
	for _, block := range item.Ipv6CidrBlockAssociationSet {
		s.Ipv6CidrBlocks = append(s.Ipv6CidrBlocks, aws.StringValue(block.Ipv6CidrBlock))
	}
	return s
}

func fromAddress(item *ec2.Address) *ElasticIP {
	return &ElasticIP{
		Tags:         FromTags(item.Tags),
		Vpc:          aws.StringValue(item.Domain) == ec2.DomainTypeVpc,
		AllocationId: aws.StringValue(item.AllocationId),
		PublicIp:     aws.StringValue(item.PublicIp),
	}
}

func fromNatGateway(item *ec2.NatGateway) *NATGateway {
	if strings.EqualFold(aws.StringValue(item.State), ec2.StateDeleted) {
		return nil
	}
	var allocationId, publicIP string
	for _, address := range item.NatGatewayAddresses {
		allocationId = aws.StringValue(address.AllocationId)
		publicIP = aws.StringValue(address.PublicIp)
		break
	}
	return &NATGateway{
		Tags:            FromTags(item.Tags),
		NATGatewayId:    aws.StringValue(item.NatGatewayId),
		EIPAllocationId: allocationId,
		PublicIP:        publicIP,
		SubnetId:        aws.StringValue(item.SubnetId),
		State:           aws.StringValue(item.State),
	}
}

func fromKeyPairInfo(item *ec2.KeyPairInfo) *KeyPairInfo {
	return &KeyPairInfo{
		Tags:           FromTags(item.Tags),
		KeyName:        aws.StringValue(item.KeyName),
		KeyFingerprint: aws.StringValue(item.KeyFingerprint),
	}
}

func fromIAMRole(item *iam.Role) *IAMRole {
	role := &IAMRole{
		RoleId:                   aws.StringValue(item.RoleId),
		RoleName:                 aws.StringValue(item.RoleName),
		Path:                     aws.StringValue(item.Path),
		AssumeRolePolicyDocument: aws.StringValue(item.AssumeRolePolicyDocument),
		ARN:                      aws.StringValue(item.Arn),
	}
	if strings.Contains(role.AssumeRolePolicyDocument, "%7B") {
		// URL decode needed, very strange API !?
		decoded, err := url.QueryUnescape(role.AssumeRolePolicyDocument)
		if err == nil {
			role.AssumeRolePolicyDocument = decoded
		}
	}
	return role
}

func fromIAMInstanceProfile(item *iam.InstanceProfile) *IAMInstanceProfile {
	var roleName string
	for _, role := range item.Roles {
		roleName = aws.StringValue(role.RoleName)
		break
	}
	return &IAMInstanceProfile{
		InstanceProfileId:   aws.StringValue(item.InstanceProfileId),
		InstanceProfileName: aws.StringValue(item.InstanceProfileName),
		Path:                aws.StringValue(item.Path),
		RoleName:            roleName,
	}
}

func single[T any](list []*T, err error) (*T, error) {
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	if len(list) == 0 {
		return nil, nil
	}
	return list[0], nil
}

func toAttributeBooleanValue(value *bool) *ec2.AttributeBooleanValue {
	if value == nil {
		value = aws.Bool(false)
	}
	return &ec2.AttributeBooleanValue{Value: value}
}

func trueOrNil(value *bool) *bool {
	if value == nil || !*value {
		return nil
	}
	return value
}

func trueOrFalse(value *bool) bool {
	if value == nil || !*value {
		return false
	}
	return *value
}
