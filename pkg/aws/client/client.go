// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v2config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// AuthConfig represents AWS auth configuration credentials.
type AuthConfig struct {
	// Region is the AWS region.
	Region string

	// AccessKey represents static credentials for authentication to AWS.
	// This field is mutually exclusive with WorkloadIdentity.
	AccessKey *AccessKey

	// WorkloadIdentity contains workload identity configuration.
	// This field is mutually exclusive with AccessKey.
	WorkloadIdentity *WorkloadIdentity
}

// AccessKey represents static credentials for authentication to AWS.
type AccessKey struct {
	// ID is the Access Key ID.
	ID string
	// Secret is the Secret Access Key.
	Secret string
}

// WorkloadIdentity contains workload identity configuration for authentication to AWS.
type WorkloadIdentity struct {
	// TokenRetriever a function that retrieves a token used for exchanging AWS credentials.
	TokenRetriever stscreds.IdentityTokenRetriever

	// RoleARN is the ARN of the role that will be assumed.
	RoleARN string
}

// Client is a struct containing several clients for the different AWS services it needs to interact with.
// * EC2 is the standard client for the EC2 service.
// * STS is the standard client for the STS service.
// * IAM is the standard client for the IAM service.
// * S3 is the standard client for the S3 service.
// * ELB is the standard client for the ELB service.
// * ELBv2 is the standard client for the ELBv2 service.
// * Route53 is the standard client for the Route53 service.
type Client struct {
	EC2                           ec2.Client
	STS                           sts.Client
	IAM                           iam.Client
	S3                            s3.Client
	ELB                           elb.Client
	ELBv2                         elbv2.Client
	EFS                           efs.Client
	Route53                       route53.Client
	Route53RateLimiter            *rate.Limiter
	Route53RateLimiterWaitTimeout time.Duration
	Logger                        logr.Logger
	PollInterval                  time.Duration
}

var _ Interface = &Client{}

// NewInterface creates a new instance of Interface for the given AWS credentials and region.
func NewInterface(authConfig AuthConfig) (Interface, error) {
	return NewClient(authConfig)
}

// NewClient creates a new Client for the given AWS credentials <accessKeyID>, <secretAccessKey>, and
// the AWS region <region>.
// It initializes the clients for the various services like EC2, ELB, etc.
func NewClient(authConfig AuthConfig) (*Client, error) {
	var credentialsProvider aws.CredentialsProvider
	if authConfig.AccessKey != nil {
		credentialsProvider = credentials.NewStaticCredentialsProvider(authConfig.AccessKey.ID, authConfig.AccessKey.Secret, "")
	} else {
		credentialsProvider = stscreds.NewWebIdentityRoleProvider(
			sts.NewFromConfig(aws.Config{Region: authConfig.Region}),
			authConfig.WorkloadIdentity.RoleARN,
			authConfig.WorkloadIdentity.TokenRetriever,
		)
	}
	cfg, err := v2config.LoadDefaultConfig(
		context.TODO(),
		v2config.WithRegion(authConfig.Region),
		v2config.WithCredentialsProvider(aws.NewCredentialsCache(credentialsProvider)),
	)
	if err != nil {
		return nil, err
	}

	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		return stack.Build.Add(
			middleware.BuildMiddlewareFunc(
				"addUserAgent",
				func(
					ctx context.Context, input middleware.BuildInput, handler middleware.BuildHandler,
				) (
					middleware.BuildOutput, middleware.Metadata, error,
				) {
					req, ok := input.Request.(*smithyhttp.Request)
					userAgent := []string{"gardener-extension-provider-aws"}

					if ok {
						header := req.Header["User-Agent"]
						if len(header) == 0 {
							header = userAgent
						} else {
							header = append(userAgent, header...)
						}
						req.Header["User-Agent"] = header
					}
					return handler.HandleBuild(ctx, input)
				},
			),
			middleware.Before,
		)
	})

	return &Client{
		EC2:                           *ec2.NewFromConfig(cfg),
		ELB:                           *elb.NewFromConfig(cfg),
		ELBv2:                         *elbv2.NewFromConfig(cfg),
		IAM:                           *iam.NewFromConfig(cfg),
		STS:                           *sts.NewFromConfig(cfg),
		S3:                            *s3.NewFromConfig(cfg),
		EFS:                           *efs.NewFromConfig(cfg),
		Route53:                       *route53.NewFromConfig(cfg),
		Route53RateLimiter:            rate.NewLimiter(rate.Inf, 0),
		Route53RateLimiterWaitTimeout: 1 * time.Second,
		Logger:                        log.Log.WithName("aws-client"),
		PollInterval:                  5 * time.Second,
	}, nil
}

// GetAccountID returns the ID of the AWS account the Client is interacting with.
func (c *Client) GetAccountID(ctx context.Context) (string, error) {
	getCallerIdentityOutput, err := c.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return *getCallerIdentityOutput.Account, nil
}

// GetVPCInternetGateway returns the ID of the internet gateway attached to the given VPC <vpcID>.
// If there is no internet gateway attached, the returned string will be empty.
func (c *Client) GetVPCInternetGateway(ctx context.Context, vpcID string) (string, error) {
	describeInternetGatewaysInput := &ec2.DescribeInternetGatewaysInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("attachment.vpc-id"),
				Values: []string{vpcID},
			},
		},
	}
	describeInternetGatewaysOutput, err := c.EC2.DescribeInternetGateways(ctx, describeInternetGatewaysInput)
	if err != nil {
		return "", ignoreNotFound(err)
	}

	if len(describeInternetGatewaysOutput.InternetGateways) > 0 {
		return aws.ToString(describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId), nil
	}
	return "", nil
}

// GetElasticIPsAssociationIDForAllocationIDs list existing elastic IP addresses for the given allocationIDs.
// returns a map[elasticIPAllocationID]elasticIPAssociationID or an error
func (c *Client) GetElasticIPsAssociationIDForAllocationIDs(ctx context.Context, allocationIDs []string) (map[string]*string, error) {
	describeAddressesInput := &ec2.DescribeAddressesInput{
		AllocationIds: allocationIDs,
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("domain"),
				Values: []string{"vpc"},
			},
		},
	}

	describeAddressesOutput, err := c.EC2.DescribeAddresses(ctx, describeAddressesInput)
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
		Filter: []ec2types.Filter{{
			Name:   aws.String(fmt.Sprintf("tag:kubernetes.io/cluster/%s", shootNamespace)),
			Values: []string{"1"},
		}},
	}

	describeNatGatewaysOutput, err := c.EC2.DescribeNatGateways(ctx, describeAddressesInput)
	if err != nil {
		return nil, ignoreNotFound(err)
	}

	result := sets.New[string]()
	if len(describeNatGatewaysOutput.NatGateways) == 0 {
		return result, nil
	}

	for _, natGateway := range describeNatGatewaysOutput.NatGateways {
		if len(natGateway.NatGatewayAddresses) == 0 {
			continue
		}

		// add all allocation IDS for the addresses for this NAT Gateway
		// these are the allocation IDS which identify the associated EIP
		for _, address := range natGateway.NatGatewayAddresses {
			result.Insert(*address.AllocationId)
		}
	}

	return result, nil
}

// GetVPCAttribute returns the value of the specified VPC attribute.
func (c *Client) GetVPCAttribute(ctx context.Context, vpcID string, attribute ec2types.VpcAttributeName) (bool, error) {
	vpcAttribute, err := c.EC2.DescribeVpcAttribute(
		ctx,
		&ec2.DescribeVpcAttributeInput{VpcId: &vpcID, Attribute: attribute},
	)
	if err != nil {
		return false, err
	}

	switch attribute {
	case ec2types.VpcAttributeNameEnableDnsSupport:
		return vpcAttribute.EnableDnsSupport != nil && vpcAttribute.EnableDnsSupport.Value != nil && *vpcAttribute.EnableDnsSupport.Value, nil
	case ec2types.VpcAttributeNameEnableDnsHostnames:
		return vpcAttribute.EnableDnsHostnames != nil && vpcAttribute.EnableDnsHostnames.Value != nil && *vpcAttribute.EnableDnsHostnames.Value, nil
	default:
		return false, nil
	}
}

// GetDHCPOptions returns DHCP options for the specified VPC ID.
func (c *Client) GetDHCPOptions(ctx context.Context, vpcID string) (map[string]string, error) {
	describeVpcsInput := &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String(FilterVpcID),
				Values: []string{vpcID},
			},
		},
	}

	describeVpcsOutput, err := c.EC2.DescribeVpcs(ctx, describeVpcsInput)
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
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("dhcp-options-id"),
				Values: []string{*describeVpcsOutput.Vpcs[0].DhcpOptionsId},
			},
		},
	}
	describeDhcpOptionsOutput, err := c.EC2.DescribeDhcpOptions(ctx, describeDhcpOptionsInput)
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
	bucketVersioningStatus, err := c.S3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		switch GetAWSAPIErrorCode(err) {
		case NoSuchBucket, PermanentRedirect:
			// No action required: either the bucket doesn't exist or it exists in a different region and wasn't created.
			return nil
		}
		return err
	}

	if bucketVersioningStatus != nil && bucketVersioningStatus.Status == s3types.BucketVersioningStatusEnabled {
		// object versioning is found to be enabled on the bucket
		return deleteVersionedObjectsWithPrefix(ctx, c.S3, bucket, prefix)
	}
	return deleteObjectsWithPrefix(ctx, c.S3, bucket, prefix)
}

// CreateBucket creates the s3 bucket with name <bucket> in <region>.
func (c *Client) CreateBucket(ctx context.Context, bucket, region string, objectLockEnabled bool) error {
	createBucketInput := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
		ACL:    s3types.BucketCannedACLPrivate,
		CreateBucketConfiguration: &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(region),
		},
		// Note: while creating a bucket with object lock enabled, object versioning will automatically gets enabled.
		ObjectLockEnabledForBucket: aws.Bool(objectLockEnabled),
	}

	if region == "us-east-1" {
		createBucketInput.CreateBucketConfiguration = nil
	}

	if _, err := c.S3.CreateBucket(ctx, createBucketInput); err != nil {
		var (
			bae *s3types.BucketAlreadyExists
			bao *s3types.BucketAlreadyOwnedByYou
		)
		if !errors.As(err, &bae) && !errors.As(err, &bao) {
			return err
		}
	}

	// Enable default server side encryption using AES256 algorithm. Key will be managed by S3
	if _, err := c.S3.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
		Bucket: aws.String(bucket),
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{
				{
					ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
						SSEAlgorithm: s3types.ServerSideEncryption("AES256"),
					},
				},
			},
		},
	}); err != nil {
		return err
	}

	// Block public access to the bucket
	if _, err := c.S3.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(bucket),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
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

	if _, err := c.S3.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucket),
		Policy: aws.String(string(bucketPolicyJSON)),
	}); err != nil {
		return err
	}

	// Set lifecycle rule to purge incomplete multipart upload orphaned because of force shutdown or rescheduling or networking issue with etcd-backup-restore.
	putBucketLifecycleConfigurationInput := &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
		LifecycleConfiguration: &s3types.BucketLifecycleConfiguration{
			Rules: []s3types.LifecycleRule{
				{
					// Note: Though as per documentation at https://docs.aws.amazon.com/AmazonS3/latest/API/API_LifecycleRule.html the Filter field is
					// optional, if not specified the SDK API fails with `Malformed XML` error code. Cross verified same behavior with aws-cli client as well.
					// Please do not remove it.
					Filter: &s3types.LifecycleRuleFilter{Prefix: ptr.To("")},
					AbortIncompleteMultipartUpload: &s3types.AbortIncompleteMultipartUpload{
						DaysAfterInitiation: aws.Int32(7),
					},
					Status: s3types.ExpirationStatusEnabled,
				},
			},
		},
	}

	if _, err = c.S3.PutBucketLifecycleConfiguration(ctx, putBucketLifecycleConfigurationInput); err != nil {
		return err
	}

	return err
}

// DeleteBucketIfExists deletes the s3 bucket with name <bucket>. If it does not exist,
// no error is returned.
func (c *Client) DeleteBucketIfExists(ctx context.Context, bucket string) error {
	if _, err := c.S3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		apiErrCode := GetAWSAPIErrorCode(err)
		switch apiErrCode {
		case NoSuchBucket, PermanentRedirect:
			// No action required: either the bucket doesn't exist or it exists in a different region and wasn't created.
			return nil
		case BucketNotEmpty:
			if err := c.DeleteObjectsWithPrefix(ctx, bucket, ""); err != nil {
				return err
			}
			return c.DeleteBucketIfExists(ctx, bucket)
		default:
			return err
		}
	}
	return nil
}

// GetBucketVersioningStatus is wrapper for S3's API GetBucketVersioning to get bucket versioning status
func (c *Client) GetBucketVersioningStatus(ctx context.Context, bucket string) (*s3.GetBucketVersioningOutput, error) {
	bucketVersioningStatus, err := c.S3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})

	return bucketVersioningStatus, err
}

// EnableBucketVersioning enables the versioning on the given bucket.
func (c *Client) EnableBucketVersioning(ctx context.Context, bucket string) error {
	input := &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucket),
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: s3types.BucketVersioningStatusEnabled,
		},
	}

	if _, err := c.S3.PutBucketVersioning(ctx, input); err != nil {
		return err
	}
	return nil
}

// GetObjectLockConfiguration is wrapper for S3's API GetObjectLockConfiguration to get object lock settings.
func (c *Client) GetObjectLockConfiguration(ctx context.Context, bucket string) (*s3.GetObjectLockConfigurationOutput, error) {
	objectConfig, err := c.S3.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(bucket),
	})

	return objectConfig, err
}

// UpdateObjectLockConfiguration updates the object lock configuration on the bucket.
func (c *Client) UpdateObjectLockConfiguration(ctx context.Context, bucket string, mode apisaws.ModeType, days int32) error {
	input := &s3.PutObjectLockConfigurationInput{
		Bucket: &bucket,
		ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
			ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
			Rule: &s3types.ObjectLockRule{
				DefaultRetention: &s3types.DefaultRetention{
					// #nosec G115
					Days: aws.Int32(days),
					Mode: GetBucketRetentiontMode(mode),
				},
			},
		},
	}
	if _, err := c.S3.PutObjectLockConfiguration(ctx, input); err != nil {
		return err
	}

	return nil
}

// RemoveObjectLockConfiguration removes the object lock configuration rules from bucket.
// Note: Object lock can't be disabled in S3, only object lock configuration rules can be removed from bucket.
func (c *Client) RemoveObjectLockConfiguration(ctx context.Context, bucket string) error {
	input := &s3.PutObjectLockConfigurationInput{
		Bucket: &bucket,
		ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
			ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
		},
	}
	if _, err := c.S3.PutObjectLockConfiguration(ctx, input); err != nil {
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

	paginator := elb.NewDescribeLoadBalancersPaginator(&c.ELB, &elb.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, description := range output.LoadBalancerDescriptions {
			if description.VPCId != nil && *description.VPCId == vpcID {
				loadBalancerNamesInVPC = append(loadBalancerNamesInVPC, description.LoadBalancerName)
			}
		}
	}

	if len(loadBalancerNamesInVPC) == 0 {
		return nil, nil
	}

	const chunkSize = 20
	loadBalancerNamesChunks := chunkSlice(loadBalancerNamesInVPC, chunkSize)
	for _, loadBalancerNamesChunk := range loadBalancerNamesChunks {
		tags, err := c.ELB.DescribeTags(ctx, &elb.DescribeTagsInput{LoadBalancerNames: aws.ToStringSlice(loadBalancerNamesChunk)})
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
	_, err := c.ELB.DeleteLoadBalancer(ctx, &elb.DeleteLoadBalancerInput{LoadBalancerName: aws.String(name)})
	return ignoreNotFound(err)
}

// ListKubernetesELBsV2 returns the list of ELBv2 loadbalancers in the given <vpcID> tagged with <clusterName>.
func (c *Client) ListKubernetesELBsV2(ctx context.Context, vpcID, clusterName string) ([]string, error) {
	var (
		loadBalancerARNsInVPC      []*string
		loadBalancerARNsForCluster []string
	)

	paginator := elbv2.NewDescribeLoadBalancersPaginator(&c.ELBv2, &elbv2.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, lb := range output.LoadBalancers {
			if lb.VpcId != nil && *lb.VpcId == vpcID {
				loadBalancerARNsInVPC = append(loadBalancerARNsInVPC, lb.LoadBalancerArn)
			}
		}
	}

	if len(loadBalancerARNsInVPC) == 0 {
		return nil, nil
	}

	const chunkSize = 20
	loadBalancerARNsChunks := chunkSlice(loadBalancerARNsInVPC, chunkSize)
	for _, loadBalancerARNsChunk := range loadBalancerARNsChunks {
		tags, err := c.ELBv2.DescribeTags(ctx, &elbv2.DescribeTagsInput{ResourceArns: aws.ToStringSlice(loadBalancerARNsChunk)})
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
	targetGroups, err := c.ELBv2.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{LoadBalancerArn: &arn})
	if err != nil {
		return fmt.Errorf("could not list loadbalancer target groups for arn %s: %w", arn, err)
	}

	if _, err := c.ELBv2.DeleteLoadBalancer(ctx, &elbv2.DeleteLoadBalancerInput{LoadBalancerArn: &arn}); ignoreNotFound(err) != nil {
		return fmt.Errorf("could not delete loadbalancer for arn %s: %w", arn, err)
	}

	for _, group := range targetGroups.TargetGroups {
		if _, err := c.ELBv2.DeleteTargetGroup(ctx, &elbv2.DeleteTargetGroupInput{TargetGroupArn: group.TargetGroupArn}); err != nil {
			return fmt.Errorf("could not delete target groups after deleting loadbalancer for arn %s: %w", arn, err)
		}
	}

	return nil
}

// ListKubernetesSecurityGroups returns the list of security groups in the given <vpcID> tagged with <clusterName>.
func (c *Client) ListKubernetesSecurityGroups(ctx context.Context, vpcID, clusterName string) ([]string, error) {
	groups, err := c.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String(FilterVpcID),
				Values: []string{vpcID}},
			{
				Name:   aws.String("tag-key"),
				Values: []string{fmt.Sprintf("kubernetes.io/cluster/%s", clusterName)}},
			{
				Name:   aws.String("tag-value"),
				Values: []string{"owned"}},
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
	var newConfigs []ec2types.NewDhcpConfiguration

	for key, values := range options.DhcpConfigurations {
		newConfigs = append(newConfigs, ec2types.NewDhcpConfiguration{
			Key:    aws.String(key),
			Values: values,
		})
	}
	input := &ec2.CreateDhcpOptionsInput{
		DhcpConfigurations: newConfigs,
		TagSpecifications:  options.ToTagSpecifications(ec2types.ResourceTypeDhcpOptions),
	}
	output, err := c.EC2.CreateDhcpOptions(ctx, input)
	if err != nil {
		return nil, err
	}
	return fromDhcpOptions(output.DhcpOptions), nil
}

// GetVpcDhcpOptions gets a DHCP option resource by identifier.
func (c *Client) GetVpcDhcpOptions(ctx context.Context, id string) (*DhcpOptions, error) {
	input := &ec2.DescribeDhcpOptionsInput{DhcpOptionsIds: []string{id}}
	output, err := c.describeVpcDhcpOptions(ctx, input)
	return single(output, err)
}

// FindVpcDhcpOptionsByTags finds DHCP option resources matching the given tag map.
func (c *Client) FindVpcDhcpOptionsByTags(ctx context.Context, tags Tags) ([]*DhcpOptions, error) {
	input := &ec2.DescribeDhcpOptionsInput{Filters: tags.ToFilters()}
	return c.describeVpcDhcpOptions(ctx, input)
}

func (c *Client) describeVpcDhcpOptions(ctx context.Context, input *ec2.DescribeDhcpOptionsInput) ([]*DhcpOptions, error) {
	output, err := c.EC2.DescribeDhcpOptions(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var options []*DhcpOptions
	for _, item := range output.DhcpOptions {
		options = append(options, fromDhcpOptions(&item))
	}
	return options, nil
}

// DeleteVpcDhcpOptions deletes a DHCP option resource by identifier.
// Returns nil, if the resource is not found.
func (c *Client) DeleteVpcDhcpOptions(ctx context.Context, id string) error {
	_, err := c.EC2.DeleteDhcpOptions(ctx, &ec2.DeleteDhcpOptionsInput{DhcpOptionsId: aws.String(id)})
	return ignoreNotFound(err)
}

// RetryableIPv6CIDRError is a custom error type.
type RetryableIPv6CIDRError struct{}

// Error prints the error message of the RetryableIPv6CIDRError error.
func (e *RetryableIPv6CIDRError) Error() string {
	return "no ipv6 CIDR assigned"
}

// IsRetryableIPv6CIDRError returns true if the error indicates that getting the IPv6 CIDR can be retried.
func IsRetryableIPv6CIDRError(err error) bool {
	_, ok := err.(*RetryableIPv6CIDRError)
	return ok
}

// CreateVpc creates a VPC resource.
func (c *Client) CreateVpc(ctx context.Context, desired *VPC) (*VPC, error) {
	input := &ec2.CreateVpcInput{
		CidrBlock:                   aws.String(desired.CidrBlock),
		AmazonProvidedIpv6CidrBlock: aws.Bool(desired.AssignGeneratedIPv6CidrBlock),
		TagSpecifications:           desired.ToTagSpecifications(ec2types.ResourceTypeVpc),
		InstanceTenancy:             desired.InstanceTenancy,
	}
	output, err := c.EC2.CreateVpc(ctx, input)
	if err != nil {
		return nil, err
	}
	vpcID := *output.Vpc.VpcId
	return c.GetVpc(ctx, vpcID)
}

// WaitForIPv6Cidr waits for the ipv6 cidr block association
func (c *Client) WaitForIPv6Cidr(ctx context.Context, vpcID string) (string, error) {
	maxRetries := 30
	waitInterval := 10 * time.Second
	for i := 0; i < maxRetries; i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(waitInterval):
			ipv6CidrBlock, err := c.GetIPv6Cidr(ctx, vpcID)
			if err == nil {
				return ipv6CidrBlock, nil
			}
			if !IsRetryableIPv6CIDRError(err) {
				return "", err
			}
		}
	}
	return "", fmt.Errorf("no IPv6 CIDR Block was assigned to VPC")
}

// GetIPv6Cidr returns the IPv6 CIDR block for the given VPC ID.
func (c *Client) GetIPv6Cidr(ctx context.Context, vpcID string) (string, error) {
	var ipv6CidrBlock string
	describeVPCInput := &ec2.DescribeVpcsInput{
		VpcIds: []string{vpcID},
	}
	resp, err := c.EC2.DescribeVpcs(ctx, describeVPCInput)
	if err != nil {
		return "", fmt.Errorf("error describing VPC: %v", err)
	}
	if len(resp.Vpcs) > 0 {
		for _, assoc := range resp.Vpcs[0].Ipv6CidrBlockAssociationSet {
			if assoc.Ipv6CidrBlockState.State == ec2types.VpcCidrBlockStateCodeAssociated {
				ipv6CidrBlock = *assoc.Ipv6CidrBlock
				vpc, err := c.GetVpc(ctx, vpcID)
				if err != nil {
					return "", err
				}
				vpc.IPv6CidrBlock = ipv6CidrBlock
				return ipv6CidrBlock, nil
			}
		}
	}
	return "", &RetryableIPv6CIDRError{}
}

// UpdateVpcAttribute sets/updates a VPC attribute if needed.
// Supported attribute names are
// `enableDnsSupport` (const ec2.VpcAttributeNameEnableDnsSupport) and
// `enableDnsHostnames` (const ec2.VpcAttributeNameEnableDnsHostnames) and
func (c *Client) UpdateVpcAttribute(ctx context.Context, vpcId, attributeName string, value bool) error {
	switch attributeName {
	case string(ec2types.VpcAttributeNameEnableDnsSupport):
		input := &ec2.ModifyVpcAttributeInput{
			EnableDnsSupport: &ec2types.AttributeBooleanValue{
				Value: aws.Bool(value),
			},
			VpcId: aws.String(vpcId),
		}
		if _, err := c.EC2.ModifyVpcAttribute(ctx, input); err != nil {
			return err
		}
		if err := c.PollImmediateUntil(ctx, func(ctx context.Context) (bool, error) {
			b, err := c.describeVpcAttributeWithContext(ctx, aws.String(vpcId), string(ec2types.VpcAttributeNameEnableDnsSupport))
			return b == value, err
		}); err != nil {
			return err
		}
		return nil
	case string(ec2types.VpcAttributeNameEnableDnsHostnames):
		input := &ec2.ModifyVpcAttributeInput{
			EnableDnsHostnames: &ec2types.AttributeBooleanValue{
				Value: aws.Bool(value),
			},
			VpcId: aws.String(vpcId),
		}
		if _, err := c.EC2.ModifyVpcAttribute(ctx, input); err != nil {
			return err
		}
		if err := c.PollImmediateUntil(ctx, func(ctx context.Context) (bool, error) {
			b, err := c.describeVpcAttributeWithContext(ctx, aws.String(vpcId), string(ec2types.VpcAttributeNameEnableDnsHostnames))
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
		VpcIds: []string{vpcID},
	}
	output, err := c.EC2.DescribeVpcs(context.TODO(), input)
	if err != nil {
		return false, err
	}
	if len(output.Vpcs) == 0 {
		return false, fmt.Errorf("VPC not found")
	}
	vpc := output.Vpcs[0]
	for _, cidr := range vpc.Ipv6CidrBlockAssociationSet {
		if cidr.Ipv6CidrBlockState.State == ec2types.VpcCidrBlockStateCodeAssociated {
			return true, nil
		}
	}
	return false, nil
}

// UpdateAmazonProvidedIPv6CidrBlock sets/updates the amazon provided IPv6 blocks.
func (c *Client) UpdateAmazonProvidedIPv6CidrBlock(ctx context.Context, desired *VPC, current *VPC) (bool, error) {
	modified := false
	if current.VpcId != "" && desired.AssignGeneratedIPv6CidrBlock != current.AssignGeneratedIPv6CidrBlock {
		ipv6CidrBlockAssociated, err := c.CheckVpcIPv6Cidr(current.VpcId)
		if err != nil {
			return modified, err
		}
		if !ipv6CidrBlockAssociated {
			input := &ec2.AssociateVpcCidrBlockInput{
				VpcId: aws.String(current.VpcId),
			}
			input.AmazonProvidedIpv6CidrBlock = aws.Bool(desired.AssignGeneratedIPv6CidrBlock)
			_, err := c.EC2.AssociateVpcCidrBlock(ctx, input)
			if err != nil {
				return modified, err
			}
			modified = true
		}
	}
	return modified, nil
}

// AddVpcDhcpOptionAssociation associates existing DHCP options resource to VPC resource, both identified by id.
func (c *Client) AddVpcDhcpOptionAssociation(vpcId string, dhcpOptionsId *string) error {
	if dhcpOptionsId == nil {
		// AWS does not provide an API to disassociate a DHCP Options set from a VPC.
		// So, we do this by setting the VPC to the default DHCP Options Set.
		dhcpOptionsId = aws.String("default")
	}
	_, err := c.EC2.AssociateDhcpOptions(context.TODO(), &ec2.AssociateDhcpOptionsInput{
		DhcpOptionsId: dhcpOptionsId,
		VpcId:         aws.String(vpcId),
	})
	return err
}

// DeleteVpc deletes a VPC resource by identifier.
// Returns nil, if the resource is not found.
func (c *Client) DeleteVpc(ctx context.Context, id string) error {
	_, err := c.EC2.DeleteVpc(ctx, &ec2.DeleteVpcInput{VpcId: aws.String(id)})
	return ignoreNotFound(err)
}

// GetVpc gets a VPC resource by identifier.
// Returns nil, if the resource is not found.
func (c *Client) GetVpc(ctx context.Context, id string) (*VPC, error) {
	input := &ec2.DescribeVpcsInput{VpcIds: []string{id}}
	output, err := c.describeVpcs(ctx, input)
	return single(output, err)
}

// FindVpcsByTags finds VPC resources matching the given tag map.
func (c *Client) FindVpcsByTags(ctx context.Context, tags Tags) ([]*VPC, error) {
	input := &ec2.DescribeVpcsInput{Filters: tags.ToFilters()}
	return c.describeVpcs(ctx, input)
}

func (c *Client) describeVpcs(ctx context.Context, input *ec2.DescribeVpcsInput) ([]*VPC, error) {
	output, err := c.EC2.DescribeVpcs(ctx, input)
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

func (c *Client) fromVpc(ctx context.Context, item ec2types.Vpc, withAttributes bool) (*VPC, error) {
	vpc := &VPC{
		VpcId:     aws.ToString(item.VpcId),
		Tags:      FromTags(item.Tags),
		CidrBlock: aws.ToString(item.CidrBlock),
		IPv6CidrBlock: func() string {
			if item.Ipv6CidrBlockAssociationSet != nil {
				return aws.ToString(item.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock)
			}
			return ""
		}(),
		DhcpOptionsId:   item.DhcpOptionsId,
		InstanceTenancy: item.InstanceTenancy,
		State:           ptr.To(string(item.State)),
	}
	var err error
	if withAttributes {
		if vpc.EnableDnsHostnames, err = c.describeVpcAttributeWithContext(ctx, item.VpcId, string(ec2types.VpcAttributeNameEnableDnsHostnames)); err != nil {
			return nil, err
		}
		if vpc.EnableDnsSupport, err = c.describeVpcAttributeWithContext(ctx, item.VpcId, string(ec2types.VpcAttributeNameEnableDnsSupport)); err != nil {
			return nil, err
		}
	}
	return vpc, nil
}

func (c *Client) describeVpcAttributeWithContext(ctx context.Context, vpcId *string, attributeName string) (bool, error) {
	output, err := c.EC2.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		Attribute: ec2types.VpcAttributeName(attributeName),
		VpcId:     vpcId,
	})
	if err != nil {
		return false, ignoreNotFound(err)
	}
	switch attributeName {
	case string(ec2types.VpcAttributeNameEnableDnsHostnames):
		return *output.EnableDnsHostnames.Value, nil
	case string(ec2types.VpcAttributeNameEnableDnsSupport):
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
		TagSpecifications: sg.ToTagSpecifications(ec2types.ResourceTypeSecurityGroup),
		VpcId:             sg.VpcId,
		Description:       sg.Description,
	}
	output, err := c.EC2.CreateSecurityGroup(ctx, input)
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
		if _, err := c.EC2.AuthorizeSecurityGroupIngress(ctx, input); err != nil {
			return err
		}
	}
	if len(egressPermissions) > 0 {
		input := &ec2.AuthorizeSecurityGroupEgressInput{
			GroupId:       aws.String(groupId),
			IpPermissions: egressPermissions,
		}
		if _, err := c.EC2.AuthorizeSecurityGroupEgress(ctx, input); err != nil {
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
		if _, err := c.EC2.RevokeSecurityGroupIngress(ctx, input); err != nil {
			return err
		}
	}
	if len(egressPermissions) > 0 {
		input := &ec2.RevokeSecurityGroupEgressInput{
			GroupId:       aws.String(groupId),
			IpPermissions: egressPermissions,
		}
		if _, err := c.EC2.RevokeSecurityGroupEgress(ctx, input); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) prepareRules(groupId string, rules []*SecurityGroupRule) (ingressPermissions, egressPermissions []ec2types.IpPermission, err error) {
	for _, rule := range rules {
		var ipPerm ec2types.IpPermission
		if rule.Foreign != nil {
			ipPerm = ec2types.IpPermission{}
			if err = json.Unmarshal([]byte(*rule.Foreign), &ipPerm); err != nil {
				return
			}
		} else {
			ipPerm = ec2types.IpPermission{
				IpProtocol:       aws.String(rule.Protocol),
				IpRanges:         nil,
				Ipv6Ranges:       nil,
				PrefixListIds:    nil,
				UserIdGroupPairs: nil,
				FromPort:         rule.FromPort,
				ToPort:           rule.ToPort,
			}
			for _, block := range rule.CidrBlocks {
				ipPerm.IpRanges = append(ipPerm.IpRanges, ec2types.IpRange{CidrIp: aws.String(block)})
			}
			for _, block := range rule.CidrBlocksv6 {
				ipPerm.Ipv6Ranges = append(ipPerm.Ipv6Ranges, ec2types.Ipv6Range{CidrIpv6: aws.String(block)})
			}
			if rule.Self {
				ipPerm.UserIdGroupPairs = []ec2types.UserIdGroupPair{
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
	input := &ec2.DescribeSecurityGroupsInput{GroupIds: []string{id}}
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
	output, err := c.EC2.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var sgList []*SecurityGroup
	for _, item := range output.SecurityGroups {
		sg := &SecurityGroup{
			Tags:        FromTags(item.Tags),
			GroupId:     aws.ToString(item.GroupId),
			GroupName:   aws.ToString(item.GroupName),
			VpcId:       item.VpcId,
			Description: item.Description,
		}
		for _, ipPerm := range item.IpPermissions {
			rule, err := fromIpPermission(aws.ToString(item.GroupId), ipPerm, SecurityGroupRuleTypeIngress)
			if err != nil {
				return nil, err
			}
			sg.Rules = append(sg.Rules, rule)
		}
		for _, ipPerm := range item.IpPermissionsEgress {
			rule, err := fromIpPermission(aws.ToString(item.GroupId), ipPerm, SecurityGroupRuleTypeEgress)
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
		Filters: []ec2types.Filter{
			{Name: aws.String(FilterVpcID), Values: []string{vpcId}},
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
	_, err := c.EC2.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(id)})
	return ignoreNotFound(err)
}

// CreateInternetGateway creates an internet gateway.
func (c *Client) CreateInternetGateway(ctx context.Context, gateway *InternetGateway) (*InternetGateway, error) {
	input := &ec2.CreateInternetGatewayInput{
		TagSpecifications: gateway.ToTagSpecifications(ec2types.ResourceTypeInternetGateway),
	}
	output, err := c.EC2.CreateInternetGateway(ctx, input)
	if err != nil {
		return nil, err
	}
	return &InternetGateway{
		Tags:              FromTags(output.InternetGateway.Tags),
		InternetGatewayId: aws.ToString(output.InternetGateway.InternetGatewayId),
	}, nil
}

// AttachInternetGateway attaches an internet gateway to a VPC.
// Returns no error, if the internet gateway is already attached to the VPC.
func (c *Client) AttachInternetGateway(ctx context.Context, vpcId, internetGatewayId string) error {
	input := &ec2.AttachInternetGatewayInput{
		InternetGatewayId: aws.String(internetGatewayId),
		VpcId:             aws.String(vpcId),
	}
	_, err := c.EC2.AttachInternetGateway(ctx, input)
	return ignoreAlreadyAssociated(err)
}

// DetachInternetGateway detaches an internet gateway to a VPC.
// Returns no error, if the internet gateway is already detached.
func (c *Client) DetachInternetGateway(ctx context.Context, vpcId, internetGatewayId string) error {
	input := &ec2.DetachInternetGatewayInput{
		InternetGatewayId: aws.String(internetGatewayId),
		VpcId:             aws.String(vpcId),
	}
	_, err := c.EC2.DetachInternetGateway(ctx, input)
	return err
}

// GetInternetGateway gets an internet gateway resource by identifier.
func (c *Client) GetInternetGateway(ctx context.Context, id string) (*InternetGateway, error) {
	input := &ec2.DescribeInternetGatewaysInput{InternetGatewayIds: []string{id}}
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
	input := &ec2.DescribeInternetGatewaysInput{Filters: []ec2types.Filter{{
		Name:   aws.String("attachment.vpc-id"),
		Values: []string{vpcId},
	}}}
	output, err := c.describeInternetGateways(ctx, input)
	return single(output, err)
}

func (c *Client) describeInternetGateways(ctx context.Context, input *ec2.DescribeInternetGatewaysInput) ([]*InternetGateway, error) {
	output, err := c.EC2.DescribeInternetGateways(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var gateways []*InternetGateway
	for _, item := range output.InternetGateways {
		gw := &InternetGateway{
			Tags:              FromTags(item.Tags),
			InternetGatewayId: aws.ToString(item.InternetGatewayId),
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
	_, err := c.EC2.DeleteInternetGateway(ctx, input)
	return ignoreNotFound(err)
}

// CreateEgressOnlyInternetGateway creates an egress-only internet gateway.
func (c *Client) CreateEgressOnlyInternetGateway(ctx context.Context, gateway *EgressOnlyInternetGateway) (*EgressOnlyInternetGateway, error) {
	input := &ec2.CreateEgressOnlyInternetGatewayInput{
		TagSpecifications: gateway.ToTagSpecifications(ec2types.ResourceTypeEgressOnlyInternetGateway),
		VpcId:             gateway.VpcId,
	}
	output, err := c.EC2.CreateEgressOnlyInternetGateway(ctx, input)
	if err != nil {
		return nil, err
	}
	return &EgressOnlyInternetGateway{
		Tags:                        FromTags(output.EgressOnlyInternetGateway.Tags),
		EgressOnlyInternetGatewayId: aws.ToString(output.EgressOnlyInternetGateway.EgressOnlyInternetGatewayId),
	}, nil
}

// GetEgressOnlyInternetGateway gets an internet gateway resource by identifier.
func (c *Client) GetEgressOnlyInternetGateway(ctx context.Context, id string) (*EgressOnlyInternetGateway, error) {
	input := &ec2.DescribeEgressOnlyInternetGatewaysInput{EgressOnlyInternetGatewayIds: []string{id}}
	output, err := c.describeEgressOnlyInternetGateways(ctx, input)
	return single(output, err)
}

// FindEgressOnlyInternetGatewaysByTags finds internet gateway resources matching the given tag map.
func (c *Client) FindEgressOnlyInternetGatewaysByTags(ctx context.Context, tags Tags) ([]*EgressOnlyInternetGateway, error) {
	input := &ec2.DescribeEgressOnlyInternetGatewaysInput{Filters: tags.ToFilters()}
	return c.describeEgressOnlyInternetGateways(ctx, input)
}

// FindEgressOnlyInternetGatewayByVPC finds an internet gateway resource attached to the given VPC.
func (c *Client) FindEgressOnlyInternetGatewayByVPC(ctx context.Context, vpcId string) (*EgressOnlyInternetGateway, error) {
	input := &ec2.DescribeEgressOnlyInternetGatewaysInput{}
	output, err := c.describeEgressOnlyInternetGateways(ctx, input)
	if err != nil {
		return nil, err
	}
	for _, eoig := range output {
		if *eoig.VpcId == vpcId {
			return eoig, nil
		}
	}
	return nil, nil
}

func (c *Client) describeEgressOnlyInternetGateways(ctx context.Context, input *ec2.DescribeEgressOnlyInternetGatewaysInput) ([]*EgressOnlyInternetGateway, error) {
	output, err := c.EC2.DescribeEgressOnlyInternetGateways(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var gateways []*EgressOnlyInternetGateway
	for _, item := range output.EgressOnlyInternetGateways {
		gw := &EgressOnlyInternetGateway{
			Tags:                        FromTags(item.Tags),
			EgressOnlyInternetGatewayId: aws.ToString(item.EgressOnlyInternetGatewayId),
		}
		for _, attachment := range item.Attachments {
			gw.VpcId = attachment.VpcId
			break
		}
		gateways = append(gateways, gw)
	}
	return gateways, nil
}

// DeleteEgressOnlyInternetGateway deletes an egress only internet gateway resource.
// Returns nil, if the resource is not found.
func (c *Client) DeleteEgressOnlyInternetGateway(ctx context.Context, id string) error {
	input := &ec2.DeleteEgressOnlyInternetGatewayInput{
		EgressOnlyInternetGatewayId: aws.String(id),
	}
	_, err := c.EC2.DeleteEgressOnlyInternetGateway(ctx, input)
	return ignoreNotFound(err)
}

// CreateVpcEndpoint creates an EC2 VPC endpoint resource.
func (c *Client) CreateVpcEndpoint(ctx context.Context, endpoint *VpcEndpoint) (*VpcEndpoint, error) {
	input := &ec2.CreateVpcEndpointInput{
		ServiceName: aws.String(endpoint.ServiceName),
		// TagSpecifications: endpoint.ToTagSpecifications(ec2.ResourceTypeClientVpnEndpoint),
		VpcId: endpoint.VpcId,
	}
	output, err := c.EC2.CreateVpcEndpoint(ctx, input)
	if err != nil {
		return nil, err
	}
	return &VpcEndpoint{
		// Tags:          FromTags(output.VpcEndpoint.Tags),
		VpcEndpointId: aws.ToString(output.VpcEndpoint.VpcEndpointId),
		VpcId:         output.VpcEndpoint.VpcId,
		ServiceName:   aws.ToString(output.VpcEndpoint.ServiceName),
	}, nil
}

// GetVpcEndpoints gets VPC endpoint resources by identifiers.
// Non-existing identifiers are silently ignored.
func (c *Client) GetVpcEndpoints(ctx context.Context, ids []string) ([]*VpcEndpoint, error) {
	input := &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: ids}
	return c.describeVpcEndpoints(ctx, input)
}

// FindVpcEndpoints finds VPC endpoint resources matching the given filters.
func (c *Client) FindVpcEndpoints(ctx context.Context, filters []ec2types.Filter) ([]*VpcEndpoint, error) {
	input := &ec2.DescribeVpcEndpointsInput{Filters: filters}
	return c.describeVpcEndpoints(ctx, input)
}

func (c *Client) describeVpcEndpoints(ctx context.Context, input *ec2.DescribeVpcEndpointsInput) ([]*VpcEndpoint, error) {
	output, err := c.EC2.DescribeVpcEndpoints(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var endpoints []*VpcEndpoint
	for _, item := range output.VpcEndpoints {
		endpoint := &VpcEndpoint{
			Tags:          FromTags(item.Tags),
			VpcEndpointId: aws.ToString(item.VpcEndpointId),
			VpcId:         item.VpcId,
			ServiceName:   aws.ToString(item.ServiceName),
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

// DeleteVpcEndpoint deletes a VPC endpoint by id.
// Returns nil if resource is not found.
func (c *Client) DeleteVpcEndpoint(ctx context.Context, id string) error {
	input := &ec2.DeleteVpcEndpointsInput{
		VpcEndpointIds: []string{id},
	}
	_, err := c.EC2.DeleteVpcEndpoints(ctx, input)
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
		AddRouteTableIds: []string{routeTableId},
	}
	_, err = c.EC2.ModifyVpcEndpoint(ctx, input)
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
				RemoveRouteTableIds: []string{routeTableId},
			}
			_, err = c.EC2.ModifyVpcEndpoint(ctx, input)
			return err
		}
	}
	return nil
}

// CreateRouteTable creates an EC2 route table resource.
// Routes specified in the input object are ignored.
func (c *Client) CreateRouteTable(ctx context.Context, routeTable *RouteTable) (*RouteTable, error) {
	input := &ec2.CreateRouteTableInput{
		TagSpecifications: routeTable.ToTagSpecifications(ec2types.ResourceTypeRouteTable),
		VpcId:             routeTable.VpcId,
	}
	output, err := c.EC2.CreateRouteTable(ctx, input)
	if err != nil {
		return nil, err
	}
	created := &RouteTable{
		Tags:         FromTags(output.RouteTable.Tags),
		RouteTableId: aws.ToString(output.RouteTable.RouteTableId),
		VpcId:        output.RouteTable.VpcId,
	}

	return created, nil
}

// CreateRoute creates a route for the given route table.
func (c *Client) CreateRoute(ctx context.Context, routeTableId string, route *Route) error {
	input := &ec2.CreateRouteInput{
		DestinationCidrBlock:        route.DestinationCidrBlock,
		DestinationIpv6CidrBlock:    route.DestinationIpv6CidrBlock,
		DestinationPrefixListId:     route.DestinationPrefixListId,
		GatewayId:                   route.GatewayId,
		NatGatewayId:                route.NatGatewayId,
		EgressOnlyInternetGatewayId: route.EgressOnlyInternetGatewayId,
		RouteTableId:                aws.String(routeTableId),
	}
	_, err := c.EC2.CreateRoute(ctx, input)
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
	_, err := c.EC2.DeleteRoute(ctx, input)
	return err
}

// GetRouteTable gets a route table by the identifier.
func (c *Client) GetRouteTable(ctx context.Context, id string) (*RouteTable, error) {
	input := &ec2.DescribeRouteTablesInput{RouteTableIds: []string{id}}
	output, err := c.describeRouteTables(ctx, input)
	return single(output, err)
}

// FindRouteTablesByTags finds routing table resources matching the given tag map.
func (c *Client) FindRouteTablesByTags(ctx context.Context, tags Tags) ([]*RouteTable, error) {
	input := &ec2.DescribeRouteTablesInput{Filters: tags.ToFilters()}
	return c.describeRouteTables(ctx, input)
}

func (c *Client) describeRouteTables(ctx context.Context, input *ec2.DescribeRouteTablesInput) ([]*RouteTable, error) {
	output, err := c.EC2.DescribeRouteTables(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var tables []*RouteTable
	for _, item := range output.RouteTables {
		table := &RouteTable{
			Tags:         FromTags(item.Tags),
			RouteTableId: aws.ToString(item.RouteTableId),
			VpcId:        item.VpcId,
		}
		for _, route := range item.Routes {
			table.Routes = append(table.Routes, &Route{
				DestinationCidrBlock:        route.DestinationCidrBlock,
				GatewayId:                   route.GatewayId,
				NatGatewayId:                route.NatGatewayId,
				EgressOnlyInternetGatewayId: route.EgressOnlyInternetGatewayId,
				DestinationPrefixListId:     route.DestinationPrefixListId,
				DestinationIpv6CidrBlock:    route.DestinationIpv6CidrBlock,
			})
		}
		for _, assoc := range item.Associations {
			table.Associations = append(table.Associations, &RouteTableAssociation{
				RouteTableAssociationId: aws.ToString(assoc.RouteTableAssociationId),
				Main:                    aws.ToBool(assoc.Main),
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
	_, err := c.EC2.DeleteRouteTable(ctx, input)
	return ignoreNotFound(err)
}

// CreateSubnet creates an EC2 subnet resource.
func (c *Client) CreateSubnet(ctx context.Context, subnet *Subnet, maxWaitDur time.Duration) (*Subnet, error) {
	input := &ec2.CreateSubnetInput{
		AvailabilityZone:  aws.String(subnet.AvailabilityZone),
		TagSpecifications: subnet.ToTagSpecifications(ec2types.ResourceTypeSubnet),
		VpcId:             subnet.VpcId,
		Ipv6Native:        subnet.Ipv6Native,
	}

	if subnet.CidrBlock != "" && (subnet.Ipv6Native == nil || !*subnet.Ipv6Native) {
		input.CidrBlock = aws.String(subnet.CidrBlock)
	}

	if subnet.Ipv6CidrBlocks != nil && subnet.Ipv6CidrBlocks[0] != "" {
		input.Ipv6CidrBlock = aws.String(subnet.Ipv6CidrBlocks[0])
	}
	output, err := c.EC2.CreateSubnet(ctx, input)
	if err != nil {
		return nil, err
	}
	if output.Subnet == nil || output.Subnet.SubnetId == nil {
		return nil, fmt.Errorf("subnet creation failed, no SubnetId returned")
	}

	// wait until the subnet is available
	waiter := ec2.NewSubnetAvailableWaiter(&c.EC2)
	err = waiter.Wait(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{*output.Subnet.SubnetId}}, maxWaitDur,
		func(o *ec2.SubnetAvailableWaiterOptions) {
			o.MinDelay = 5 * time.Second  // Optional; defaults to 15s if not set
			o.MaxDelay = 60 * time.Second // Optional; defaults to 120s if not set
		})
	if err != nil {
		return nil, fmt.Errorf("subnet %s did not become available: %w", *output.Subnet.SubnetId, err)
	}

	return fromSubnet(output.Subnet), nil
}

// CreateCIDRReservation creates a EC2 subnet cidr reservation resource.
func (c *Client) CreateCIDRReservation(ctx context.Context, subnet *Subnet, cidr string, reservationType string) (string, error) {
	input := &ec2.CreateSubnetCidrReservationInput{
		SubnetId:        &subnet.SubnetId,
		Cidr:            aws.String(cidr),
		ReservationType: ec2types.SubnetCidrReservationType(reservationType),
	}

	output, err := c.EC2.CreateSubnetCidrReservation(ctx, input)
	if err != nil {
		return "", err
	}
	return *output.SubnetCidrReservation.Cidr, nil
}

// GetIPv6CIDRReservations gets the IPv6 CIDR reservations for the given subnet.
func (c *Client) GetIPv6CIDRReservations(ctx context.Context, subnet *Subnet) ([]string, error) {
	input := &ec2.GetSubnetCidrReservationsInput{
		SubnetId: &subnet.SubnetId,
	}

	output, err := c.EC2.GetSubnetCidrReservations(ctx, input)
	if err != nil {
		return nil, err
	}
	var cidrs []string
	for _, cidrReservation := range output.SubnetIpv6CidrReservations {
		if cidrReservation.Cidr != nil {
			cidrs = append(cidrs, *cidrReservation.Cidr)
		}
	}
	return cidrs, nil
}

// GetSubnets gets subnets for the given identifiers.
// Non-existing identifiers are ignored silently.
func (c *Client) GetSubnets(ctx context.Context, ids []string) ([]*Subnet, error) {
	input := &ec2.DescribeSubnetsInput{SubnetIds: ids}
	return c.describeSubnets(ctx, input)
}

// FindSubnetsByTags finds subnet resources matching the given tag map.
func (c *Client) FindSubnetsByTags(ctx context.Context, tags Tags) ([]*Subnet, error) {
	input := &ec2.DescribeSubnetsInput{Filters: tags.ToFilters()}
	return c.describeSubnets(ctx, input)
}

// FindSubnets finds subnets matching the given filters.
func (c *Client) FindSubnets(ctx context.Context, filters []ec2types.Filter) ([]*Subnet, error) {
	input := &ec2.DescribeSubnetsInput{Filters: filters}
	return c.describeSubnets(ctx, input)
}

func (c *Client) describeSubnets(ctx context.Context, input *ec2.DescribeSubnetsInput) ([]*Subnet, error) {
	output, err := c.EC2.DescribeSubnets(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var subnets []*Subnet
	for _, item := range output.Subnets {
		subnets = append(subnets, fromSubnet(&item))
	}
	return subnets, nil
}

// CheckSubnetIPv6Cidr checks if the subnet has an IPv6 CIDR block assigned
func (c *Client) CheckSubnetIPv6Cidr(subnetID string) (bool, error) {
	input := &ec2.DescribeSubnetsInput{
		SubnetIds: []string{subnetID},
	}
	output, err := c.EC2.DescribeSubnets(context.TODO(), input)
	if err != nil {
		return false, err
	}
	if len(output.Subnets) == 0 {
		return false, fmt.Errorf("subnet not found")
	}
	subnet := output.Subnets[0]
	for _, cidr := range subnet.Ipv6CidrBlockAssociationSet {
		if cidr.Ipv6CidrBlockState.State == ec2types.SubnetCidrBlockStateCodeAssociated {
			return true, nil
		}
	}
	return false, nil
}

// UpdateSubnetAttributes updates attributes of the given subnet
func (c *Client) UpdateSubnetAttributes(ctx context.Context, desired, current *Subnet) (bool, error) {
	modified := false
	if trueOrFalse(current.EnableDns64) != trueOrFalse(desired.EnableDns64) {
		input := &ec2.ModifySubnetAttributeInput{
			EnableDns64: toAttributeBooleanValue(desired.EnableDns64),
			SubnetId:    aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttribute(ctx, input); err != nil {
			return false, fmt.Errorf("updating EnableDns64 failed: %w", err)
		}
		modified = true
	}
	if trueOrFalse(current.EnableResourceNameDnsAAAARecordOnLaunch) != trueOrFalse(desired.EnableResourceNameDnsAAAARecordOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			EnableResourceNameDnsAAAARecordOnLaunch: toAttributeBooleanValue(desired.EnableResourceNameDnsAAAARecordOnLaunch),
			SubnetId:                                aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttribute(ctx, input); err != nil {
			return false, fmt.Errorf("updating EnableResourceNameDnsAAAARecordOnLaunch failed: %w", err)
		}
		modified = true
	}
	if trueOrFalse(current.EnableResourceNameDnsARecordOnLaunch) != trueOrFalse(desired.EnableResourceNameDnsARecordOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			EnableResourceNameDnsARecordOnLaunch: toAttributeBooleanValue(desired.EnableResourceNameDnsARecordOnLaunch),
			SubnetId:                             aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttribute(ctx, input); err != nil {
			return false, fmt.Errorf("updating EnableResourceNameDnsARecordOnLaunch failed: %w", err)
		}
		modified = true
	}
	if trueOrFalse(current.MapCustomerOwnedIpOnLaunch) != trueOrFalse(desired.MapCustomerOwnedIpOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			MapCustomerOwnedIpOnLaunch: toAttributeBooleanValue(desired.MapCustomerOwnedIpOnLaunch),
			SubnetId:                   aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttribute(ctx, input); err != nil {
			return false, fmt.Errorf("updating MapCustomerOwnedIpOnLaunch failed: %w", err)
		}
		modified = true
	}
	if trueOrFalse(current.MapPublicIpOnLaunch) != trueOrFalse(desired.MapPublicIpOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			MapPublicIpOnLaunch: toAttributeBooleanValue(desired.MapPublicIpOnLaunch),
			SubnetId:            aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttribute(ctx, input); err != nil {
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
			if _, err := c.EC2.AssociateSubnetCidrBlock(ctx, input); err != nil {
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
		if _, err := c.EC2.ModifySubnetAttribute(ctx, input); err != nil {
			return false, fmt.Errorf("updating CustomerOwnedIpv4Pool failed: %w", err)
		}
		modified = true
	}
	privateDnsHostnameTypeOnLaunch := desired.PrivateDnsHostnameTypeOnLaunch
	if privateDnsHostnameTypeOnLaunch == nil {
		if desired.CidrBlock != "" && (desired.Ipv6Native == nil || !*desired.Ipv6Native) {
			privateDnsHostnameTypeOnLaunch = ptr.To(string(ec2types.HostnameTypeIpName))
		} else {
			privateDnsHostnameTypeOnLaunch = ptr.To(string(ec2types.HostnameTypeResourceName))
		}
	}

	if !reflect.DeepEqual(current.PrivateDnsHostnameTypeOnLaunch, privateDnsHostnameTypeOnLaunch) {
		input := &ec2.ModifySubnetAttributeInput{
			PrivateDnsHostnameTypeOnLaunch: ec2types.HostnameType(*privateDnsHostnameTypeOnLaunch),
			SubnetId:                       aws.String(current.SubnetId),
		}
		if _, err := c.EC2.ModifySubnetAttribute(ctx, input); err != nil {
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
		_, realErr = c.EC2.DeleteSubnet(ctx, input)
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
	var domainOpt ec2types.DomainType
	if eip.Vpc {
		domainOpt = ec2types.DomainTypeVpc
	}
	input := &ec2.AllocateAddressInput{
		Domain:            domainOpt,
		TagSpecifications: eip.ToTagSpecifications(ec2types.ResourceTypeElasticIp),
	}
	output, err := c.EC2.AllocateAddress(ctx, input)
	if err != nil {
		return nil, err
	}
	return &ElasticIP{
		Tags:         eip.Clone(),
		Vpc:          eip.Vpc,
		AllocationId: aws.ToString(output.AllocationId),
		PublicIp:     aws.ToString(output.PublicIp),
	}, nil
}

// GetElasticIP gets an elastic IP resource by identifier.
func (c *Client) GetElasticIP(ctx context.Context, id string) (*ElasticIP, error) {
	input := &ec2.DescribeAddressesInput{AllocationIds: []string{id}}
	output, err := c.describeElasticIPs(ctx, input)
	return single(output, err)
}

// FindElasticIPsByTags finds elastic IP resources matching the given tag map.
func (c *Client) FindElasticIPsByTags(ctx context.Context, tags Tags) ([]*ElasticIP, error) {
	input := &ec2.DescribeAddressesInput{Filters: tags.ToFilters()}
	return c.describeElasticIPs(ctx, input)
}

func (c *Client) describeElasticIPs(ctx context.Context, input *ec2.DescribeAddressesInput) ([]*ElasticIP, error) {
	output, err := c.EC2.DescribeAddresses(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var eips []*ElasticIP
	for _, item := range output.Addresses {
		eips = append(eips, fromAddress(&item))
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
		_, realErr = c.EC2.ReleaseAddress(ctx, input)
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
		TagSpecifications: gateway.ToTagSpecifications(ec2types.ResourceTypeNatgateway),
	}
	output, err := c.EC2.CreateNatGateway(ctx, input)
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
			return strings.EqualFold(item.State, string(ec2types.NatGatewayStateAvailable)), nil
		}
	})
}

// GetNATGateway gets an NAT gateway by identifier.
// If the resource is not found or in state "deleted", nil is returned
func (c *Client) GetNATGateway(ctx context.Context, id string) (*NATGateway, error) {
	input := &ec2.DescribeNatGatewaysInput{NatGatewayIds: []string{id}}
	output, err := c.describeNATGateways(ctx, input)
	gw, err := single(output, err)
	if gw != nil && strings.EqualFold(gw.State, string(ec2types.StateDeleted)) {
		return nil, nil
	}
	return gw, err
}

// FindNATGatewaysByTags finds NAT gateway resources matching the given tag map.
func (c *Client) FindNATGatewaysByTags(ctx context.Context, tags Tags) ([]*NATGateway, error) {
	input := &ec2.DescribeNatGatewaysInput{Filter: tags.ToFilters()}
	return c.describeNATGateways(ctx, input)
}

// FindNATGateways finds NAT gateway resources matching the given filters.
func (c *Client) FindNATGateways(ctx context.Context, filters []ec2types.Filter) ([]*NATGateway, error) {
	input := &ec2.DescribeNatGatewaysInput{Filter: filters}
	return c.describeNATGateways(ctx, input)
}

func (c *Client) describeNATGateways(ctx context.Context, input *ec2.DescribeNatGatewaysInput) ([]*NATGateway, error) {
	output, err := c.EC2.DescribeNatGateways(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	var gateways []*NATGateway
	for _, item := range output.NatGateways {
		gw := fromNatGateway(&item)
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
	_, err := c.EC2.DeleteNatGateway(ctx, input)
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
		TagSpecifications: tags.ToTagSpecifications(ec2types.ResourceTypeKeyPair),
	}
	output, err := c.EC2.ImportKeyPair(ctx, input)
	if err != nil {
		return nil, err
	}
	return &KeyPairInfo{
		Tags:           FromTags(output.Tags),
		KeyName:        aws.ToString(output.KeyName),
		KeyFingerprint: aws.ToString(output.KeyFingerprint),
	}, nil
}

// GetKeyPair gets a EC2 key pair by its key name.
func (c *Client) GetKeyPair(ctx context.Context, keyName string) (*KeyPairInfo, error) {
	input := &ec2.DescribeKeyPairsInput{KeyNames: []string{keyName}}
	output, err := c.describeKeyPairs(ctx, input)
	return single(output, err)
}

// FindKeyPairsByTags finds EC key pair resources matching the given tag map.
func (c *Client) FindKeyPairsByTags(ctx context.Context, tags Tags) ([]*KeyPairInfo, error) {
	input := &ec2.DescribeKeyPairsInput{Filters: tags.ToFilters()}
	return c.describeKeyPairs(ctx, input)
}

func (c *Client) describeKeyPairs(ctx context.Context, input *ec2.DescribeKeyPairsInput) ([]*KeyPairInfo, error) {
	output, err := c.EC2.DescribeKeyPairs(ctx, input)
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
	_, err := c.EC2.DeleteKeyPair(ctx, input)
	return ignoreNotFound(err)
}

// CreateRouteTableAssociation associates a route table with a subnet.
// Returns association id and error.
func (c *Client) CreateRouteTableAssociation(ctx context.Context, routeTableId, subnetId string) (*string, error) {
	input := &ec2.AssociateRouteTableInput{
		RouteTableId: aws.String(routeTableId),
		SubnetId:     aws.String(subnetId),
	}
	output, err := c.EC2.AssociateRouteTable(ctx, input)
	if err != nil {
		return nil, err
	}
	return output.AssociationId, nil
}

// DeleteRouteTableAssociation deletes the route table association by the association identifier.
// Returns nil if the resource is not found.
func (c *Client) DeleteRouteTableAssociation(ctx context.Context, associationId string) error {
	input := &ec2.DisassociateRouteTableInput{
		AssociationId: aws.String(associationId),
	}
	_, err := c.EC2.DisassociateRouteTable(ctx, input)
	return ignoreNotFound(err)
}

// CreateIAMRole creates an IAM role resource.
func (c *Client) CreateIAMRole(ctx context.Context, role *IAMRole) (*IAMRole, error) {
	input := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(role.AssumeRolePolicyDocument),
		Path:                     aws.String(role.Path),
		RoleName:                 aws.String(role.RoleName),
	}
	output, err := c.IAM.CreateRole(ctx, input)
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
	output, err := c.IAM.GetRole(ctx, input)
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
	_, err := c.IAM.DeleteRole(ctx, input)
	return ignoreNotFound(err)
}

// UpdateAssumeRolePolicy updates the assumeRolePolicy of an IAM role.
func (c *Client) UpdateAssumeRolePolicy(ctx context.Context, roleName, assumeRolePolicy string) error {
	input := &iam.UpdateAssumeRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyDocument: aws.String(assumeRolePolicy),
	}
	_, err := c.IAM.UpdateAssumeRolePolicy(ctx, input)
	return err
}

// CreateIAMInstanceProfile creates an IAM instance profile.
func (c *Client) CreateIAMInstanceProfile(ctx context.Context, profile *IAMInstanceProfile) (*IAMInstanceProfile, error) {
	input := &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String(profile.InstanceProfileName),
		Path:                aws.String(profile.Path),
	}
	output, err := c.IAM.CreateInstanceProfile(ctx, input)
	if err != nil {
		return nil, err
	}
	profileName := aws.ToString(output.InstanceProfile.InstanceProfileName)
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
	output, err := c.IAM.GetInstanceProfile(ctx, input)
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
	_, err := c.IAM.AddRoleToInstanceProfile(ctx, input)
	return err
}

// RemoveRoleFromIAMInstanceProfile removes a role from an instance profile.
func (c *Client) RemoveRoleFromIAMInstanceProfile(ctx context.Context, profileName, roleName string) error {
	input := &iam.RemoveRoleFromInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
		RoleName:            aws.String(roleName),
	}
	_, err := c.IAM.RemoveRoleFromInstanceProfile(ctx, input)
	return ignoreNotFound(err)
}

// DeleteIAMInstanceProfile deletes an IAM instance profile by profile name.
// Returns nil if the resource is not found.
func (c *Client) DeleteIAMInstanceProfile(ctx context.Context, profileName string) error {
	input := &iam.DeleteInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	}
	_, err := c.IAM.DeleteInstanceProfile(ctx, input)
	return ignoreNotFound(err)
}

// PutIAMRolePolicy creates or updates an IAM role policy.
func (c *Client) PutIAMRolePolicy(ctx context.Context, policy *IAMRolePolicy) error {
	input := &iam.PutRolePolicyInput{
		PolicyDocument: aws.String(policy.PolicyDocument),
		PolicyName:     aws.String(policy.PolicyName),
		RoleName:       aws.String(policy.RoleName),
	}
	_, err := c.IAM.PutRolePolicy(ctx, input)
	return err
}

// GetIAMRolePolicy gets an IAM role policy by policy name and role name.
func (c *Client) GetIAMRolePolicy(ctx context.Context, policyName, roleName string) (*IAMRolePolicy, error) {
	input := &iam.GetRolePolicyInput{
		PolicyName: aws.String(policyName),
		RoleName:   aws.String(roleName),
	}
	output, err := c.IAM.GetRolePolicy(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	return &IAMRolePolicy{
		PolicyName:     aws.ToString(output.PolicyName),
		RoleName:       aws.ToString(output.RoleName),
		PolicyDocument: aws.ToString(output.PolicyDocument),
	}, nil
}

// DeleteIAMRolePolicy deletes an IAM role policy by policy name and role name.
// Returns nil if the resource is not found.
func (c *Client) DeleteIAMRolePolicy(ctx context.Context, policyName, roleName string) error {
	input := &iam.DeleteRolePolicyInput{
		PolicyName: aws.String(policyName),
		RoleName:   aws.String(roleName),
	}
	_, err := c.IAM.DeleteRolePolicy(ctx, input)
	return ignoreNotFound(err)
}

// GetFileSystems retrieve information about an efs file system by its ID
func (c *Client) GetFileSystems(ctx context.Context, fileSystemID string) (*efstypes.FileSystemDescription, error) {
	output, err := c.EFS.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{
		FileSystemId: &fileSystemID,
	})
	if err != nil {
		return nil, err
	}
	if len(output.FileSystems) != 1 {
		return nil, fmt.Errorf("expected 1 file system, got %d", len(output.FileSystems))
	}
	return &output.FileSystems[0], nil
}

// FindFileSystemsByTags retrieve information about an efs file system by its ID
func (c *Client) FindFileSystemsByTags(ctx context.Context, tags Tags) ([]*efstypes.FileSystemDescription, error) {
	var result []*efstypes.FileSystemDescription

	output, err := c.EFS.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, ignoreNotFound(err)
	}

	for _, fs := range output.FileSystems {
		tagsResp, err := c.EFS.ListTagsForResource(ctx, &efs.ListTagsForResourceInput{
			ResourceId: fs.FileSystemId,
		})
		if err != nil {
			c.Logger.Info("could not get tags for fs %s: %v", *fs.FileSystemId, err)
			continue
		}

		if tags.ContainEfsTags(tagsResp.Tags) {
			result = append(result, &fs)
		}
	}

	return result, nil
}

// CreateFileSystem creates an efs file system
func (c *Client) CreateFileSystem(ctx context.Context, input *efs.CreateFileSystemInput) (*efstypes.FileSystemDescription, error) {
	output, err := c.EFS.CreateFileSystem(ctx, input)
	if ignoreAlreadyExists(err) != nil {
		return nil, err
	}
	if output == nil || output.FileSystemId == nil {
		return nil, fmt.Errorf("efs file system creation failed, no FileSystemId returned")
	}

	var fsDescription *efstypes.FileSystemDescription
	err = c.PollImmediateUntil(ctx, func(ctx context.Context) (bool, error) {
		fsDescription, err = c.GetFileSystems(ctx, *output.FileSystemId)
		if err != nil {
			return true, err
		}
		if fsDescription.LifeCycleState == efstypes.LifeCycleStateAvailable {
			return true, nil
		}
		return false, nil
	})
	return fsDescription, err
}

// DeleteFileSystem deletes an efs file system
func (c *Client) DeleteFileSystem(ctx context.Context, input *efs.DeleteFileSystemInput) error {
	_, err := c.EFS.DeleteFileSystem(ctx, input)
	return ignoreNotFound(err)
}

// DescribeMountTargetsEfs describes an efs mount target
func (c *Client) DescribeMountTargetsEfs(ctx context.Context, input *efs.DescribeMountTargetsInput) (*efs.DescribeMountTargetsOutput, error) {
	output, err := c.EFS.DescribeMountTargets(ctx, input)
	if err != nil {
		return nil, ignoreNotFound(err)
	}
	return output, nil
}

// CreateMountTargetEfs creates an efs mount target
// You can create one mount target in each Availability Zone in your VPC. All EC2
// instances in a VPC within a given Availability Zone share a single mount target
// for a given file system. If you have multiple subnets in an Availability Zone,
// you create a mount target in one of the subnets. EC2 instances do not need to be
// in the same subnet as the mount target in order to access their file system.
func (c *Client) CreateMountTargetEfs(ctx context.Context, input *efs.CreateMountTargetInput) (*efs.CreateMountTargetOutput, error) {
	return c.EFS.CreateMountTarget(ctx, input)
}

// DeleteMountTargetEfs deletes an efs mount target
func (c *Client) DeleteMountTargetEfs(ctx context.Context, input *efs.DeleteMountTargetInput) error {
	_, err := c.EFS.DeleteMountTarget(ctx, input)
	return ignoreNotFound(err)
}

// CreateEC2Tags creates the tags for the given EC2 resource identifiers
func (c *Client) CreateEC2Tags(ctx context.Context, resources []string, tags Tags) error {
	input := &ec2.CreateTagsInput{
		Resources: resources,
		Tags:      tags.ToEC2Tags(),
	}
	_, err := c.EC2.CreateTags(ctx, input)
	return err
}

// DeleteEC2Tags deletes the tags for the given EC2 resource identifiers
func (c *Client) DeleteEC2Tags(ctx context.Context, resources []string, tags Tags) error {
	input := &ec2.DeleteTagsInput{
		Resources: resources,
		Tags:      tags.ToEC2Tags(),
	}
	_, err := c.EC2.DeleteTags(ctx, input)
	return err
}

// PollImmediateUntil runs the 'condition' before waiting for the interval.
// 'condition' will always be invoked at least once.
func (c *Client) PollImmediateUntil(ctx context.Context, condition wait.ConditionWithContextFunc) error {
	return wait.PollUntilContextCancel(ctx, c.PollInterval, true, condition)
}

// PollUntil tries a condition func until it returns true,
// an error or the specified context is cancelled or expired.
func (c *Client) PollUntil(ctx context.Context, condition wait.ConditionWithContextFunc) error {
	return wait.PollUntilContextCancel(ctx, c.PollInterval, false, condition)
}

// IsAlreadyExistsError returns true if an AWS resource already exists.
func IsAlreadyExistsError(err error) bool {
	var efsAlreadyExists *efstypes.FileSystemAlreadyExists
	return errors.As(err, &efsAlreadyExists)
}

// IsNotFoundError returns true if the given error is a awserr.Error indicating that an AWS resource was not found.
func IsNotFoundError(err error) bool {
	var apnf *elbtypes.AccessPointNotFoundException
	if errors.As(err, &apnf) {
		return true
	}

	var nse *iamtypes.NoSuchEntityException
	if errors.As(err, &nse) {
		return true
	}

	var efsNotFound *efstypes.FileSystemNotFound
	if errors.As(err, &efsNotFound) {
		return true
	}

	var efsMountTargetFound *efstypes.MountTargetNotFound
	if errors.As(err, &efsMountTargetFound) {
		return true
	}

	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		if code := apiError.ErrorCode(); code == "NatGatewayNotFound" || strings.HasSuffix(code, ".NotFound") {
			return true
		}
	}
	return false
}

// IsAlreadyAssociatedError returns true if the given error is a awserr.Error indicating that an AWS resource was already associated.
func IsAlreadyAssociatedError(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		if code := apiError.ErrorCode(); code == "Resource.AlreadyAssociated" {
			return true
		}
	}
	return false
}

// IsAlreadyDetachedError returns true if the given error is a awserr.Error indicating that a NatGateway resource was already detached.
func IsAlreadyDetachedError(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		if code := apiError.ErrorCode(); code == "Gateway.NotAttached" {
			return true
		}
	}
	return false
}

func ignoreAlreadyExists(err error) error {
	if err == nil || IsAlreadyExistsError(err) {
		return nil
	}
	return err
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

// IgnoreAlreadyDetached ignores the error if it is nil or indicates that the resource was already detached.
func IgnoreAlreadyDetached(err error) error {
	if err == nil || IsAlreadyDetachedError(err) {
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

func fromDhcpOptions(item *ec2types.DhcpOptions) *DhcpOptions {
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
		DhcpOptionsId:      aws.ToString(item.DhcpOptionsId),
		DhcpConfigurations: config,
	}
}

func fromIpPermission(groupId string, ipPerm ec2types.IpPermission, ruleType SecurityGroupRuleType) (*SecurityGroupRule, error) {
	var foreign bool
	var blocks []string
	for _, block := range ipPerm.IpRanges {
		blocks = append(blocks, *block.CidrIp)
	}
	rule := &SecurityGroupRule{
		Type:       ruleType,
		Protocol:   aws.ToString(ipPerm.IpProtocol),
		CidrBlocks: blocks,
		FromPort:   ipPerm.FromPort,
		ToPort:     ipPerm.ToPort,
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
		rule.Foreign = ptr.To(string(data))
	}
	return rule, nil
}

func fromSubnet(item *ec2types.Subnet) *Subnet {
	s := &Subnet{
		Tags:                        FromTags(item.Tags),
		SubnetId:                    aws.ToString(item.SubnetId),
		VpcId:                       item.VpcId,
		AvailabilityZone:            aws.ToString(item.AvailabilityZone),
		AssignIpv6AddressOnCreation: trueOrNil(item.AssignIpv6AddressOnCreation),
		CustomerOwnedIpv4Pool:       item.CustomerOwnedIpv4Pool,
		EnableDns64:                 trueOrNil(item.EnableDns64),
		Ipv6Native:                  trueOrNil(item.Ipv6Native),
		MapCustomerOwnedIpOnLaunch:  trueOrNil(item.MapCustomerOwnedIpOnLaunch),
		MapPublicIpOnLaunch:         trueOrNil(item.MapPublicIpOnLaunch),
		OutpostArn:                  item.OutpostArn,
	}

	if item.CidrBlock != nil && *item.CidrBlock != "" {
		s.CidrBlock = aws.ToString(item.CidrBlock)
	}

	if item.PrivateDnsNameOptionsOnLaunch != nil {
		s.EnableResourceNameDnsAAAARecordOnLaunch = trueOrNil(item.PrivateDnsNameOptionsOnLaunch.EnableResourceNameDnsAAAARecord)
		s.EnableResourceNameDnsARecordOnLaunch = trueOrNil(item.PrivateDnsNameOptionsOnLaunch.EnableResourceNameDnsARecord)
		s.PrivateDnsHostnameTypeOnLaunch = ptr.To(string(item.PrivateDnsNameOptionsOnLaunch.HostnameType))
	}
	for _, block := range item.Ipv6CidrBlockAssociationSet {
		s.Ipv6CidrBlocks = append(s.Ipv6CidrBlocks, aws.ToString(block.Ipv6CidrBlock))
	}
	return s
}

func fromAddress(item *ec2types.Address) *ElasticIP {
	return &ElasticIP{
		Tags:          FromTags(item.Tags),
		Vpc:           item.Domain == ec2types.DomainTypeVpc,
		AllocationId:  aws.ToString(item.AllocationId),
		PublicIp:      aws.ToString(item.PublicIp),
		AssociationID: item.AssociationId,
	}
}

func fromNatGateway(item *ec2types.NatGateway) *NATGateway {
	if item.State == ec2types.NatGatewayStateDeleted {
		return nil
	}
	var allocationId, publicIP string
	for _, address := range item.NatGatewayAddresses {
		allocationId = aws.ToString(address.AllocationId)
		publicIP = aws.ToString(address.PublicIp)
		break
	}
	return &NATGateway{
		Tags:            FromTags(item.Tags),
		NATGatewayId:    aws.ToString(item.NatGatewayId),
		EIPAllocationId: allocationId,
		PublicIP:        publicIP,
		SubnetId:        aws.ToString(item.SubnetId),
		State:           string(item.State),
		VpcId:           item.VpcId,
	}
}

func fromKeyPairInfo(item ec2types.KeyPairInfo) *KeyPairInfo {
	return &KeyPairInfo{
		Tags:           FromTags(item.Tags),
		KeyName:        aws.ToString(item.KeyName),
		KeyFingerprint: aws.ToString(item.KeyFingerprint),
	}
}

func fromIAMRole(item *iamtypes.Role) *IAMRole {
	role := &IAMRole{
		RoleId:                   aws.ToString(item.RoleId),
		RoleName:                 aws.ToString(item.RoleName),
		Path:                     aws.ToString(item.Path),
		AssumeRolePolicyDocument: aws.ToString(item.AssumeRolePolicyDocument),
		ARN:                      aws.ToString(item.Arn),
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

func fromIAMInstanceProfile(item *iamtypes.InstanceProfile) *IAMInstanceProfile {
	var roleName string
	for _, role := range item.Roles {
		roleName = aws.ToString(role.RoleName)
		break
	}
	return &IAMInstanceProfile{
		InstanceProfileId:   aws.ToString(item.InstanceProfileId),
		InstanceProfileName: aws.ToString(item.InstanceProfileName),
		Path:                aws.ToString(item.Path),
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

func toAttributeBooleanValue(value *bool) *ec2types.AttributeBooleanValue {
	if value == nil {
		value = aws.Bool(false)
	}
	return &ec2types.AttributeBooleanValue{Value: value}
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

// GetBucketRetentiontMode returns the s3typed ObjectLockRetentionMode
func GetBucketRetentiontMode(mode apisaws.ModeType) s3types.ObjectLockRetentionMode {
	if mode == apisaws.GovernanceMode {
		return s3types.ObjectLockRetentionModeGovernance
	}
	return s3types.ObjectLockRetentionModeCompliance
}

// deleteObjectsWithPrefix deletes all objects present in a bucket(object versioning is not enabled) for a given prefix.
func deleteObjectsWithPrefix(ctx context.Context, s3client s3.Client, bucket, prefix string) error {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	paginator := s3.NewListObjectsV2Paginator(&s3client, input)
	for paginator.HasMorePages() {
		objectIDs := make([]s3types.ObjectIdentifier, 0)
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, object := range output.Contents {
			identifier := s3types.ObjectIdentifier{Key: object.Key}
			objectIDs = append(objectIDs, identifier)
		}
		if len(objectIDs) != 0 {
			if _, err = s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(bucket),
				Delete: &s3types.Delete{
					Objects: objectIDs,
					Quiet:   aws.Bool(true),
				},
			}); err != nil {
				var nsk *s3types.NoSuchKey
				if errors.As(err, &nsk) {
					return nil
				}
				return err
			}
		}
	}
	return nil
}

// deleteVersionedObjectsWithPrefix tries to delete all versioned objects and delete markers(if any) present inside the object versioned enabled bucket for a given prefix.
func deleteVersionedObjectsWithPrefix(ctx context.Context, s3client s3.Client, bucket, prefix string) error {
	input := &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	paginator := s3.NewListObjectVersionsPaginator(&s3client, input)
	for paginator.HasMorePages() {
		objectIDs := make([]s3types.ObjectIdentifier, 0)
		deleteMarkerIDs := make([]s3types.ObjectIdentifier, 0)
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, objVersion := range page.Versions {
			identifier := s3types.ObjectIdentifier{
				Key: objVersion.Key,
			}
			// To handle non-versioned objects present in the bucket
			if objVersion.VersionId != nil {
				identifier.VersionId = objVersion.VersionId
			}
			objectIDs = append(objectIDs, identifier)
		}

		for _, deleteMarker := range page.DeleteMarkers {
			identifier := s3types.ObjectIdentifier{
				Key:       deleteMarker.Key,
				VersionId: deleteMarker.VersionId,
			}
			deleteMarkerIDs = append(deleteMarkerIDs, identifier)
		}

		// Delete all the objects(versioned and non-versioned) present in bucket.
		if len(objectIDs) != 0 {
			if _, err = s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(bucket),
				Delete: &s3types.Delete{
					Objects: objectIDs,
					Quiet:   aws.Bool(true),
				},
			}); err != nil {
				var nsk *s3types.NoSuchKey
				if errors.As(err, &nsk) {
					return nil
				}
				return err
			}
		}

		// Delete all the delete markers present(if any) in bucket.
		if len(deleteMarkerIDs) != 0 {
			if _, err = s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(bucket),
				Delete: &s3types.Delete{
					Objects: deleteMarkerIDs,
					Quiet:   aws.Bool(true),
				},
			}); err != nil {
				var nsk *s3types.NoSuchKey
				if errors.As(err, &nsk) {
					return nil
				}
				return err
			}
		}
	}

	if isObjectPresent, err := addTagToObjectsIfPresent(ctx, &s3client, input); err != nil {
		return err
	} else if isObjectPresent {
		// add the lifecycle policies to bucket to purge the remaining snapshot objects present in the prefix.
		return toGCobjectsAddLifeCyclePolicyObjects(ctx, &s3client, bucket)
	}

	return nil
}

func addTagToObjectsIfPresent(ctx context.Context, s3client *s3.Client, input *s3.ListObjectVersionsInput) (bool, error) {
	paginator := s3.NewListObjectVersionsPaginator(s3client, input)

	isObjectPresent := false

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return isObjectPresent, err
		}

		for _, object := range page.Versions {
			isObjectPresent = true
			// if object present in the prefix then tagged those object
			if err := setObjectTag(ctx, s3client, *input.Bucket, *object.Key, *object.VersionId, S3ObjectMarkedForDeletionTagKey, "true"); err != nil {
				return isObjectPresent, err
			}
		}

		for range page.DeleteMarkers {
			isObjectPresent = true
		}
	}
	return isObjectPresent, nil
}

// To know more about working of Lifecycle in versioning enabled S3 bucket, please refer here:
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html
func toGCobjectsAddLifeCyclePolicyObjects(ctx context.Context, s3Client *s3.Client, bucket string) error {
	putBucketLifecycleConfigurationInput1 := &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
		LifecycleConfiguration: &s3types.BucketLifecycleConfiguration{
			Rules: []s3types.LifecycleRule{
				{
					// Lifecycle rule to expire the current version of "tagged" objects and permanently delete the noncurrent version of objects.
					ID:     aws.String(S3ObjectDeletionLifecyclePolicy),
					Status: s3types.ExpirationStatusEnabled,
					Filter: &s3types.LifecycleRuleFilter{
						Tag: &s3types.Tag{
							Key:   aws.String(S3ObjectMarkedForDeletionTagKey),
							Value: aws.String("true"),
						},
					},

					Expiration: &s3types.LifecycleExpiration{
						Days: aws.Int32(1),
					},
					NoncurrentVersionExpiration: &s3types.NoncurrentVersionExpiration{
						NoncurrentDays: aws.Int32(1),
					},
				},
				{
					// Lifecycle rule to delete the delete markers that are generated by the above lifecycle rule.
					ID:     aws.String(S3DeleteMarkerDeletionLifecyclePolicy),
					Filter: &s3types.LifecycleRuleFilter{Prefix: ptr.To("")},
					Status: s3types.ExpirationStatusEnabled,
					Expiration: &s3types.LifecycleExpiration{
						ExpiredObjectDeleteMarker: aws.Bool(true),
					},
				},
				{
					// re-add the lifecycle rule to purge incomplete multipart upload as by adding above rules, old rule get overwritten.
					Filter: &s3types.LifecycleRuleFilter{Prefix: ptr.To("")},
					AbortIncompleteMultipartUpload: &s3types.AbortIncompleteMultipartUpload{
						DaysAfterInitiation: aws.Int32(7),
					},
					Status: s3types.ExpirationStatusEnabled,
				},
			},
		},
	}

	if _, err := s3Client.PutBucketLifecycleConfiguration(ctx, putBucketLifecycleConfigurationInput1); err != nil {
		return err
	}

	return nil
}

// setObjectTag set the tag to an object specified by <key> and <versionID> in <bucket>.
func setObjectTag(ctx context.Context, s3Client *s3.Client, bucket, key, verionID, tagKey, tagValue string) error {
	input := s3.PutObjectTaggingInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Tagging: &s3types.Tagging{
			TagSet: []s3types.Tag{
				{
					Key:   aws.String(tagKey),
					Value: aws.String(tagValue),
				},
			},
		},
	}

	if len(verionID) > 0 {
		input.VersionId = aws.String(verionID)
	}

	if _, err := s3Client.PutObjectTagging(ctx, &input); err != nil {
		return err
	}

	return nil
}
