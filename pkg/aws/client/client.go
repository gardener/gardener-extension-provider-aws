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
	"strings"

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
	"github.com/pkg/errors"
)

// Client is a struct containing several clients for the different AWS services it needs to interact with.
// * EC2 is the standard client for the EC2 service.
// * STS is the standard client for the STS service.
// * IAM is the standard client for the IAM service.
// * S3 is the standard client for the S3 service.
// * ELB is the standard client for the ELB service.
// * ELBv2 is the standard client for the ELBv2 service.
type Client struct {
	EC2     ec2iface.EC2API
	STS     stsiface.STSAPI
	IAM     iamiface.IAMAPI
	S3      s3iface.S3API
	ELB     elbiface.ELBAPI
	ELBv2   elbv2iface.ELBV2API
	Route53 route53iface.Route53API
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
		EC2:     ec2.New(s, config),
		ELB:     elb.New(s, config),
		ELBv2:   elbv2.New(s, config),
		IAM:     iam.New(s, config),
		STS:     sts.New(s, config),
		S3:      s3.New(s, config),
		Route53: route53.New(s, config),
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

// VerifyVPCAttributes checks whether the VPC attributes are correct.
func (c *Client) VerifyVPCAttributes(ctx context.Context, vpcID string) error {
	vpcAttribute, err := c.EC2.DescribeVpcAttributeWithContext(ctx, &ec2.DescribeVpcAttributeInput{VpcId: &vpcID, Attribute: aws.String("enableDnsSupport")})
	if err != nil {
		return err
	}
	if vpcAttribute.EnableDnsSupport == nil || vpcAttribute.EnableDnsSupport.Value == nil || !*vpcAttribute.EnableDnsSupport.Value {
		return fmt.Errorf("invalid VPC attributes: `enableDnsSupport` must be set to `true`")
	}

	vpcAttribute, err = c.EC2.DescribeVpcAttributeWithContext(ctx, &ec2.DescribeVpcAttributeInput{VpcId: &vpcID, Attribute: aws.String("enableDnsHostnames")})
	if err != nil {
		return err
	}
	if vpcAttribute.EnableDnsHostnames == nil || vpcAttribute.EnableDnsHostnames.Value == nil || !*vpcAttribute.EnableDnsHostnames.Value {
		return fmt.Errorf("invalid VPC attributes: `enableDnsHostnames` must be set to `true`")
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
		return errors.Wrapf(err, "could not list loadbalancer target groups for arn %s", arn)
	}

	if _, err := c.ELBv2.DeleteLoadBalancerWithContext(ctx, &elbv2.DeleteLoadBalancerInput{LoadBalancerArn: &arn}); ignoreNotFound(err) != nil {
		return errors.Wrapf(err, "could not delete loadbalancer for arn %s", arn)
	}

	for _, group := range targetGroups.TargetGroups {
		if _, err := c.ELBv2.DeleteTargetGroup(&elbv2.DeleteTargetGroupInput{TargetGroupArn: group.TargetGroupArn}); err != nil {
			return errors.Wrapf(err, "could not delete target groups after deleting loadbalancer for arn %s", arn)
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

// GetDNSHostedZones returns a map of all DNS hosted zone names mapped to their IDs.
func (c *Client) GetDNSHostedZones(ctx context.Context) (map[string]string, error) {
	zones := make(map[string]string)
	if err := c.Route53.ListHostedZonesPagesWithContext(ctx, &route53.ListHostedZonesInput{}, func(out *route53.ListHostedZonesOutput, lastPage bool) bool {
		for _, zone := range out.HostedZones {
			zones[normalizeZoneName(aws.StringValue(zone.Name))] = normalizeZoneId(aws.StringValue(zone.Id))
		}
		return !lastPage
	}); err != nil {
		return nil, err
	}
	return zones, nil
}

func normalizeZoneName(zoneName string) string {
	if strings.HasPrefix(zoneName, "\\052.") {
		zoneName = "*" + zoneName[4:]
	}
	if strings.HasSuffix(zoneName, ".") {
		return zoneName[:len(zoneName)-1]
	}
	return zoneName
}

func normalizeZoneId(zoneId string) string {
	parts := strings.Split(zoneId, "/")
	return parts[len(parts)-1]
}

// CreateOrUpdateDNSRecord creates or updates the DNS record in the DNS hosted zone with the given zone ID,
// with the given name, type, values, and TTL.
func (c *Client) CreateOrUpdateDNSRecord(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64) error {
	_, err := c.Route53.ChangeResourceRecordSetsWithContext(ctx, newChangeResourceRecordSetsInput(zoneId, route53.ChangeActionUpsert, name, recordType, values, ttl))
	return err
}

// DeleteDNSRecord deletes the DNS record in the DNS hosted zone with the given zone ID,
// with the given name, type, values, and TTL.
func (c *Client) DeleteDNSRecord(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64) error {
	_, err := c.Route53.ChangeResourceRecordSetsWithContext(ctx, newChangeResourceRecordSetsInput(zoneId, route53.ChangeActionDelete, name, recordType, values, ttl))
	return ignoreNotFoundRoute53(err)
}

func newChangeResourceRecordSetsInput(zoneId, action, name, recordType string, values []string, ttl int64) *route53.ChangeResourceRecordSetsInput {
	return &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneId),
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action:            aws.String(action),
					ResourceRecordSet: newResourceRecordSet(name, recordType, newResourceRecords(recordType, values), ttl),
				},
			},
		},
	}
}

func newResourceRecords(recordType string, values []string) []*route53.ResourceRecord {
	var resourceRecords []*route53.ResourceRecord
	if recordType == route53.RRTypeCname {
		resourceRecords = append(resourceRecords, &route53.ResourceRecord{
			Value: aws.String(values[0]),
		})
	} else {
		for _, value := range values {
			if recordType == route53.RRTypeTxt {
				value = encloseInQuotes(value)
			}
			resourceRecords = append(resourceRecords, &route53.ResourceRecord{
				Value: aws.String(value),
			})
		}
	}
	return resourceRecords
}

func newResourceRecordSet(name, recordType string, resourceRecords []*route53.ResourceRecord, ttl int64) *route53.ResourceRecordSet {
	if recordType == route53.RRTypeCname {
		if zoneId := canonicalHostedZoneId(aws.StringValue(resourceRecords[0].Value)); zoneId != "" {
			return &route53.ResourceRecordSet{
				Name: aws.String(name),
				Type: aws.String(route53.RRTypeA),
				AliasTarget: &route53.AliasTarget{
					DNSName:              resourceRecords[0].Value,
					HostedZoneId:         aws.String(zoneId),
					EvaluateTargetHealth: aws.Bool(true),
				},
			}
		}
	}
	return &route53.ResourceRecordSet{
		Name:            aws.String(name),
		Type:            aws.String(recordType),
		ResourceRecords: resourceRecords,
		TTL:             aws.Int64(ttl),
	}
}

var (
	// original code: https://github.com/kubernetes-sigs/external-dns/blob/master/provider/aws/aws.go
	// see: https://docs.aws.amazon.com/general/latest/gr/elb.html
	canonicalHostedZoneIds = map[string]string{
		// Application Load Balancers and Classic Load Balancers
		"us-east-2.elb.amazonaws.com":         "Z3AADJGX6KTTL2",
		"us-east-1.elb.amazonaws.com":         "Z35SXDOTRQ7X7K",
		"us-west-1.elb.amazonaws.com":         "Z368ELLRRE2KJ0",
		"us-west-2.elb.amazonaws.com":         "Z1H1FL5HABSF5",
		"ca-central-1.elb.amazonaws.com":      "ZQSVJUPU6J1EY",
		"ap-east-1.elb.amazonaws.com":         "Z3DQVH9N71FHZ0",
		"ap-south-1.elb.amazonaws.com":        "ZP97RAFLXTNZK",
		"ap-northeast-2.elb.amazonaws.com":    "ZWKZPGTI48KDX",
		"ap-northeast-3.elb.amazonaws.com":    "Z5LXEXXYW11ES",
		"ap-southeast-1.elb.amazonaws.com":    "Z1LMS91P8CMLE5",
		"ap-southeast-2.elb.amazonaws.com":    "Z1GM3OXH4ZPM65",
		"ap-northeast-1.elb.amazonaws.com":    "Z14GRHDCWA56QT",
		"eu-central-1.elb.amazonaws.com":      "Z215JYRZR1TBD5",
		"eu-west-1.elb.amazonaws.com":         "Z32O12XQLNTSW2",
		"eu-west-2.elb.amazonaws.com":         "ZHURV8PSTC4K8",
		"eu-west-3.elb.amazonaws.com":         "Z3Q77PNBQS71R4",
		"eu-north-1.elb.amazonaws.com":        "Z23TAZ6LKFMNIO",
		"eu-south-1.elb.amazonaws.com":        "Z3ULH7SSC9OV64",
		"sa-east-1.elb.amazonaws.com":         "Z2P70J7HTTTPLU",
		"cn-north-1.elb.amazonaws.com.cn":     "Z1GDH35T77C1KE",
		"cn-northwest-1.elb.amazonaws.com.cn": "ZM7IZAIOVVDZF",
		"us-gov-west-1.elb.amazonaws.com":     "Z33AYJ8TM3BH4J",
		"us-gov-east-1.elb.amazonaws.com":     "Z166TLBEWOO7G0",
		"me-south-1.elb.amazonaws.com":        "ZS929ML54UICD",
		"af-south-1.elb.amazonaws.com":        "Z268VQBMOI5EKX",
		// Network Load Balancers
		"elb.us-east-2.amazonaws.com":         "ZLMOA37VPKANP",
		"elb.us-east-1.amazonaws.com":         "Z26RNL4JYFTOTI",
		"elb.us-west-1.amazonaws.com":         "Z24FKFUX50B4VW",
		"elb.us-west-2.amazonaws.com":         "Z18D5FSROUN65G",
		"elb.ca-central-1.amazonaws.com":      "Z2EPGBW3API2WT",
		"elb.ap-east-1.amazonaws.com":         "Z12Y7K3UBGUAD1",
		"elb.ap-south-1.amazonaws.com":        "ZVDDRBQ08TROA",
		"elb.ap-northeast-2.amazonaws.com":    "ZIBE1TIR4HY56",
		"elb.ap-southeast-1.amazonaws.com":    "ZKVM4W9LS7TM",
		"elb.ap-southeast-2.amazonaws.com":    "ZCT6FZBF4DROD",
		"elb.ap-northeast-1.amazonaws.com":    "Z31USIVHYNEOWT",
		"elb.eu-central-1.amazonaws.com":      "Z3F0SRJ5LGBH90",
		"elb.eu-west-1.amazonaws.com":         "Z2IFOLAFXWLO4F",
		"elb.eu-west-2.amazonaws.com":         "ZD4D7Y8KGAS4G",
		"elb.eu-west-3.amazonaws.com":         "Z1CMS0P5QUZ6D5",
		"elb.eu-north-1.amazonaws.com":        "Z1UDT6IFJ4EJM",
		"elb.eu-south-1.amazonaws.com":        "Z23146JA1KNAFP",
		"elb.sa-east-1.amazonaws.com":         "ZTK26PT1VY4CU",
		"elb.cn-north-1.amazonaws.com.cn":     "Z3QFB96KMJ7ED6",
		"elb.cn-northwest-1.amazonaws.com.cn": "ZQEIKTCZ8352D",
		"elb.us-gov-west-1.amazonaws.com":     "ZMG1MZ2THAWF1",
		"elb.us-gov-east-1.amazonaws.com":     "Z1ZSMQQ6Q24QQ8",
		"elb.me-south-1.amazonaws.com":        "Z3QSRYVP46NYYV",
		"elb.af-south-1.amazonaws.com":        "Z203XCE67M25HM",
		// Global Accelerator
		"awsglobalaccelerator.com": "Z2BJ6XQ5FK7U4H",
	}
)

// canonicalHostedZoneId returns the matching canonical hosted zone ID for the given hostname, if found.
func canonicalHostedZoneId(hostname string) string {
	for suffix, zone := range canonicalHostedZoneIds {
		if strings.HasSuffix(hostname, "."+suffix) {
			return zone
		}
	}
	return ""
}

func encloseInQuotes(s string) string {
	if s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}

func ignoreNotFound(err error) error {
	if err == nil {
		return nil
	}
	if aerr, ok := err.(awserr.Error); ok && (aerr.Code() == elb.ErrCodeAccessPointNotFoundException || aerr.Code() == "InvalidGroup.NotFound") {
		return nil
	}
	return err
}

func ignoreNotFoundRoute53(err error) error {
	if err == nil {
		return nil
	}
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeInvalidChangeBatch && strings.Contains(aerr.Message(), "it was not found") {
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
