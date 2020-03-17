// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package infrastructure_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"text/template"

	"github.com/aws/aws-sdk-go/aws/awserr"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/aws/matchers"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/helm/pkg/chartutil"
	"k8s.io/helm/pkg/engine"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// TODO: validate why --kubeconfig gets registered from `controller/cmd/options.go`
	kubeconfig      = flag.String("kubecfg", "", "the path to the kubeconfig that shall be used for the test")
	accessKeyID     = flag.String("access-key-id", "", "AWS access key id")
	secretAccessKey = flag.String("secret-access-key", "", "AWS secret access key")
	region          = flag.String("region", "", "AWS region")
)

func validateFlags() {
	if len(*kubeconfig) == 0 {
		panic("need a path to a kubeconfig in order to execute terraformer pod")
	}
	if len(*accessKeyID) == 0 {
		panic("need an AWS access key id")
	}
	if len(*secretAccessKey) == 0 {
		panic("need an AWS secret access key")
	}
	if len(*region) == 0 {
		panic("need an AWS region")
	}
}

type awsClient struct {
	EC2 ec2iface.EC2API
	IAM iamiface.IAMAPI
	STS stsiface.STSAPI
}

func newAWSClient(accessKeyID, secretAccessKey, region string) *awsClient {
	var (
		awsConfig    = &awssdk.Config{Credentials: credentials.NewStaticCredentials(accessKeyID, secretAccessKey, "")}
		regionConfig = &awssdk.Config{Region: &region}
	)

	s, err := session.NewSession(awsConfig)
	if err != nil {
		panic(err)
	}

	return &awsClient{
		EC2: ec2.New(s, regionConfig),
		IAM: iam.New(s, regionConfig),
		STS: sts.New(s, regionConfig),
	}
}

type infrastructureIdentifiers struct {
	vpcID                       *string
	dhcpOptionsID               *string
	vpcEndpointID               *string
	internetGatewayID           *string
	securityGroupIDs            []*string
	keyPairName                 *string
	subnetIDs                   []*string
	elasticIPAllocationID       *string
	natGatewayID                *string
	routeTableIDs               []*string
	bastionsRoleName            *string
	nodesRoleName               *string
	bastionsInstanceProfileName *string
	nodesInstanceProfileName    *string
	bastionsRolePolicyName      *string
	nodesRolePolicyName         *string
}

var _ = Describe("Infrastructure tests", func() {
	BeforeSuite(func() {
		flag.Parse()
		validateFlags()

		aws.InternalChartsPath = filepath.Join("..", "..", "..", aws.InternalChartsPath)
	})

	var (
		ctx    = context.Background()
		logger = log.Log.WithName("test")

		awsClient *awsClient
		accountID string

		restConfig *rest.Config
		c          client.Client

		scheme        *runtime.Scheme
		decoder       runtime.Decoder
		chartRenderer chartrenderer.Interface
	)

	BeforeEach(func() {
		awsClient = newAWSClient(*accessKeyID, *secretAccessKey, *region)

		getCallerIdentityOutput, err := awsClient.STS.GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
		Expect(err).NotTo(HaveOccurred())
		Expect(getCallerIdentityOutput.Account).NotTo(BeNil())
		Expect(getCallerIdentityOutput.Account).NotTo(PointTo(BeEmpty()))
		accountID = *getCallerIdentityOutput.Account

		k8sClient, err := kubernetes.NewClientFromFile("", *kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		restConfig = k8sClient.RESTConfig()
		c = k8sClient.Client()

		scheme = runtime.NewScheme()
		Expect(api.AddToScheme(scheme)).To(Succeed())
		Expect(awsv1alpha1.AddToScheme(scheme)).To(Succeed())
		decoder = serializer.NewCodecFactory(scheme).UniversalDecoder()
		chartRenderer = chartrenderer.New(engine.New(), &chartutil.Capabilities{})
	})

	Describe("#Reconcile, #Delete", func() {
		const (
			secretName = "cloudprovider"

			gatewayEndpoint = "s3"
			internalCIDR    = "10.250.112.0/22"
			publicCIDR      = "10.250.96.0/22"
			workersCIDR     = "10.250.0.0/19"
		)

		var (
			availabilityZone          string
			cidr                      *string
			sshPublicKey              []byte
			infrastructureIdentifiers infrastructureIdentifiers
		)

		BeforeEach(func() {
			availabilityZone = *region + "a"
			cidr = pointer.StringPtr("10.250.0.0/16")
			sshPublicKey = []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcSZKq0lM9w+ElLp9I9jFvqEFbOV1+iOBX7WEe66GvPLOWl9ul03ecjhOf06+FhPsWFac1yaxo2xj+SJ+FVZ3DdSn4fjTpS9NGyQVPInSZveetRw0TV0rbYCFBTJuVqUFu6yPEgdcWq8dlUjLqnRNwlelHRcJeBfACBZDLNSxjj0oUz7ANRNCEne1ecySwuJUAz3IlNLPXFexRT0alV7Nl9hmJke3dD73nbeGbQtwvtu8GNFEoO4Eu3xOCKsLw6ILLo4FBiFcYQOZqvYZgCb4ncKM52bnABagG54upgBMZBRzOJvWp0ol+jK3Em7Vb6ufDTTVNiQY78U6BAlNZ8Xg+LUVeyk1C6vWjzAQf02eRvMdfnRCFvmwUpzbHWaVMsQm8gf3AgnTUuDR0ev1nQH/5892wZA86uLYW/wLiiSbvQsqtY1jSn9BAGFGdhXgWLAkGsd/E1vOT+vDcor6/6KjHBm0rG697A3TDBRkbXQ/1oFxcM9m17RteCaXuTiAYWMqGKDoJvTMDc4L+Uvy544pEfbOH39zfkIYE76WLAFPFsUWX6lXFjQrX3O7vEV73bCHoJnwzaNd03PSdJOw+LCzrTmxVezwli3F9wUDiBRB0HkQxIXQmncc1HSecCKALkogIK+1e1OumoWh6gPdkF4PlTMUxRitrwPWSaiUIlPfCpQ== your_email@example.com")
		})

		It("should correctly create and delete the expected AWS resources", func() {
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					// GenerateName: "provider-aws-test-",
					Name: "provider-aws-test-tim",
				},
			}
			Expect(c.Create(ctx, namespace)).NotTo(HaveOccurred())

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace.Name,
				},
				Data: map[string][]byte{
					aws.AccessKeyID:     []byte(*accessKeyID),
					aws.SecretAccessKey: []byte(*secretAccessKey),
				},
			}
			Expect(c.Create(ctx, secret)).NotTo(HaveOccurred())

			providerConfig := awsv1alpha1.InfrastructureConfig{
				TypeMeta: metav1.TypeMeta{
					APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
					Kind:       "InfrastructureConfig",
				},
				EnableECRAccess: pointer.BoolPtr(true),
				Networks: awsv1alpha1.Networks{
					VPC: awsv1alpha1.VPC{
						CIDR:             cidr,
						GatewayEndpoints: []string{gatewayEndpoint},
					},
					Zones: []awsv1alpha1.Zone{
						{
							Name:     availabilityZone,
							Internal: internalCIDR,
							Public:   publicCIDR,
							Workers:  workersCIDR,
						},
					},
				},
			}
			providerConfigJSON, err := json.Marshal(providerConfig)
			Expect(err).NotTo(HaveOccurred())

			infra := &extensionsv1alpha1.Infrastructure{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "infrastructure",
					Namespace: namespace.Name,
				},
				Spec: extensionsv1alpha1.InfrastructureSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{
						Type: aws.Type,
						ProviderConfig: &runtime.RawExtension{
							Raw: providerConfigJSON,
						},
					},
					SecretRef: corev1.SecretReference{
						Name:      secretName,
						Namespace: namespace.Name,
					},
					Region:       *region,
					SSHPublicKey: sshPublicKey,
				},
			}

			defer func() {
				By("delete infrastructure")
				Expect(infrastructure.Delete(ctx, logger, restConfig, c, infra)).NotTo(HaveOccurred())
				Expect(client.IgnoreNotFound(c.Delete(ctx, namespace))).NotTo(HaveOccurred())

				By("test infrastructure deletion")
				testDeletion(ctx, awsClient, infrastructureIdentifiers)
			}()

			By("reconcile infrastructure")
			infraStatus, _, err := infrastructure.Reconcile(ctx, logger, restConfig, c, decoder, chartRenderer, infra)
			Expect(err).NotTo(HaveOccurred())

			By("test infrastructure reconciliation")
			infrastructureIdentifiers = testReconciliation(ctx, awsClient, infra, infraStatus, providerConfig, accountID,
				availabilityZone, cidr, internalCIDR, workersCIDR, publicCIDR, gatewayEndpoint)
		})
	})
})

func testReconciliation(
	ctx context.Context,
	awsClient *awsClient,
	infra *extensionsv1alpha1.Infrastructure,
	infraStatus *awsv1alpha1.InfrastructureStatus,
	providerConfig awsv1alpha1.InfrastructureConfig,
	accountID string,
	availabilityZone string,
	cidr *string,
	internalCIDR string,
	workersCIDR string,
	publicCIDR string,
	gatewayEndpoint string,
) (
	infrastructureIdentifier infrastructureIdentifiers,
) {
	const (
		kubernetesTagPrefix     = "kubernetes.io/cluster/"
		kubernetesRoleTagPrefix = "kubernetes.io/role/"

		privateUtilitySuffix = "-private-utility-z0"
		publicUtilitySuffix  = "-public-utility-z0"
		nodesSuffix          = "-nodes-z0"

		sshPublicKeyDigest = "46:ca:46:0e:8e:1d:bc:0c:45:31:ee:0f:43:5f:9b:f1"
		allCIDR            = "0.0.0.0/0"
	)

	var (
		nameFilter = []*ec2.Filter{
			{
				Name: awssdk.String("tag:Name"),
				Values: []*string{
					awssdk.String(infra.Namespace),
				},
			},
		}
		kubernetesTagFilter = []*ec2.Filter{
			{
				Name: awssdk.String("tag:" + kubernetesTagPrefix + infra.Namespace),
				Values: []*string{
					awssdk.String("1"),
				},
			},
		}
		vpcIDFilter = []*ec2.Filter{
			{
				Name: awssdk.String("vpc-id"),
				Values: []*string{
					awssdk.String(infraStatus.VPC.ID),
				},
			},
		}

		defaultTags = []*ec2.Tag{
			{
				Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
				Value: awssdk.String("1"),
			},
			{
				Key:   awssdk.String("Name"),
				Value: awssdk.String(infra.Namespace),
			},
		}
	)

	// vpc

	describeVpcsOutput, err := awsClient.EC2.DescribeVpcsWithContext(ctx, &ec2.DescribeVpcsInput{VpcIds: []*string{awssdk.String(infraStatus.VPC.ID)}})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeVpcsOutput.Vpcs).To(HaveLen(1))
	Expect(describeVpcsOutput.Vpcs[0].VpcId).To(PointTo(Equal(infraStatus.VPC.ID)))
	Expect(describeVpcsOutput.Vpcs[0].CidrBlock).To(Equal(cidr))
	Expect(describeVpcsOutput.Vpcs[0].Tags).To(ConsistOf(defaultTags))
	infrastructureIdentifier.vpcID = describeVpcsOutput.Vpcs[0].VpcId

	// dhcp options + dhcp options attachment

	describeDhcpOptionsOutput, err := awsClient.EC2.DescribeDhcpOptionsWithContext(ctx, &ec2.DescribeDhcpOptionsInput{Filters: nameFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeDhcpOptionsOutput.DhcpOptions).To(HaveLen(1))
	Expect(describeVpcsOutput.Vpcs[0].DhcpOptionsId).To(Equal(describeDhcpOptionsOutput.DhcpOptions[0].DhcpOptionsId))
	Expect(describeDhcpOptionsOutput.DhcpOptions[0].DhcpConfigurations).To(Equal([]*ec2.DhcpConfiguration{
		{
			Key: awssdk.String("domain-name"),
			Values: []*ec2.AttributeValue{
				{Value: awssdk.String(*region + ".compute.internal")}, // this will not work for us-east-1
			},
		}, {
			Key: awssdk.String("domain-name-servers"),
			Values: []*ec2.AttributeValue{
				{Value: awssdk.String("AmazonProvidedDNS")},
			},
		},
	}))
	Expect(describeDhcpOptionsOutput.DhcpOptions[0].Tags).To(ConsistOf(defaultTags))
	infrastructureIdentifier.dhcpOptionsID = describeDhcpOptionsOutput.DhcpOptions[0].DhcpOptionsId

	// vpc gateway endpoints

	describeVpcEndpointsOutput, err := awsClient.EC2.DescribeVpcEndpointsWithContext(ctx, &ec2.DescribeVpcEndpointsInput{Filters: vpcIDFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeVpcEndpointsOutput.VpcEndpoints).To(HaveLen(1))
	Expect(describeVpcEndpointsOutput.VpcEndpoints[0].ServiceName).To(PointTo(Equal(fmt.Sprintf("com.amazonaws.%s.%s", *region, gatewayEndpoint))))
	Expect(describeVpcEndpointsOutput.VpcEndpoints[0].Tags).To(ConsistOf([]*ec2.Tag{
		{
			Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
			Value: awssdk.String("1"),
		},
		{
			Key:   awssdk.String("Name"),
			Value: awssdk.String(infra.Namespace + "-gw-" + gatewayEndpoint),
		},
	}))
	infrastructureIdentifier.vpcEndpointID = describeVpcEndpointsOutput.VpcEndpoints[0].VpcEndpointId

	// internet gateway

	describeInternetGatewaysOutput, err := awsClient.EC2.DescribeInternetGatewaysWithContext(ctx, &ec2.DescribeInternetGatewaysInput{Filters: []*ec2.Filter{
		{
			Name: awssdk.String("attachment.vpc-id"),
			Values: []*string{
				awssdk.String(infraStatus.VPC.ID),
			},
		},
	}})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeInternetGatewaysOutput.InternetGateways).To(HaveLen(1))
	Expect(describeInternetGatewaysOutput.InternetGateways[0].Tags).To(ConsistOf(defaultTags))
	infrastructureIdentifier.internetGatewayID = describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId

	// security groups + security group rules

	infrastructureIdentifier.securityGroupIDs = []*string{}
	describeSecurityGroupsOutput, err := awsClient.EC2.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{Filters: vpcIDFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeSecurityGroupsOutput.SecurityGroups).To(HaveLen(2))
	for _, securityGroup := range describeSecurityGroupsOutput.SecurityGroups {
		if securityGroup.GroupName != nil && *securityGroup.GroupName == "default" {
			Expect(securityGroup.IpPermissions).To(BeEmpty())
			Expect(securityGroup.IpPermissionsEgress).To(BeEmpty())
			Expect(securityGroup.Tags).To(BeEmpty())
			infrastructureIdentifier.securityGroupIDs = append(infrastructureIdentifier.securityGroupIDs, securityGroup.GroupId)
		} else if *securityGroup.GroupName == infra.Namespace+"-nodes" {
			Expect(securityGroup.IpPermissions).To(BeSemanticallyEqualTo([]*ec2.IpPermission{
				{
					FromPort:   awssdk.Int64(30000),
					IpProtocol: awssdk.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp: awssdk.String(publicCIDR),
						},
						{
							CidrIp: awssdk.String(allCIDR),
						},
						{
							CidrIp: awssdk.String(internalCIDR),
						},
					},
					ToPort: awssdk.Int64(32767),
				},
				{
					IpProtocol: awssdk.String("-1"),
					UserIdGroupPairs: []*ec2.UserIdGroupPair{
						{
							GroupId: securityGroup.GroupId,
							UserId:  awssdk.String(accountID),
						},
					},
				},
				{
					FromPort:   awssdk.Int64(30000),
					IpProtocol: awssdk.String("udp"),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp: awssdk.String(publicCIDR),
						},
						{
							CidrIp: awssdk.String(internalCIDR),
						},
						{
							CidrIp: awssdk.String(allCIDR),
						},
					},
					ToPort: awssdk.Int64(32767),
				},
			}))
			Expect(securityGroup.IpPermissionsEgress).To(BeSemanticallyEqualTo([]*ec2.IpPermission{
				{
					IpProtocol: awssdk.String("-1"),
					IpRanges: []*ec2.IpRange{
						{CidrIp: awssdk.String(allCIDR)},
					},
				},
			}))
			Expect(securityGroup.Tags).To(ConsistOf([]*ec2.Tag{
				{
					Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
					Value: awssdk.String("1"),
				},
				{
					Key:   awssdk.String("Name"),
					Value: awssdk.String(infra.Namespace + "-nodes"),
				},
			}))
			infrastructureIdentifier.securityGroupIDs = append(infrastructureIdentifier.securityGroupIDs, securityGroup.GroupId)
		}
	}

	// ec2 key pair

	describeKeyPairsOutput, err := awsClient.EC2.DescribeKeyPairsWithContext(ctx, &ec2.DescribeKeyPairsInput{
		KeyNames: []*string{awssdk.String(infra.Namespace + "-ssh-publickey")},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeKeyPairsOutput.KeyPairs[0].KeyFingerprint).To(PointTo(Equal(sshPublicKeyDigest)))
	infrastructureIdentifier.keyPairName = describeKeyPairsOutput.KeyPairs[0].KeyName

	// subnets

	describeSubnetsOutput, err := awsClient.EC2.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{Filters: vpcIDFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeSubnetsOutput.Subnets).To(HaveLen(3))
	var (
		foundExpectedSubnets int
		workersSubnetID      string
		publicSubnetID       string
		internalSubnetID     string
	)
	for _, subnet := range describeSubnetsOutput.Subnets {
		for _, tag := range subnet.Tags {
			if reflect.DeepEqual(tag.Key, awssdk.String("Name")) && reflect.DeepEqual(tag.Value, awssdk.String(infra.Namespace+nodesSuffix)) {
				foundExpectedSubnets++
				workersSubnetID = *subnet.SubnetId
				Expect(subnet.AvailabilityZone).To(PointTo(Equal(availabilityZone)))
				Expect(subnet.CidrBlock).To(PointTo(Equal(workersCIDR)))
				Expect(subnet.State).To(PointTo(Equal("available")))
				Expect(subnet.Tags).To(ConsistOf([]*ec2.Tag{
					{
						Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
						Value: awssdk.String("1"),
					},
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(infra.Namespace + nodesSuffix),
					},
				}))
				infrastructureIdentifier.subnetIDs = append(infrastructureIdentifier.subnetIDs, subnet.SubnetId)
			}
			if reflect.DeepEqual(tag.Key, awssdk.String("Name")) && reflect.DeepEqual(tag.Value, awssdk.String(infra.Namespace+publicUtilitySuffix)) {
				foundExpectedSubnets++
				publicSubnetID = *subnet.SubnetId
				Expect(subnet.AvailabilityZone).To(PointTo(Equal(availabilityZone)))
				Expect(subnet.CidrBlock).To(PointTo(Equal(publicCIDR)))
				Expect(subnet.State).To(PointTo(Equal("available")))
				Expect(subnet.Tags).To(ConsistOf([]*ec2.Tag{
					{
						Key:   awssdk.String(kubernetesRoleTagPrefix + "elb"),
						Value: awssdk.String("use"),
					},
					{
						Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
						Value: awssdk.String("1"),
					},
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(infra.Namespace + publicUtilitySuffix),
					},
				}))
				infrastructureIdentifier.subnetIDs = append(infrastructureIdentifier.subnetIDs, subnet.SubnetId)
			}
			if reflect.DeepEqual(tag.Key, awssdk.String("Name")) && reflect.DeepEqual(tag.Value, awssdk.String(infra.Namespace+privateUtilitySuffix)) {
				foundExpectedSubnets++
				internalSubnetID = *subnet.SubnetId
				Expect(subnet.AvailabilityZone).To(PointTo(Equal(availabilityZone)))
				Expect(subnet.CidrBlock).To(PointTo(Equal(internalCIDR)))
				Expect(subnet.State).To(PointTo(Equal("available")))
				Expect(subnet.Tags).To(ConsistOf([]*ec2.Tag{
					{
						Key:   awssdk.String(kubernetesRoleTagPrefix + "internal-elb"),
						Value: awssdk.String("use"),
					},
					{
						Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
						Value: awssdk.String("1"),
					},
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(infra.Namespace + privateUtilitySuffix),
					},
				}))
				infrastructureIdentifier.subnetIDs = append(infrastructureIdentifier.subnetIDs, subnet.SubnetId)
			}
		}
	}
	Expect(foundExpectedSubnets).To(Equal(3))

	// elastic ips

	describeAddressesOutput, err := awsClient.EC2.DescribeAddressesWithContext(ctx, &ec2.DescribeAddressesInput{Filters: kubernetesTagFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeAddressesOutput.Addresses).To(HaveLen(1))
	Expect(describeAddressesOutput.Addresses[0].Tags).To(ConsistOf([]*ec2.Tag{
		{
			Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
			Value: awssdk.String("1"),
		},
		{
			Key:   awssdk.String("Name"),
			Value: awssdk.String(infra.Namespace + "-eip-natgw-z0"),
		},
	}))
	infrastructureIdentifier.elasticIPAllocationID = describeAddressesOutput.Addresses[0].AllocationId

	// nat gateways

	describeNatGatewaysOutput, err := awsClient.EC2.DescribeNatGatewaysWithContext(ctx, &ec2.DescribeNatGatewaysInput{Filter: vpcIDFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeNatGatewaysOutput.NatGateways).To(HaveLen(1))
	Expect(describeNatGatewaysOutput.NatGateways[0].NatGatewayAddresses).To(ConsistOf([]*ec2.NatGatewayAddress{
		{
			AllocationId:       describeAddressesOutput.Addresses[0].AllocationId,
			NetworkInterfaceId: describeAddressesOutput.Addresses[0].NetworkInterfaceId,
			PrivateIp:          describeAddressesOutput.Addresses[0].PrivateIpAddress,
			PublicIp:           describeAddressesOutput.Addresses[0].PublicIp,
		},
	}))
	Expect(describeNatGatewaysOutput.NatGateways[0].SubnetId).To(PointTo(Equal(publicSubnetID)))
	Expect(describeNatGatewaysOutput.NatGateways[0].Tags).To(ConsistOf([]*ec2.Tag{
		{
			Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
			Value: awssdk.String("1"),
		},
		{
			Key:   awssdk.String("Name"),
			Value: awssdk.String(infra.Namespace + "-natgw-z0"),
		},
	}))
	infrastructureIdentifier.natGatewayID = describeNatGatewaysOutput.NatGateways[0].NatGatewayId

	// route tables + routes

	describeRouteTablesOutput, err := awsClient.EC2.DescribeRouteTablesWithContext(ctx, &ec2.DescribeRouteTablesInput{Filters: vpcIDFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeRouteTablesOutput.RouteTables).To(HaveLen(3))
	var (
		foundExpectedRouteTables int
	)
	for _, routeTable := range describeRouteTablesOutput.RouteTables {
		if len(routeTable.Tags) == 0 {
			Expect(routeTable.Associations).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Main": PointTo(Equal(true)),
			}))))
			foundExpectedRouteTables++
			Expect(routeTable.Routes).To(ConsistOf([]*ec2.Route{
				{
					DestinationCidrBlock: cidr,
					GatewayId:            awssdk.String("local"),
					Origin:               awssdk.String("CreateRouteTable"),
					State:                awssdk.String("active"),
				},
			}))
			infrastructureIdentifier.routeTableIDs = append(infrastructureIdentifier.routeTableIDs, routeTable.RouteTableId)
		}
		for _, tag := range routeTable.Tags {
			if reflect.DeepEqual(tag.Key, awssdk.String("Name")) && reflect.DeepEqual(tag.Value, awssdk.String(infra.Namespace)) {
				foundExpectedRouteTables++
				Expect(routeTable.Associations).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
					"Main":     PointTo(Equal(false)),
					"SubnetId": PointTo(Equal(publicSubnetID)),
				}))))
				Expect(routeTable.Routes).To(ConsistOf([]*ec2.Route{
					{
						DestinationCidrBlock: cidr,
						GatewayId:            awssdk.String("local"),
						Origin:               awssdk.String("CreateRouteTable"),
						State:                awssdk.String("active"),
					},
					{
						DestinationCidrBlock: awssdk.String(allCIDR),
						GatewayId:            describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId,
						Origin:               awssdk.String("CreateRoute"),
						State:                awssdk.String("active"),
					},
				}))
				Expect(routeTable.Tags).To(Equal(defaultTags))
				infrastructureIdentifier.routeTableIDs = append(infrastructureIdentifier.routeTableIDs, routeTable.RouteTableId)
			}
			if reflect.DeepEqual(tag.Key, awssdk.String("Name")) && reflect.DeepEqual(tag.Value, awssdk.String(infra.Namespace+"-private-"+availabilityZone)) {
				foundExpectedRouteTables++
				Expect(routeTable.Associations).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Main":     PointTo(Equal(false)),
						"SubnetId": PointTo(Equal(workersSubnetID)),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Main":     PointTo(Equal(false)),
						"SubnetId": PointTo(Equal(internalSubnetID)),
					})),
				))
				Expect(routeTable.Routes).To(ConsistOf([]*ec2.Route{
					{
						DestinationCidrBlock: cidr,
						GatewayId:            awssdk.String("local"),
						Origin:               awssdk.String("CreateRouteTable"),
						State:                awssdk.String("active"),
					},
					{
						DestinationCidrBlock: awssdk.String(allCIDR),
						NatGatewayId:         describeNatGatewaysOutput.NatGateways[0].NatGatewayId,
						Origin:               awssdk.String("CreateRoute"),
						State:                awssdk.String("active"),
					},
				}))
				Expect(routeTable.Tags).To(ConsistOf([]*ec2.Tag{
					{
						Key:   awssdk.String(kubernetesTagPrefix + infra.Namespace),
						Value: awssdk.String("1"),
					},
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(infra.Namespace + "-private-" + availabilityZone),
					},
				}))
				infrastructureIdentifier.routeTableIDs = append(infrastructureIdentifier.routeTableIDs, routeTable.RouteTableId)
			}
		}
	}
	Expect(foundExpectedRouteTables).To(Equal(3))

	// IAM resources bastions

	getRoleOutputBastions, err := awsClient.IAM.GetRoleWithContext(ctx, &iam.GetRoleInput{RoleName: awssdk.String(infra.Namespace + "-bastions")})
	Expect(err).NotTo(HaveOccurred())
	Expect(getRoleOutputBastions.Role).To(BeSemanticallyEqualTo(&iam.Role{
		Path: awssdk.String("/"),
		AssumeRolePolicyDocument: awssdk.String(`
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`),
	}))
	infrastructureIdentifier.bastionsRoleName = getRoleOutputBastions.Role.RoleName

	getInstanceProfileOutputBastions, err := awsClient.IAM.GetInstanceProfileWithContext(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: awssdk.String(infra.Namespace + "-bastions")})
	Expect(err).NotTo(HaveOccurred())
	Expect(getInstanceProfileOutputBastions.InstanceProfile).NotTo(BeNil())
	iamInstanceProfileBastions := *getInstanceProfileOutputBastions.InstanceProfile
	Expect(iamInstanceProfileBastions.Path).To(Equal(awssdk.String("/")))
	Expect(iamInstanceProfileBastions.Roles).To(BeSemanticallyEqualTo([]*iam.Role{getRoleOutputBastions.Role}))
	infrastructureIdentifier.bastionsInstanceProfileName = getInstanceProfileOutputBastions.InstanceProfile.InstanceProfileName

	getRolePolicyOutputBastions, err := awsClient.IAM.GetRolePolicyWithContext(ctx, &iam.GetRolePolicyInput{PolicyName: awssdk.String(infra.Namespace + "-bastions"), RoleName: awssdk.String(infra.Namespace + "-bastions")})
	Expect(err).NotTo(HaveOccurred())
	Expect(getRolePolicyOutputBastions.RoleName).NotTo(BeNil())
	Expect(getRolePolicyOutputBastions.RoleName).To(Equal(awssdk.String(infra.Namespace + "-bastions")))
	Expect(getRolePolicyOutputBastions.PolicyName).NotTo(BeNil())
	Expect(getRolePolicyOutputBastions.PolicyName).To(Equal(awssdk.String(infra.Namespace + "-bastions")))
	iamRolePolicyDocumentBastions, err := url.QueryUnescape(*getRolePolicyOutputBastions.PolicyDocument)
	Expect(err).NotTo(HaveOccurred())
	Expect(iamRolePolicyDocumentBastions).To(MatchJSON(`
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}`))
	infrastructureIdentifier.bastionsRolePolicyName = getRolePolicyOutputBastions.PolicyName

	// IAM resources nodes

	getRoleOutputNodes, err := awsClient.IAM.GetRoleWithContext(ctx, &iam.GetRoleInput{RoleName: awssdk.String(infra.Namespace + "-nodes")})
	Expect(err).NotTo(HaveOccurred())
	Expect(getRoleOutputNodes.Role).To(BeSemanticallyEqualTo(&iam.Role{
		Path: awssdk.String("/"),
		AssumeRolePolicyDocument: awssdk.String(`
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`),
	}))
	infrastructureIdentifier.nodesRoleName = getRoleOutputBastions.Role.RoleName

	getInstanceProfileOutputNodes, err := awsClient.IAM.GetInstanceProfileWithContext(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: awssdk.String(infra.Namespace + "-nodes")})
	Expect(err).NotTo(HaveOccurred())
	Expect(getInstanceProfileOutputNodes.InstanceProfile).NotTo(BeNil())
	iamInstanceProfileNodes := *getInstanceProfileOutputNodes.InstanceProfile
	Expect(iamInstanceProfileNodes.Path).To(Equal(awssdk.String("/")))
	Expect(iamInstanceProfileNodes.Roles).To(BeSemanticallyEqualTo([]*iam.Role{getRoleOutputNodes.Role}))
	infrastructureIdentifier.nodesInstanceProfileName = getInstanceProfileOutputNodes.InstanceProfile.InstanceProfileName

	getRolePolicyOutputNodes, err := awsClient.IAM.GetRolePolicyWithContext(ctx, &iam.GetRolePolicyInput{PolicyName: awssdk.String(infra.Namespace + "-nodes"), RoleName: awssdk.String(infra.Namespace + "-nodes")})
	Expect(err).NotTo(HaveOccurred())
	Expect(getRolePolicyOutputNodes.RoleName).NotTo(BeNil())
	Expect(getRolePolicyOutputNodes.RoleName).To(Equal(awssdk.String(infra.Namespace + "-nodes")))
	Expect(getRolePolicyOutputNodes.PolicyName).NotTo(BeNil())
	Expect(getRolePolicyOutputNodes.PolicyName).To(Equal(awssdk.String(infra.Namespace + "-nodes")))
	iamRolePolicyDocumentNodes, err := url.QueryUnescape(*getRolePolicyOutputNodes.PolicyDocument)
	Expect(err).NotTo(HaveOccurred())
	templateIAMRolePolicyDocumentNodes, err := template.New("policy").Parse(`
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Resource": [
        "*"
      ]
    }{{ if .EnableECRAccess }},
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:BatchGetImage"
      ],
      "Resource": [
        "*"
      ]
    }{{ end }}
  ]
}`)
	Expect(err).NotTo(HaveOccurred())
	var writer bytes.Buffer
	if err = templateIAMRolePolicyDocumentNodes.Execute(&writer, struct{ EnableECRAccess *bool }{EnableECRAccess: providerConfig.EnableECRAccess}); err != nil {
		panic(fmt.Errorf("error rendering template: %v", err))
	}
	expectedIAMRolePolicyDocumentNodes := writer.String()
	Expect(iamRolePolicyDocumentNodes).To(MatchJSON(expectedIAMRolePolicyDocumentNodes))
	infrastructureIdentifier.nodesRolePolicyName = getRolePolicyOutputNodes.PolicyName

	return
}

func testDeletion(
	ctx context.Context,
	awsClient *awsClient,
	infrastructureIdentifier infrastructureIdentifiers,
) {
	// vpc

	if infrastructureIdentifier.vpcID != nil {
		describeVpcsOutput, err := awsClient.EC2.DescribeVpcsWithContext(ctx, &ec2.DescribeVpcsInput{VpcIds: []*string{infrastructureIdentifier.vpcID}})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidVpcID.NotFound"))
		Expect(describeVpcsOutput.Vpcs).To(BeEmpty())
	}

	// dhcp options

	if infrastructureIdentifier.dhcpOptionsID != nil {
		describeDhcpOptionsOutput, err := awsClient.EC2.DescribeDhcpOptionsWithContext(ctx, &ec2.DescribeDhcpOptionsInput{DhcpOptionsIds: []*string{infrastructureIdentifier.dhcpOptionsID}})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidDhcpOptionID.NotFound"))
		Expect(describeDhcpOptionsOutput.DhcpOptions).To(BeEmpty())
	}

	// vpc gateway endpoints

	if infrastructureIdentifier.vpcEndpointID != nil {
		describeVpcEndpointsOutput, err := awsClient.EC2.DescribeVpcEndpointsWithContext(ctx, &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: []*string{infrastructureIdentifier.vpcEndpointID}})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidVpcEndpointId.NotFound"))
		Expect(describeVpcEndpointsOutput.VpcEndpoints).To(BeEmpty())
	}

	// internet gateway

	if infrastructureIdentifier.internetGatewayID != nil {
		describeInternetGatewaysOutput, err := awsClient.EC2.DescribeInternetGatewaysWithContext(ctx, &ec2.DescribeInternetGatewaysInput{InternetGatewayIds: []*string{infrastructureIdentifier.internetGatewayID}})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidInternetGatewayID.NotFound"))
		Expect(describeInternetGatewaysOutput.InternetGateways).To(BeEmpty())
	}

	// security groups

	if len(infrastructureIdentifier.securityGroupIDs) > 0 {
		describeSecurityGroupsOutput, err := awsClient.EC2.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: infrastructureIdentifier.securityGroupIDs})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidGroup.NotFound"))
		Expect(describeSecurityGroupsOutput.SecurityGroups).To(BeEmpty())
	}

	// ec2 key pair

	if infrastructureIdentifier.keyPairName != nil {
		describeKeyPairsOutput, err := awsClient.EC2.DescribeKeyPairsWithContext(ctx, &ec2.DescribeKeyPairsInput{KeyNames: []*string{infrastructureIdentifier.keyPairName}})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidKeyPair.NotFound"))
		Expect(describeKeyPairsOutput.KeyPairs).To(BeEmpty())
	}

	// subnets

	if len(infrastructureIdentifier.subnetIDs) > 0 {
		describeSubnetsOutput, err := awsClient.EC2.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{SubnetIds: infrastructureIdentifier.subnetIDs})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidSubnetID.NotFound"))
		Expect(describeSubnetsOutput.Subnets).To(BeEmpty())
	}

	// elastic ips

	if infrastructureIdentifier.elasticIPAllocationID != nil {
		describeAddressesOutput, err := awsClient.EC2.DescribeAddressesWithContext(ctx, &ec2.DescribeAddressesInput{AllocationIds: []*string{infrastructureIdentifier.elasticIPAllocationID}})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidAllocationID.NotFound"))
		Expect(describeAddressesOutput.Addresses).To(BeEmpty())
	}

	// nat gateways

	if infrastructureIdentifier.natGatewayID != nil {
		describeNatGatewaysOutput, err := awsClient.EC2.DescribeNatGatewaysWithContext(ctx, &ec2.DescribeNatGatewaysInput{NatGatewayIds: []*string{infrastructureIdentifier.natGatewayID}})
		if err != nil {
			Expect(err).To(HaveOccurred())
			awsErr, _ := err.(awserr.Error)
			Expect(awsErr.Code()).To(Equal("NatGatewayNotFound"))
			Expect(describeNatGatewaysOutput.NatGateways).To(BeEmpty())
		} else {
			Expect(describeNatGatewaysOutput.NatGateways).To(HaveLen(1))
			Expect(describeNatGatewaysOutput.NatGateways[0].State).To(PointTo(Equal("deleted")))
		}
	}

	// route tables

	if len(infrastructureIdentifier.routeTableIDs) > 0 {
		describeRouteTablesOutput, err := awsClient.EC2.DescribeRouteTablesWithContext(ctx, &ec2.DescribeRouteTablesInput{RouteTableIds: infrastructureIdentifier.routeTableIDs})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("InvalidRouteTableID.NotFound"))
		Expect(describeRouteTablesOutput.RouteTables).To(BeEmpty())
	}

	// IAM resources bastions

	if infrastructureIdentifier.bastionsRoleName != nil {
		getRoleOutputBastions, err := awsClient.IAM.GetRoleWithContext(ctx, &iam.GetRoleInput{RoleName: infrastructureIdentifier.bastionsRoleName})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("NoSuchEntity"))
		Expect(getRoleOutputBastions.Role).To(BeNil())
	}

	if infrastructureIdentifier.bastionsInstanceProfileName != nil {
		getInstanceProfileOutputBastions, err := awsClient.IAM.GetInstanceProfileWithContext(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: infrastructureIdentifier.bastionsInstanceProfileName})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("NoSuchEntity"))
		Expect(getInstanceProfileOutputBastions.InstanceProfile).To(BeNil())
	}

	if infrastructureIdentifier.bastionsRolePolicyName != nil {
		getRolePolicyOutputBastions, err := awsClient.IAM.GetRolePolicyWithContext(ctx, &iam.GetRolePolicyInput{PolicyName: infrastructureIdentifier.bastionsRolePolicyName, RoleName: infrastructureIdentifier.bastionsRoleName})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("NoSuchEntity"))
		Expect(getRolePolicyOutputBastions.PolicyDocument).To(BeNil())
	}

	// IAM resources nodes

	if infrastructureIdentifier.nodesRoleName != nil {
		getRoleOutputNodes, err := awsClient.IAM.GetRoleWithContext(ctx, &iam.GetRoleInput{RoleName: infrastructureIdentifier.nodesRoleName})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("NoSuchEntity"))
		Expect(getRoleOutputNodes.Role).To(BeNil())
	}

	if infrastructureIdentifier.nodesInstanceProfileName != nil {
		getInstanceProfileOutputNodes, err := awsClient.IAM.GetInstanceProfileWithContext(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: infrastructureIdentifier.nodesInstanceProfileName})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("NoSuchEntity"))
		Expect(getInstanceProfileOutputNodes.InstanceProfile).To(BeNil())
	}

	if infrastructureIdentifier.nodesRolePolicyName != nil {
		getRolePolicyOutputNodes, err := awsClient.IAM.GetRolePolicyWithContext(ctx, &iam.GetRolePolicyInput{PolicyName: infrastructureIdentifier.nodesRolePolicyName, RoleName: infrastructureIdentifier.nodesRoleName})
		Expect(err).To(HaveOccurred())
		awsErr, _ := err.(awserr.Error)
		Expect(awsErr.Code()).To(Equal("NoSuchEntity"))
		Expect(getRolePolicyOutputNodes.PolicyDocument).To(BeNil())
	}
}
