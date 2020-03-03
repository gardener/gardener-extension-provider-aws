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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apiv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
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
	}
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

		restConfig *rest.Config
		c          client.Client

		scheme        *runtime.Scheme
		decoder       runtime.Decoder
		chartRenderer chartrenderer.Interface
	)

	BeforeEach(func() {
		awsClient = newAWSClient(*accessKeyID, *secretAccessKey, *region)

		k8sClient, err := kubernetes.NewClientFromFile("", *kubeconfig)
		if err != nil {
			panic(err)
		}
		restConfig = k8sClient.RESTConfig()
		c = k8sClient.Client()

		scheme = runtime.NewScheme()
		_ = api.AddToScheme(scheme)
		_ = apiv1alpha1.AddToScheme(scheme)
		decoder = serializer.NewCodecFactory(scheme).UniversalDecoder()
		chartRenderer = chartrenderer.New(engine.New(), &chartutil.Capabilities{})
	})

	Describe("#Reconcile, #Delete", func() {
		var (
			cidr            = pointer.StringPtr("10.250.0.0/16")
			gatewayEndpoint = "s3"
			secretName      = "cloudprovider"
		)

		It("should correctly create and delete the expected AWS resources", func() {
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "provider-aws-test-",
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

			providerConfig := apiv1alpha1.InfrastructureConfig{
				TypeMeta: metav1.TypeMeta{
					APIVersion: apiv1alpha1.SchemeGroupVersion.String(),
					Kind:       "InfrastructureConfig",
				},
				Networks: apiv1alpha1.Networks{
					VPC: apiv1alpha1.VPC{
						CIDR:             cidr,
						GatewayEndpoints: []string{gatewayEndpoint},
					},
					Zones: []apiv1alpha1.Zone{
						{
							Name:     *region + "a",
							Internal: "10.250.112.0/22",
							Public:   "10.250.96.0/22",
							Workers:  "10.250.0.0/19",
						},
					},
				},
			}
			providerConfigJSON, _ := json.Marshal(providerConfig)

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
					SSHPublicKey: []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcSZKq0lM9w+ElLp9I9jFvqEFbOV1+iOBX7WEe66GvPLOWl9ul03ecjhOf06+FhPsWFac1yaxo2xj+SJ+FVZ3DdSn4fjTpS9NGyQVPInSZveetRw0TV0rbYCFBTJuVqUFu6yPEgdcWq8dlUjLqnRNwlelHRcJeBfACBZDLNSxjj0oUz7ANRNCEne1ecySwuJUAz3IlNLPXFexRT0alV7Nl9hmJke3dD73nbeGbQtwvtu8GNFEoO4Eu3xOCKsLw6ILLo4FBiFcYQOZqvYZgCb4ncKM52bnABagG54upgBMZBRzOJvWp0ol+jK3Em7Vb6ufDTTVNiQY78U6BAlNZ8Xg+LUVeyk1C6vWjzAQf02eRvMdfnRCFvmwUpzbHWaVMsQm8gf3AgnTUuDR0ev1nQH/5892wZA86uLYW/wLiiSbvQsqtY1jSn9BAGFGdhXgWLAkGsd/E1vOT+vDcor6/6KjHBm0rG697A3TDBRkbXQ/1oFxcM9m17RteCaXuTiAYWMqGKDoJvTMDc4L+Uvy544pEfbOH39zfkIYE76WLAFPFsUWX6lXFjQrX3O7vEV73bCHoJnwzaNd03PSdJOw+LCzrTmxVezwli3F9wUDiBRB0HkQxIXQmncc1HSecCKALkogIK+1e1OumoWh6gPdkF4PlTMUxRitrwPWSaiUIlPfCpQ== your_email@example.com"),
				},
			}

			defer func() {
				Expect(infrastructure.Delete(ctx, logger, restConfig, c, infra)).NotTo(HaveOccurred())
				Expect(client.IgnoreNotFound(c.Delete(ctx, namespace))).NotTo(HaveOccurred())
			}()

			infraStatus, _, err := infrastructure.Reconcile(ctx, logger, restConfig, c, decoder, chartRenderer, infra)
			Expect(err).NotTo(HaveOccurred())

			var (
				nameFilter = []*ec2.Filter{
					{
						Name: awssdk.String("tag:Name"),
						Values: []*string{
							awssdk.String(infra.Namespace),
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
						Key:   awssdk.String("kubernetes.io/cluster/" + infra.Namespace),
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

			// vpc gateway endpoints

			describeVpcEndpointsOutput, err := awsClient.EC2.DescribeVpcEndpointsWithContext(ctx, &ec2.DescribeVpcEndpointsInput{Filters: vpcIDFilter})
			Expect(err).NotTo(HaveOccurred())
			Expect(describeVpcEndpointsOutput.VpcEndpoints).To(HaveLen(1))
			Expect(describeVpcEndpointsOutput.VpcEndpoints[0].ServiceName).To(PointTo(Equal(fmt.Sprintf("com.amazonaws.%s.%s", *region, gatewayEndpoint))))
			Expect(describeVpcEndpointsOutput.VpcEndpoints[0].Tags).To(ConsistOf([]*ec2.Tag{
				{
					Key:   awssdk.String("kubernetes.io/cluster/" + infra.Namespace),
					Value: awssdk.String("1"),
				},
				{
					Key:   awssdk.String("Name"),
					Value: awssdk.String(infra.Namespace + "-gw-" + gatewayEndpoint),
				},
			}))

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

			// security groups + security group rules

			describeSecurityGroupsOutput, err := awsClient.EC2.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{Filters: vpcIDFilter})
			Expect(err).NotTo(HaveOccurred())
			Expect(describeSecurityGroupsOutput.SecurityGroups).To(HaveLen(2))
			for _, securityGroup := range describeSecurityGroupsOutput.SecurityGroups {
				if securityGroup.GroupName != nil && *securityGroup.GroupName == "default" {
					Expect(securityGroup.IpPermissions).To(BeEmpty())
					Expect(securityGroup.IpPermissionsEgress).To(BeEmpty())
					Expect(securityGroup.Tags).To(BeEmpty())
				} else {
					Expect(securityGroup.IpPermissions).To(Equal([]*ec2.IpPermission{
						{
							FromPort:   awssdk.Int64(30000),
							IpProtocol: awssdk.String("tcp"),
							IpRanges: []*ec2.IpRange{
								{
									CidrIp: awssdk.String("10.250.96.0/22"),
								},
								{
									CidrIp: awssdk.String("0.0.0.0/0"),
								},
								{
									CidrIp: awssdk.String("10.250.112.0/22"),
								},
							},
							ToPort: awssdk.Int64(32767),
						},
						{
							IpProtocol: awssdk.String("-1"),
							UserIdGroupPairs: []*ec2.UserIdGroupPair{
								{
									GroupId: awssdk.String("sg-0be00e025bdb333e3"),
									UserId:  awssdk.String("802691470131"),
								},
							},
						},
						{
							FromPort:   awssdk.Int64(30000),
							IpProtocol: awssdk.String("udp"),
							IpRanges: []*ec2.IpRange{
								{
									CidrIp: awssdk.String("10.250.96.0/22"),
								},
								{
									CidrIp: awssdk.String("10.250.112.0/22"),
								},
								{
									CidrIp: awssdk.String("0.0.0.0/0"),
								},
							},
							ToPort: awssdk.Int64(32767),
						},
					}))
					Expect(securityGroup.IpPermissionsEgress).To(Equal([]*ec2.IpPermission{
						{
							IpProtocol: awssdk.String("-1"),
							IpRanges: []*ec2.IpRange{
								{CidrIp: awssdk.String("0.0.0.0/0")},
							},
						},
					}))
					Expect(securityGroup.Tags).To(ConsistOf(defaultTags))
				}
			}
		})
	})
})
