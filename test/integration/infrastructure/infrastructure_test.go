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
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
	"time"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	gardenerutils "github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	awsinstall "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/aws/matchers"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"
)

const (
	s3GatewayEndpoint = "s3"
	vpcCIDR           = "10.250.0.0/16"

	kubernetesTagPrefix        = "kubernetes.io/"
	kubernetesClusterTagPrefix = kubernetesTagPrefix + "cluster/"
	kubernetesRoleTagPrefix    = kubernetesTagPrefix + "role/"
	ignoredTagKey              = "SomeIgnoredTag"
	ignoredTagKeyPrefix        = "ignored-tag/prefix/"
)

var (
	accessKeyID     = flag.String("access-key-id", "", "AWS access key id")
	secretAccessKey = flag.String("secret-access-key", "", "AWS secret access key")
	region          = flag.String("region", "", "AWS region")
)

func validateFlags() {
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

var _ = Describe("Infrastructure tests", func() {
	var (
		ctx    = context.Background()
		logger *logrus.Entry

		testEnv   *envtest.Environment
		mgrCancel context.CancelFunc
		c         client.Client
		decoder   runtime.Decoder

		awsClient *awsclient.Client

		internalChartsPath string
	)

	BeforeSuite(func() {
		internalChartsPath = aws.InternalChartsPath
		repoRoot := filepath.Join("..", "..", "..")
		aws.InternalChartsPath = filepath.Join(repoRoot, aws.InternalChartsPath)

		// enable manager logs
		logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(GinkgoWriter)))

		log := logrus.New()
		log.SetOutput(GinkgoWriter)
		logger = logrus.NewEntry(log)

		By("starting test environment")
		testEnv = &envtest.Environment{
			UseExistingCluster: pointer.BoolPtr(true),
			CRDInstallOptions: envtest.CRDInstallOptions{
				Paths: []string{
					filepath.Join(repoRoot, "example", "20-crd-cluster.yaml"),
					filepath.Join(repoRoot, "example", "20-crd-infrastructure.yaml"),
				},
			},
		}

		cfg, err := testEnv.Start()
		Expect(err).ToNot(HaveOccurred())
		Expect(cfg).ToNot(BeNil())

		By("setup manager")
		mgr, err := manager.New(cfg, manager.Options{
			MetricsBindAddress: "0",
		})
		Expect(err).ToNot(HaveOccurred())

		Expect(extensionsv1alpha1.AddToScheme(mgr.GetScheme())).To(Succeed())
		Expect(awsinstall.AddToScheme(mgr.GetScheme())).To(Succeed())

		Expect(infrastructure.AddToManager(mgr)).To(Succeed())

		var mgrContext context.Context
		mgrContext, mgrCancel = context.WithCancel(ctx)

		By("start manager")
		go func() {
			err := mgr.Start(mgrContext)
			Expect(err).NotTo(HaveOccurred())
		}()

		// test client should be uncached and independent from the tested manager
		c, err = client.New(cfg, client.Options{
			Scheme: mgr.GetScheme(),
			Mapper: mgr.GetRESTMapper(),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(BeNil())
		decoder = serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder()

		flag.Parse()
		validateFlags()

		awsClient, err = awsclient.NewClient(*accessKeyID, *secretAccessKey, *region)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterSuite(func() {
		defer func() {
			By("stopping manager")
			mgrCancel()
		}()

		By("running cleanup actions")
		framework.RunCleanupActions()

		By("stopping test environment")
		Expect(testEnv.Stop()).To(Succeed())

		aws.InternalChartsPath = internalChartsPath
	})

	Context("with infrastructure that requests new vpc (networks.vpc.cidr)", func() {
		It("should successfully create and delete", func() {
			providerConfig := newProviderConfig(awsv1alpha1.VPC{
				CIDR:             pointer.StringPtr(vpcCIDR),
				GatewayEndpoints: []string{s3GatewayEndpoint},
			})

			namespace, err := generateNamespaceName()
			Expect(err).NotTo(HaveOccurred())

			err = runTest(ctx, logger, c, namespace, providerConfig, decoder, awsClient)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("with infrastructure that uses existing vpc (networks.vpc.id)", func() {
		It("should fail to create when required vpc attribute is not enabled", func() {
			enableDnsHostnames := false
			vpcID, err := prepareNewVPC(ctx, logger, awsClient, vpcCIDR, enableDnsHostnames)
			Expect(err).NotTo(HaveOccurred())
			Expect(vpcID).NotTo(BeEmpty())

			framework.AddCleanupAction(func() {
				err := teardownVPC(ctx, logger, awsClient, vpcID)
				Expect(err).NotTo(HaveOccurred())
			})

			providerConfig := newProviderConfig(awsv1alpha1.VPC{
				ID:               &vpcID,
				GatewayEndpoints: []string{s3GatewayEndpoint},
			})

			namespace, err := generateNamespaceName()
			Expect(err).NotTo(HaveOccurred())

			err = runTest(ctx, logger, c, namespace, providerConfig, decoder, awsClient)
			Expect(err).To(HaveOccurred())

			By("verify infrastructure status")
			infra := &extensionsv1alpha1.Infrastructure{}
			err = c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "infrastructure"}, infra)
			Expect(err).NotTo(HaveOccurred())

			Expect(infra.Status.LastError).NotTo(BeNil())
			Expect(infra.Status.LastError.Description).To(ContainSubstring("invalid VPC attributes: `enableDnsHostnames` must be set to `true`"))
		})

		It("should successfully create and delete", func() {
			enableDnsHostnames := true
			vpcID, err := prepareNewVPC(ctx, logger, awsClient, vpcCIDR, enableDnsHostnames)
			Expect(err).NotTo(HaveOccurred())
			Expect(vpcID).NotTo(BeEmpty())

			framework.AddCleanupAction(func() {
				err := teardownVPC(ctx, logger, awsClient, vpcID)
				Expect(err).NotTo(HaveOccurred())
			})

			providerConfig := newProviderConfig(awsv1alpha1.VPC{
				ID:               &vpcID,
				GatewayEndpoints: []string{s3GatewayEndpoint},
			})

			namespace, err := generateNamespaceName()
			Expect(err).NotTo(HaveOccurred())

			err = runTest(ctx, logger, c, namespace, providerConfig, decoder, awsClient)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

func runTest(ctx context.Context, logger *logrus.Entry, c client.Client, namespaceName string, providerConfig *awsv1alpha1.InfrastructureConfig, decoder runtime.Decoder, awsClient *awsclient.Client) error {
	var (
		namespace                 *corev1.Namespace
		cluster                   *extensionsv1alpha1.Cluster
		infra                     *extensionsv1alpha1.Infrastructure
		infrastructureIdentifiers infrastructureIdentifiers
	)

	framework.AddCleanupAction(func() {
		By("delete infrastructure")
		Expect(client.IgnoreNotFound(c.Delete(ctx, infra))).To(Succeed())

		By("wait until infrastructure is deleted")
		err := extensions.WaitUntilExtensionCRDeleted(
			ctx,
			c,
			logger,
			func() extensionsv1alpha1.Object { return &extensionsv1alpha1.Infrastructure{} },
			"Infrastructure",
			infra.Namespace,
			infra.Name,
			10*time.Second,
			16*time.Minute,
		)
		Expect(err).NotTo(HaveOccurred())

		By("verify infrastructure deletion")
		verifyDeletion(ctx, awsClient, infrastructureIdentifiers)

		Expect(client.IgnoreNotFound(c.Delete(ctx, namespace))).To(Succeed())
		Expect(client.IgnoreNotFound(c.Delete(ctx, cluster))).To(Succeed())
	})

	By("create namespace for test execution")
	namespace = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}
	if err := c.Create(ctx, namespace); err != nil {
		return err
	}

	By("create cluster")
	cluster = &extensionsv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}
	if err := c.Create(ctx, cluster); err != nil {
		return err
	}

	By("deploy cloudprovider secret into namespace")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cloudprovider",
			Namespace: namespaceName,
		},
		Data: map[string][]byte{
			aws.AccessKeyID:     []byte(*accessKeyID),
			aws.SecretAccessKey: []byte(*secretAccessKey),
		},
	}
	if err := c.Create(ctx, secret); err != nil {
		return err
	}

	By("create infrastructure")
	infra, err := newInfrastructure(namespaceName, providerConfig)
	if err != nil {
		return err
	}

	if err := c.Create(ctx, infra); err != nil {
		return err
	}

	By("wait until infrastructure is created")
	if err := extensions.WaitUntilExtensionCRReady(
		ctx,
		c,
		logger,
		func() client.Object { return &extensionsv1alpha1.Infrastructure{} },
		extensionsv1alpha1.InfrastructureResource,
		infra.Namespace,
		infra.Name,
		10*time.Second,
		30*time.Second,
		16*time.Minute,
		nil,
	); err != nil {
		return err
	}

	By("decode infrastucture status")
	if err := c.Get(ctx, client.ObjectKey{Namespace: infra.Namespace, Name: infra.Name}, infra); err != nil {
		return err
	}

	providerStatus := &awsv1alpha1.InfrastructureStatus{}
	if _, _, err := decoder.Decode(infra.Status.ProviderStatus.Raw, nil, providerStatus); err != nil {
		return err
	}

	By("verify infrastructure creation")
	infrastructureIdentifiers = verifyCreation(ctx, awsClient, infra, providerStatus, providerConfig, pointer.StringPtr(vpcCIDR), s3GatewayEndpoint)

	By("add tags to subnet")
	// add some ignored and not ignored tags to subnet and verify that ignored tags are not removed in the next reconciliation
	taggedSubnetID := infrastructureIdentifiers.subnetIDs[0]
	Expect(createTagsSubnet(ctx, awsClient, taggedSubnetID)).To(Succeed())

	By("triggering infrastructure reconciliation")
	infraCopy := infra.DeepCopy()
	metav1.SetMetaDataAnnotation(&infra.ObjectMeta, "gardener.cloud/operation", "reconcile")
	Expect(c.Patch(ctx, infra, client.MergeFrom(infraCopy))).To(Succeed())

	By("wait until infrastructure is reconciled")
	if err := extensions.WaitUntilExtensionCRReady(
		ctx,
		c,
		logger,
		func() client.Object { return &extensionsv1alpha1.Infrastructure{} },
		"Infrastucture",
		infra.Namespace,
		infra.Name,
		10*time.Second,
		30*time.Second,
		16*time.Minute,
		nil,
	); err != nil {
		return err
	}

	By("verify tags on subnet")
	verifyTagsSubnet(ctx, awsClient, taggedSubnetID)

	return nil
}

func newProviderConfig(vpc awsv1alpha1.VPC) *awsv1alpha1.InfrastructureConfig {
	availabilityZone := *region + "a"

	return &awsv1alpha1.InfrastructureConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
			Kind:       "InfrastructureConfig",
		},
		EnableECRAccess: pointer.BoolPtr(true),
		Networks: awsv1alpha1.Networks{
			VPC: vpc,
			Zones: []awsv1alpha1.Zone{
				{
					Name:     availabilityZone,
					Internal: "10.250.112.0/22",
					Public:   "10.250.96.0/22",
					Workers:  "10.250.0.0/19",
				},
			},
		},
		IgnoreTags: &awsv1alpha1.IgnoreTags{
			Keys:        []string{ignoredTagKey},
			KeyPrefixes: []string{ignoredTagKeyPrefix},
		},
	}
}

func newInfrastructure(namespace string, providerConfig *awsv1alpha1.InfrastructureConfig) (*extensionsv1alpha1.Infrastructure, error) {
	const sshPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcSZKq0lM9w+ElLp9I9jFvqEFbOV1+iOBX7WEe66GvPLOWl9ul03ecjhOf06+FhPsWFac1yaxo2xj+SJ+FVZ3DdSn4fjTpS9NGyQVPInSZveetRw0TV0rbYCFBTJuVqUFu6yPEgdcWq8dlUjLqnRNwlelHRcJeBfACBZDLNSxjj0oUz7ANRNCEne1ecySwuJUAz3IlNLPXFexRT0alV7Nl9hmJke3dD73nbeGbQtwvtu8GNFEoO4Eu3xOCKsLw6ILLo4FBiFcYQOZqvYZgCb4ncKM52bnABagG54upgBMZBRzOJvWp0ol+jK3Em7Vb6ufDTTVNiQY78U6BAlNZ8Xg+LUVeyk1C6vWjzAQf02eRvMdfnRCFvmwUpzbHWaVMsQm8gf3AgnTUuDR0ev1nQH/5892wZA86uLYW/wLiiSbvQsqtY1jSn9BAGFGdhXgWLAkGsd/E1vOT+vDcor6/6KjHBm0rG697A3TDBRkbXQ/1oFxcM9m17RteCaXuTiAYWMqGKDoJvTMDc4L+Uvy544pEfbOH39zfkIYE76WLAFPFsUWX6lXFjQrX3O7vEV73bCHoJnwzaNd03PSdJOw+LCzrTmxVezwli3F9wUDiBRB0HkQxIXQmncc1HSecCKALkogIK+1e1OumoWh6gPdkF4PlTMUxRitrwPWSaiUIlPfCpQ== your_email@example.com"

	providerConfigJSON, err := json.Marshal(&providerConfig)
	if err != nil {
		return nil, err
	}

	return &extensionsv1alpha1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "infrastructure",
			Namespace: namespace,
		},
		Spec: extensionsv1alpha1.InfrastructureSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type: aws.Type,
				ProviderConfig: &runtime.RawExtension{
					Raw: providerConfigJSON,
				},
			},
			SecretRef: corev1.SecretReference{
				Name:      "cloudprovider",
				Namespace: namespace,
			},
			Region:       *region,
			SSHPublicKey: []byte(sshPublicKey),
		},
	}, nil
}

func generateNamespaceName() (string, error) {
	suffix, err := gardenerutils.GenerateRandomStringFromCharset(5, "0123456789abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		return "", err
	}

	return "aws-infrastructure-it--" + suffix, nil
}

func prepareNewVPC(ctx context.Context, logger *logrus.Entry, awsClient *awsclient.Client, vpcCIDR string, enableDnsHostnames bool) (string, error) {
	entry := logger.WithField("test", "existing-vpc")

	createVpcOutput, err := awsClient.EC2.CreateVpc(&ec2.CreateVpcInput{
		CidrBlock: awssdk.String(vpcCIDR),
	})
	if err != nil {
		return "", err
	}
	vpcID := createVpcOutput.Vpc.VpcId

	if err := wait.PollUntil(5*time.Second, func() (bool, error) {
		entry.Infof("Waiting until vpc '%s' is avaiable...", *vpcID)

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
	}, ctx.Done()); err != nil {
		return "", err
	}

	if enableDnsHostnames {
		_, err = awsClient.EC2.ModifyVpcAttribute(&ec2.ModifyVpcAttributeInput{
			EnableDnsHostnames: &ec2.AttributeBooleanValue{
				Value: awssdk.Bool(true),
			},
			VpcId: vpcID,
		})
		if err != nil {
			return "", err
		}
	}

	createIgwOutput, err := awsClient.EC2.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
	if err != nil {
		return "", err
	}
	igwID := createIgwOutput.InternetGateway.InternetGatewayId

	_, err = awsClient.EC2.AttachInternetGateway(&ec2.AttachInternetGatewayInput{
		InternetGatewayId: igwID,
		VpcId:             vpcID,
	})
	if err != nil {
		return "", err
	}

	if err := wait.PollUntil(5*time.Second, func() (bool, error) {
		entry.Infof("Waiting until internet gateway '%s' is attached to vpc '%s'...", *igwID, *vpcID)

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
	}, ctx.Done()); err != nil {
		return "", err
	}

	return *vpcID, nil
}

func createTagsSubnet(ctx context.Context, awsClient *awsclient.Client, subnetID *string) error {
	_, err := awsClient.EC2.CreateTagsWithContext(ctx, &ec2.CreateTagsInput{
		Resources: []*string{subnetID},
		Tags: []*ec2.Tag{{
			Key:   awssdk.String(ignoredTagKey),
			Value: awssdk.String("foo"),
		}, {
			Key:   awssdk.String(ignoredTagKeyPrefix + "key"),
			Value: awssdk.String("bar"),
		}, {
			Key:   awssdk.String("not-ignored-key"),
			Value: awssdk.String("foo"),
		}, {
			Key:   awssdk.String("not-ignored-prefix/key"),
			Value: awssdk.String("bar"),
		}},
	})
	return err
}

func teardownVPC(ctx context.Context, logger *logrus.Entry, awsClient *awsclient.Client, vpcID string) error {
	entry := logger.WithField("test", "existing-vpc")

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

	if err := wait.PollUntil(5*time.Second, func() (bool, error) {
		entry.Infof("Waiting until internet gateway '%s' is detached from vpc '%s'...", *igwID, vpcID)

		describeIgwOutput, err := awsClient.EC2.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{
			InternetGatewayIds: []*string{igwID},
		})
		if err != nil {
			return false, err
		}
		igw := describeIgwOutput.InternetGateways[0]

		return len(igw.Attachments) == 0, nil
	}, ctx.Done()); err != nil {
		return err
	}

	_, err = awsClient.EC2.DeleteInternetGateway(&ec2.DeleteInternetGatewayInput{
		InternetGatewayId: igwID,
	})
	if err != nil {
		return err
	}

	if err := wait.PollUntil(5*time.Second, func() (bool, error) {
		entry.Infof("Waiting until internet gateway '%s' is deleted...", *igwID)

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
	}, ctx.Done()); err != nil {
		return err
	}

	_, err = awsClient.EC2.DeleteVpc(&ec2.DeleteVpcInput{
		VpcId: &vpcID,
	})
	if err != nil {
		return err
	}

	if err := wait.PollUntil(5*time.Second, func() (bool, error) {
		entry.Infof("Waiting until vpc '%s' is deleted...", vpcID)

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
	}, ctx.Done()); err != nil {
		return err
	}

	return nil
}

type infrastructureIdentifiers struct {
	vpcID                    *string
	dhcpOptionsID            *string
	vpcEndpointID            *string
	internetGatewayID        *string
	securityGroupIDs         []*string
	keyPairName              *string
	subnetIDs                []*string
	elasticIPAllocationID    *string
	natGatewayID             *string
	routeTableIDs            []*string
	nodesRoleName            *string
	nodesInstanceProfileName *string
	nodesRolePolicyName      *string
}

func verifyCreation(
	ctx context.Context,
	awsClient *awsclient.Client,
	infra *extensionsv1alpha1.Infrastructure,
	infraStatus *awsv1alpha1.InfrastructureStatus,
	providerConfig *awsv1alpha1.InfrastructureConfig,
	cidr *string,
	gatewayEndpoint string,
) (
	infrastructureIdentifier infrastructureIdentifiers,
) {
	const (
		privateUtilitySuffix = "-private-utility-z0"
		publicUtilitySuffix  = "-public-utility-z0"
		nodesSuffix          = "-nodes-z0"

		sshPublicKeyDigest = "46:ca:46:0e:8e:1d:bc:0c:45:31:ee:0f:43:5f:9b:f1"
		allCIDR            = "0.0.0.0/0"
	)

	var (
		kubernetesTagFilter = []*ec2.Filter{
			{
				Name: awssdk.String("tag:" + kubernetesClusterTagPrefix + infra.Namespace),
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
				Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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
	if providerConfig.Networks.VPC.CIDR != nil {
		Expect(describeVpcsOutput.Vpcs[0].Tags).To(ConsistOf(defaultTags))
		infrastructureIdentifier.vpcID = describeVpcsOutput.Vpcs[0].VpcId
	}

	// dhcp options + dhcp options attachment

	describeDhcpOptionsOutput, err := awsClient.EC2.DescribeDhcpOptionsWithContext(ctx, &ec2.DescribeDhcpOptionsInput{DhcpOptionsIds: []*string{describeVpcsOutput.Vpcs[0].DhcpOptionsId}})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeDhcpOptionsOutput.DhcpOptions).To(HaveLen(1))
	Expect(describeVpcsOutput.Vpcs[0].DhcpOptionsId).To(Equal(describeDhcpOptionsOutput.DhcpOptions[0].DhcpOptionsId))
	Expect(describeDhcpOptionsOutput.DhcpOptions[0].DhcpConfigurations).To(ConsistOf([]*ec2.DhcpConfiguration{
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
	if providerConfig.Networks.VPC.CIDR != nil {
		Expect(describeDhcpOptionsOutput.DhcpOptions[0].Tags).To(ConsistOf(defaultTags))
		infrastructureIdentifier.dhcpOptionsID = describeDhcpOptionsOutput.DhcpOptions[0].DhcpOptionsId
	}

	// vpc gateway endpoints

	describeVpcEndpointsOutput, err := awsClient.EC2.DescribeVpcEndpointsWithContext(ctx, &ec2.DescribeVpcEndpointsInput{Filters: vpcIDFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeVpcEndpointsOutput.VpcEndpoints).To(HaveLen(1))
	Expect(describeVpcEndpointsOutput.VpcEndpoints[0].ServiceName).To(PointTo(Equal(fmt.Sprintf("com.amazonaws.%s.%s", *region, gatewayEndpoint))))
	Expect(describeVpcEndpointsOutput.VpcEndpoints[0].Tags).To(ConsistOf([]*ec2.Tag{
		{
			Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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
	if providerConfig.Networks.VPC.CIDR != nil {
		Expect(describeInternetGatewaysOutput.InternetGateways[0].Tags).To(ConsistOf(defaultTags))
		infrastructureIdentifier.internetGatewayID = describeInternetGatewaysOutput.InternetGateways[0].InternetGatewayId
	}

	// security groups + security group rules

	var (
		internalCIDR = providerConfig.Networks.Zones[0].Internal
		workersCIDR  = providerConfig.Networks.Zones[0].Workers
		publicCIDR   = providerConfig.Networks.Zones[0].Public
	)

	accountID, err := awsClient.GetAccountID(ctx)
	Expect(err).NotTo(HaveOccurred())

	infrastructureIdentifier.securityGroupIDs = []*string{}
	describeSecurityGroupsOutput, err := awsClient.EC2.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{Filters: vpcIDFilter})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeSecurityGroupsOutput.SecurityGroups).To(HaveLen(2))
	for _, securityGroup := range describeSecurityGroupsOutput.SecurityGroups {
		if securityGroup.GroupName != nil && *securityGroup.GroupName == "default" && providerConfig.Networks.VPC.CIDR != nil {
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
					Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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

	availabilityZone := providerConfig.Networks.Zones[0].Name

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
						Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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
						Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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
						Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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
			Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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
			Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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
				Expect(routeTable.Tags).To(ConsistOf(defaultTags))
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
						Key:   awssdk.String(kubernetesClusterTagPrefix + infra.Namespace),
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
	infrastructureIdentifier.nodesRoleName = getRoleOutputNodes.Role.RoleName

	getInstanceProfileOutputNodes, err := awsClient.IAM.GetInstanceProfileWithContext(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: awssdk.String(infra.Namespace + "-nodes")})
	Expect(err).NotTo(HaveOccurred())
	Expect(getInstanceProfileOutputNodes.InstanceProfile).NotTo(BeNil())
	iamInstanceProfileNodes := *getInstanceProfileOutputNodes.InstanceProfile
	Expect(iamInstanceProfileNodes.Path).To(Equal(awssdk.String("/")))
	Expect(iamInstanceProfileNodes.Roles).To(BeSemanticallyEqualTo([]*iam.Role{getRoleOutputNodes.Role}))
	infrastructureIdentifier.nodesInstanceProfileName = getInstanceProfileOutputNodes.InstanceProfile.InstanceProfileName

	getRolePolicyOutputNodes, err := awsClient.IAM.GetRolePolicyWithContext(ctx, &iam.GetRolePolicyInput{PolicyName: awssdk.String(infra.Namespace + "-nodes"), RoleName: awssdk.String(infra.Namespace + "-nodes")})
	Expect(err).NotTo(HaveOccurred())
	Expect(getRolePolicyOutputNodes.RoleName).To(Equal(awssdk.String(infra.Namespace + "-nodes")))
	Expect(getRolePolicyOutputNodes.PolicyName).To(Equal(awssdk.String(infra.Namespace + "-nodes")))
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
	err = templateIAMRolePolicyDocumentNodes.Execute(&writer, struct{ EnableECRAccess *bool }{EnableECRAccess: providerConfig.EnableECRAccess})
	Expect(err).NotTo(HaveOccurred())
	expectedIAMRolePolicyDocumentNodes := writer.String()
	Expect(getRolePolicyOutputNodes.PolicyDocument).To(BeSemanticallyEqualToRolePolicyDocument(expectedIAMRolePolicyDocumentNodes))
	infrastructureIdentifier.nodesRolePolicyName = getRolePolicyOutputNodes.PolicyName

	return
}

func verifyTagsSubnet(ctx context.Context, awsClient *awsclient.Client, subnetID *string) {
	describeSubnetsOutput, err := awsClient.EC2.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []*string{subnetID}})
	Expect(err).NotTo(HaveOccurred())
	Expect(describeSubnetsOutput.Subnets).To(HaveLen(1))

	for _, tag := range describeSubnetsOutput.Subnets[0].Tags {
		switch {
		case *tag.Key == "Name":
		case strings.HasPrefix(*tag.Key, kubernetesTagPrefix):
		case *tag.Key == ignoredTagKey:
		case strings.HasPrefix(*tag.Key, ignoredTagKeyPrefix):
		default:
			Fail(fmt.Sprintf("unexpected key %q found on subnet %s", *tag.Key, *subnetID))
		}
	}
}

func verifyDeletion(
	ctx context.Context,
	awsClient *awsclient.Client,
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
