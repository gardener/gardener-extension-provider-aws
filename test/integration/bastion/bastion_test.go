// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion_test

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"time"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/logger"
	gardenerutils "github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/test/framework"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	awsinstall "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	bastionctrl "github.com/gardener/gardener-extension-provider-aws/pkg/controller/bastion"
	"github.com/gardener/gardener-extension-provider-aws/test/integration"
)

const (
	mockCidrv6          = "fd12:3456:789a:1::/64" // test ingress rule for ipV6
	vpcCIDR             = "10.250.0.0/16"
	subnetCIDR          = "10.250.0.0/18"
	publicUtilitySuffix = "public-utility-z0"
	imageVersion        = "1.0.0" // not the real version - only used in the cloudProfile
	imageName           = "gardenlinux-aws-gardener*"
)

var (
	accessKeyID     = flag.String("access-key-id", "", "AWS access key id")
	secretAccessKey = flag.String("secret-access-key", "", "AWS secret access key")
	region          = flag.String("region", "", "AWS region")
	logLevel        = flag.String("logLevel", "", "Log level (debug, info, error)")
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
	if len(*logLevel) == 0 {
		logLevel = ptr.To(logger.DebugLevel)
	} else {
		if !slices.Contains(logger.AllLogLevels, *logLevel) {
			panic("invalid log level: " + *logLevel)
		}
	}
}

var (
	ctx = context.Background()

	log       logr.Logger
	awsClient *awsclient.Client

	extensionscluster *extensionsv1alpha1.Cluster
	corecluster       *controller.Cluster

	testEnv   *envtest.Environment
	mgrCancel context.CancelFunc
	c         client.Client

	namespaceName string
	namespace     *corev1.Namespace
	myPublicIPv4  string
)

var _ = BeforeSuite(func() {
	repoRoot := filepath.Join("..", "..", "..")

	// enable manager logs
	logf.SetLogger(logger.MustNewZapLogger(*logLevel, logger.FormatJSON, zap.WriteTo(GinkgoWriter)))

	log = logf.Log.WithName("bastion-test")

	DeferCleanup(func() {
		defer func() {
			By("stopping manager")
			mgrCancel()
		}()

		By("running cleanup actions")
		framework.RunCleanupActions()

		By("stopping test environment")
		Expect(testEnv.Stop()).To(Succeed())
	})

	By("generating randomized test resource identifiers")
	randString, err := randomString()
	Expect(err).NotTo(HaveOccurred())

	namespaceName = fmt.Sprintf("aws-bastion-it--%s", randString)
	namespace = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}

	myPublicIPv4, err = getMyPublicIPWithMask()
	Expect(err).NotTo(HaveOccurred())

	By("starting test environment")
	testEnv = &envtest.Environment{
		UseExistingCluster: ptr.To(true),
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{
				filepath.Join(repoRoot, "example", "20-crd-extensions.gardener.cloud_bastions.yaml"),
				filepath.Join(repoRoot, "example", "20-crd-extensions.gardener.cloud_clusters.yaml"),
			},
		},
	}

	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	By("setup manager")
	mgr, err := manager.New(cfg, manager.Options{
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	Expect(err).ToNot(HaveOccurred())

	Expect(extensionsv1alpha1.AddToScheme(mgr.GetScheme())).To(Succeed())
	Expect(awsinstall.AddToScheme(mgr.GetScheme())).To(Succeed())

	Expect(bastionctrl.AddToManager(ctx, mgr)).To(Succeed())

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

	flag.Parse()
	validateFlags()

	awsClient, err = awsclient.NewClient(*accessKeyID, *secretAccessKey, *region)
	Expect(err).NotTo(HaveOccurred())

	imageAMI := getImageAMI(ctx, imageName, awsClient)
	extensionscluster, corecluster = newCluster(namespaceName, imageAMI)
})

var _ = Describe("Bastion tests", func() {
	It("should successfully create and delete", func() {
		By("setup infrastructure")
		infra := setupInfrastructure(ctx, log, awsClient, extensionscluster.ObjectMeta.Name)
		framework.AddCleanupAction(func() {
			teardownInfrastructure(ctx, awsClient, infra)
		})

		By("setup shoot environment")
		setupShootEnvironment(ctx, c, namespace, extensionscluster)
		framework.AddCleanupAction(func() {
			teardownShootEnvironment(ctx, c, namespace, extensionscluster)
		})

		By("setup bastion")
		bastion, options := setupBastion(ctx, awsClient, c, namespaceName, corecluster)
		framework.AddCleanupAction(func() {
			teardownBastion(ctx, log, c, bastion)

			By("verify bastion deletion")
			verifyDeletion(ctx, awsClient, options)
		})

		By("wait until bastion is reconciled")
		Expect(extensions.WaitUntilExtensionObjectReady(
			ctx,
			c,
			log,
			bastion,
			extensionsv1alpha1.BastionResource,
			10*time.Second,
			30*time.Second,
			5*time.Minute,
			nil,
		)).To(Succeed())

		// update the options to have the just created security group's ID
		securityGroup := getSecurityGroup(ctx, awsClient, options, options.BastionSecurityGroupName)
		options.BastionSecurityGroupID = *securityGroup.GroupId

		By("refetch bastion resource")
		Expect(c.Get(ctx, client.ObjectKey{Namespace: bastion.Namespace, Name: bastion.Name}, bastion)).To(Succeed())

		By("verify the bastion's status contains endpoints")
		Expect(bastionctrl.IngressReady(bastion.Status.Ingress)).To(BeTrue())

		By("check ports")
		err := retry(10, 6*time.Second, func() error {
			return verifyPort22IsOpen(ctx, c, bastion)
		})
		Expect(err).NotTo(HaveOccurred())
		verifyPort42IsClosed(ctx, c, bastion)

		By("verify cloud resources")
		verifyCreation(ctx, awsClient, options)
	})
})

func getImageAMI(ctx context.Context, name string, awsClient *awsclient.Client) string {
	filters := []*ec2.Filter{
		{
			Name: awssdk.String("name"),
			Values: []*string{
				awssdk.String(name),
			},
		},
		{
			Name: awssdk.String("virtualization-type"),
			Values: []*string{
				awssdk.String("hvm"),
			},
		},
		{
			Name: awssdk.String("architecture"),
			Values: []*string{
				awssdk.String("arm64"),
			},
		},
		{
			Name:   awssdk.String("is-public"),
			Values: []*string{awssdk.String("true")},
		},
		{
			Name:   awssdk.String("state"),
			Values: []*string{awssdk.String("available")},
		},
	}

	result, err := awsClient.EC2.DescribeImagesWithContext(ctx, &ec2.DescribeImagesInput{
		Filters: filters,
	})

	sort.Slice(result.Images, func(i, j int) bool {
		t1, err := time.Parse(time.RFC3339, *result.Images[i].CreationDate)
		Expect(err).NotTo(HaveOccurred())
		t2, err := time.Parse(time.RFC3339, *result.Images[j].CreationDate)
		Expect(err).NotTo(HaveOccurred())
		return t1.After(t2)
	})

	Expect(err).NotTo(HaveOccurred())
	Expect(result.Images).ToNot(BeEmpty())
	return *result.Images[0].ImageId
}

func normaliseCIDR(cidr string) string {
	_, ipnet, _ := net.ParseCIDR(cidr)
	return ipnet.String()
}

type infrastructure struct {
	VPCID                 string
	SubnetID              string
	WorkerSecurityGroupID string
}

func setupInfrastructure(ctx context.Context, log logr.Logger, awsClient *awsclient.Client, shootName string) *infrastructure {
	vpcID, igwID, err := integration.CreateVPC(ctx, log, awsClient, vpcCIDR, true, false)
	Expect(err).NotTo(HaveOccurred())
	Expect(vpcID).NotTo(BeEmpty())
	Expect(igwID).NotTo(BeEmpty())

	subnetName := fmt.Sprintf("%s-%s", shootName, publicUtilitySuffix)
	subnetID, err := integration.CreateSubnet(ctx, log, awsClient, vpcID, subnetCIDR, subnetName)
	Expect(err).NotTo(HaveOccurred())
	Expect(subnetID).NotTo(BeEmpty())

	workerSecurityGroupName := fmt.Sprintf("%s-nodes", shootName)
	workerSecurityGroupID, err := integration.CreateSecurityGroup(ctx, awsClient, workerSecurityGroupName, vpcID)
	Expect(err).NotTo(HaveOccurred())
	Expect(workerSecurityGroupID).NotTo(BeEmpty())

	// add route to internet gateway otherwise the instance won't be reachable
	err = integration.AddRoute(ctx, awsClient, vpcID, igwID, myPublicIPv4)
	Expect(err).NotTo(HaveOccurred())

	return &infrastructure{
		VPCID:                 vpcID,
		SubnetID:              subnetID,
		WorkerSecurityGroupID: workerSecurityGroupID,
	}
}

func teardownInfrastructure(ctx context.Context, awsClient *awsclient.Client, infra *infrastructure) {
	Expect(integration.DestroySubnet(ctx, log, awsClient, infra.SubnetID)).To(Succeed())
	Expect(integration.DestroySecurityGroup(ctx, log, awsClient, infra.WorkerSecurityGroupID)).To(Succeed())
	Expect(integration.DestroyVPC(ctx, log, awsClient, infra.VPCID)).To(Succeed())
}

func setupShootEnvironment(ctx context.Context, c client.Client, namespace *corev1.Namespace, cluster *extensionsv1alpha1.Cluster) {
	Expect(c.Create(ctx, namespace)).To(Succeed())
	Expect(c.Create(ctx, cluster)).To(Succeed())

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      v1beta1constants.SecretNameCloudProvider,
			Namespace: namespace.Name,
		},
		Data: map[string][]byte{
			aws.AccessKeyID:     []byte(*accessKeyID),
			aws.SecretAccessKey: []byte(*secretAccessKey),
		},
	}
	Expect(c.Create(ctx, secret)).To(Succeed())
}

func teardownShootEnvironment(ctx context.Context, c client.Client, namespace *corev1.Namespace, cluster *extensionsv1alpha1.Cluster) {
	Expect(client.IgnoreNotFound(c.Delete(ctx, namespace))).To(Succeed())
	Expect(client.IgnoreNotFound(c.Delete(ctx, cluster))).To(Succeed())
}

func setupBastion(ctx context.Context, awsClient *awsclient.Client, c client.Client, name string, cluster *controller.Cluster) (*extensionsv1alpha1.Bastion, *bastionctrl.Options) {
	bastion, err := newBastion(name)
	Expect(err).NotTo(HaveOccurred())

	options, err := bastionctrl.DetermineOptions(ctx, bastion, cluster, awsClient)
	Expect(err).NotTo(HaveOccurred())

	Expect(c.Create(ctx, bastion)).To(Succeed())

	return bastion, options
}

func teardownBastion(ctx context.Context, log logr.Logger, c client.Client, bastion *extensionsv1alpha1.Bastion) {
	By("delete bastion")
	Expect(client.IgnoreNotFound(c.Delete(ctx, bastion))).To(Succeed())

	By("wait until bastion is deleted")
	err := extensions.WaitUntilExtensionObjectDeleted(
		ctx,
		c,
		log,
		bastion,
		extensionsv1alpha1.BastionResource,
		10*time.Second,
		16*time.Minute,
	)
	Expect(err).NotTo(HaveOccurred())
}

func newCluster(name string, amiID string) (*extensionsv1alpha1.Cluster, *controller.Cluster) {
	providerConfig := &awsv1alpha1.CloudProfileConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "aws.provider.extensions.gardener.cloud/v1alpha1",
			Kind:       "CloudProfileConfig",
		},
		MachineImages: []awsv1alpha1.MachineImages{
			{
				Name: "gardenlinux",
				Versions: []awsv1alpha1.MachineImageVersion{
					{
						Version: imageVersion,
						Regions: []awsv1alpha1.RegionAMIMapping{
							{
								Name:         *region,
								AMI:          amiID,
								Architecture: ptr.To("arm64"),
							},
						},
					},
				},
			},
		},
	}

	providerConfigJSON, err := json.Marshal(providerConfig)
	Expect(err).NotTo(HaveOccurred())

	cloudProfile := &gardencorev1beta1.CloudProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core.gardener.cloud/v1beta1",
			Kind:       "CloudProfile",
		},
		Spec: gardencorev1beta1.CloudProfileSpec{
			Bastion: &gardencorev1beta1.Bastion{
				MachineImage: &gardencorev1beta1.BastionMachineImage{
					Name: "gardenlinux",
				},
			},
			MachineImages: []gardencorev1beta1.MachineImage{
				{
					Name: "gardenlinux",
					Versions: []gardencorev1beta1.MachineImageVersion{
						{
							ExpirableVersion: gardencorev1beta1.ExpirableVersion{
								Version:        imageVersion,
								Classification: ptr.To(gardencorev1beta1.ClassificationSupported),
							},
							Architectures: []string{"arm64"},
						},
					},
				},
			},
			MachineTypes: []gardencorev1beta1.MachineType{{
				CPU:          resource.MustParse("4"),
				Memory:       resource.MustParse("4"),
				Name:         "t4g.nano",
				Architecture: ptr.To("arm64"),
			}},
			ProviderConfig: &runtime.RawExtension{
				Raw:    providerConfigJSON,
				Object: providerConfig,
			},
		},
	}

	shoot := &gardencorev1beta1.Shoot{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core.gardener.cloud/v1beta1",
			Kind:       "Shoot",
		},
		Spec: gardencorev1beta1.ShootSpec{
			Region: *region,
		},
	}

	cloudProfileJSON, err := json.Marshal(cloudProfile)
	Expect(err).NotTo(HaveOccurred())
	shootJSON, err := json.Marshal(shoot)
	Expect(err).NotTo(HaveOccurred())

	extensionscluster := &extensionsv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: extensionsv1alpha1.ClusterSpec{
			CloudProfile: runtime.RawExtension{
				Object: cloudProfile,
				Raw:    cloudProfileJSON,
			},
			Seed: runtime.RawExtension{
				Raw: []byte("{}"),
			},
			Shoot: runtime.RawExtension{
				Object: shoot,
				Raw:    shootJSON,
			},
		},
	}

	corecluster := &controller.Cluster{
		ObjectMeta:   metav1.ObjectMeta{Name: name},
		CloudProfile: cloudProfile,
		Shoot:        shoot,
	}

	return extensionscluster, corecluster
}

func newBastion(namespace string) (*extensionsv1alpha1.Bastion, error) {
	randString, err := randomString()
	Expect(err).NotTo(HaveOccurred())

	return &extensionsv1alpha1.Bastion{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("bastion-%s", randString),
			Namespace: namespace,
		},
		Spec: extensionsv1alpha1.BastionSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type: aws.Type,
			},
			UserData: []byte("#!/bin/bash\n\nsystemctl start ssh"),
			Ingress: []extensionsv1alpha1.BastionIngressPolicy{{
				IPBlock: networkingv1.IPBlock{
					CIDR: myPublicIPv4,
				},
			}, {
				IPBlock: networkingv1.IPBlock{
					CIDR: mockCidrv6,
				},
			}},
		},
	}, nil
}

func randomString() (string, error) {
	suffix, err := gardenerutils.GenerateRandomStringFromCharset(5, "0123456789abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		return "", err
	}

	return suffix, nil
}

func getSecurityGroup(ctx context.Context, awsClient *awsclient.Client, options *bastionctrl.Options, groupName string) *ec2.SecurityGroup {
	output, err := awsClient.EC2.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   awssdk.String("vpc-id"),
				Values: []*string{awssdk.String(options.VPCID)},
			},
			{
				Name:   awssdk.String("group-name"),
				Values: []*string{awssdk.String(groupName)},
			},
		},
	})

	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, output.SecurityGroups).To(HaveLen(1))

	return output.SecurityGroups[0]
}

func verifyCreation(
	ctx context.Context,
	awsClient *awsclient.Client,
	options *bastionctrl.Options,
) {
	accountID, err := awsClient.GetAccountID(ctx)
	Expect(err).NotTo(HaveOccurred())

	// bastion security group
	securityGroup := getSecurityGroup(ctx, awsClient, options, options.BastionSecurityGroupName)
	Expect(securityGroup.GroupId).To(PointTo(Equal(options.BastionSecurityGroupID)))

	// ingress permissions
	Expect(securityGroup.IpPermissions).To(HaveLen(1))
	Expect(securityGroup.IpPermissions).To(ConsistOf(&ec2.IpPermission{
		FromPort:   awssdk.Int64(bastionctrl.SSHPort),
		ToPort:     awssdk.Int64(bastionctrl.SSHPort),
		IpProtocol: awssdk.String("tcp"),
		IpRanges: []*ec2.IpRange{{
			CidrIp: awssdk.String(normaliseCIDR(myPublicIPv4)),
		}},
		Ipv6Ranges: []*ec2.Ipv6Range{{
			CidrIpv6: awssdk.String(normaliseCIDR(mockCidrv6)),
		}},
	}))

	// egress permissions
	Expect(securityGroup.IpPermissionsEgress).To(HaveLen(1))
	Expect(securityGroup.IpPermissionsEgress).To(ConsistOf(&ec2.IpPermission{
		FromPort:   awssdk.Int64(bastionctrl.SSHPort),
		ToPort:     awssdk.Int64(bastionctrl.SSHPort),
		IpProtocol: awssdk.String("tcp"),
		UserIdGroupPairs: []*ec2.UserIdGroupPair{{
			UserId:  awssdk.String(accountID),
			GroupId: awssdk.String(options.WorkerSecurityGroupID),
		}},
	}))

	// worker security group
	securityGroup = getSecurityGroup(ctx, awsClient, options, options.WorkerSecurityGroupName)
	Expect(securityGroup.GroupId).To(PointTo(Equal(options.WorkerSecurityGroupID)))
	Expect(securityGroup.IpPermissions).NotTo(BeEmpty())
	Expect(securityGroup.IpPermissions).To(ContainElement(&ec2.IpPermission{
		FromPort:   awssdk.Int64(bastionctrl.SSHPort),
		ToPort:     awssdk.Int64(bastionctrl.SSHPort),
		IpProtocol: awssdk.String("tcp"),
		UserIdGroupPairs: []*ec2.UserIdGroupPair{{
			UserId:  awssdk.String(accountID),
			GroupId: awssdk.String(options.BastionSecurityGroupID),
		}},
	}))

	// bastion instance
	instances, err := awsClient.EC2.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   awssdk.String("tag:Name"),
				Values: []*string{awssdk.String(options.InstanceName)},
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(instances.Reservations).To(HaveLen(1))
	Expect(instances.Reservations[0].Instances).To(HaveLen(1))
	instance := instances.Reservations[0].Instances[0]
	Expect(instance.ImageId).To(PointTo(Equal(options.ImageID)))
	Expect(instance.InstanceType).To(PointTo(Equal(options.InstanceType)))
	Expect(instance.PublicIpAddress).ToNot(BeNil())
	Expect(instance.PublicDnsName).ToNot(BeNil())
}

func verifyDeletion(
	ctx context.Context,
	awsClient *awsclient.Client,
	options *bastionctrl.Options,
) {
	// bastion security group should be gone
	output, err := awsClient.EC2.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   awssdk.String("vpc-id"),
				Values: []*string{awssdk.String(options.VPCID)},
			},
			{
				Name:   awssdk.String("group-name"),
				Values: []*string{awssdk.String(options.BastionSecurityGroupName)},
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(output.SecurityGroups).To(BeEmpty())

	// worker security group should not have SSH approval anymore
	securityGroup := getSecurityGroup(ctx, awsClient, options, options.WorkerSecurityGroupName)
	Expect(securityGroup.GroupId).To(PointTo(Equal(options.WorkerSecurityGroupID)))
	Expect(securityGroup.IpPermissions).To(BeEmpty())

	// instance should be terminated
	instances, err := awsClient.EC2.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   awssdk.String("tag:Name"),
				Values: []*string{awssdk.String(options.InstanceName)},
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(instances.Reservations).To(HaveLen(1))
	Expect(instances.Reservations[0].Instances).To(HaveLen(1))
	Expect(instances.Reservations[0].Instances[0].State.Code).To(PointTo(Equal(int64(bastionctrl.InstanceStateTerminated))))
}

func getMyPublicIPWithMask() (string, error) {
	ipV4Resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}

	myIpV4, err := ipFromReader(ipV4Resp.Body)
	if err != nil {
		return "", err
	}

	return myIpV4, nil
}

func ipFromReader(reader io.ReadCloser) (string, error) {
	defer func() {
		err := reader.Close()
		if err != nil {
			Expect(err).NotTo(HaveOccurred())
		}
	}()

	body, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}

	ip := net.ParseIP(string(body))
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(24, 32) // use a /24 net for IPv4
	} else if ip.To16() != nil {
		mask = net.CIDRMask(64, 128) // IPv6 /64 mask
	} else {
		return "", fmt.Errorf("not a valid IP address")
	}

	cidr := net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	full := cidr.String()

	_, ipNet, _ := net.ParseCIDR(full)
	return ipNet.String(), nil
}

func verifyPort22IsOpen(ctx context.Context, c client.Client, bastion *extensionsv1alpha1.Bastion) error {
	By("check connection to port 22 open should not error")
	bastionUpdated := &extensionsv1alpha1.Bastion{}
	Expect(c.Get(ctx, client.ObjectKey{Namespace: bastion.Namespace, Name: bastion.Name}, bastionUpdated)).To(Succeed())

	ipAddress := bastionUpdated.Status.Ingress.IP
	address := net.JoinHostPort(ipAddress, "22")
	conn, err := net.DialTimeout("tcp4", address, 10*time.Second)
	if err != nil {
		return err
	}
	if conn == nil {
		return fmt.Errorf("connection should not be nil")
	}
	return nil
}

func verifyPort42IsClosed(ctx context.Context, c client.Client, bastion *extensionsv1alpha1.Bastion) {
	By("check connection to port 42 which should fail")
	bastionUpdated := &extensionsv1alpha1.Bastion{}
	Expect(c.Get(ctx, client.ObjectKey{Namespace: bastion.Namespace, Name: bastion.Name}, bastionUpdated)).To(Succeed())

	ipAddress := bastionUpdated.Status.Ingress.IP
	address := net.JoinHostPort(ipAddress, "42")
	conn, err := net.DialTimeout("tcp4", address, 3*time.Second)
	Expect(err).Should(HaveOccurred())
	Expect(conn).To(BeNil())
}

// retry performs a function with retries, delay, and a max number of attempts
func retry(maxRetries int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		log.Info(fmt.Sprintf("Attempt %d failed, retrying in %v: %v", i+1, delay, err))
		time.Sleep(delay)
	}
	return err
}
