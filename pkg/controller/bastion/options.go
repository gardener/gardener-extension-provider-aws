// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion

import (
	"context"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/extensions"

	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// Options contains provider-related information required for setting up
// a bastion instance. This struct combines precomputed values like the
// bastion instance name with the IDs of pre-existing cloud provider
// resources, like the VPC ID, subnet ID etc.
type Options struct {
	Shoot                    *gardencorev1beta1.Shoot
	SubnetID                 string
	VPCID                    string
	BastionSecurityGroupName string
	WorkerSecurityGroupName  string
	WorkerSecurityGroupID    string
	InstanceName             string
	InstanceType             string
	ImageID                  string

	// set later during reconciling phase
	BastionSecurityGroupID string
}

// DetermineOptions determines the required information like VPC ID and
// instance type that are required to reconcile a Bastion on AWS. This
// function does not create any IaaS resources.
func DetermineOptions(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster, awsClient *awsclient.Client) (*Options, error) {
	name := cluster.ObjectMeta.Name
	region := cluster.Shoot.Spec.Region
	subnetName := name + "-public-utility-z0"
	instanceName := fmt.Sprintf("%s-%s-bastion", name, bastion.Name)

	// this security group will be created during reconciliation
	bastionSecurityGroupName := fmt.Sprintf("%s-%s-bsg", name, bastion.Name)

	subnetID, vpcID, err := resolveSubnetName(ctx, awsClient, subnetName)
	if err != nil {
		return nil, fmt.Errorf("failed to find subnet %q: %w", subnetName, err)
	}

	// this security group exists already and just needs to be resolved to its ID
	workerSecurityGroupName := name + "-nodes"
	workerSecurityGroup, err := getSecurityGroup(ctx, awsClient, vpcID, workerSecurityGroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to check for worker security group: %w", err)
	}
	if workerSecurityGroup == nil {
		return nil, fmt.Errorf("security group for worker node does not exist yet")
	}

	vmDetails, err := DetermineVmDetails(cluster.CloudProfile.Spec)
	if err != nil {
		return nil, fmt.Errorf("failed to determine VM details for bastion host: %w", err)
	}

	cloudProfileConfig, err := getCloudProfileConfig(cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to extract cloud provider config from cluster: %w", err)
	}

	machineImageVersion, err := getProviderSpecificImage(cloudProfileConfig.MachineImages, vmDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to extract image from provider config: %w", err)
	}

	ami, err := findImageAMIByRegion(machineImageVersion, vmDetails, region)
	if err != nil {
		return nil, fmt.Errorf("failed to find image AMI by region: %w", err)
	}

	return &Options{
		Shoot:                    cluster.Shoot,
		SubnetID:                 subnetID,
		VPCID:                    vpcID,
		BastionSecurityGroupName: bastionSecurityGroupName,
		WorkerSecurityGroupName:  workerSecurityGroupName,
		WorkerSecurityGroupID:    *workerSecurityGroup.GroupId,
		InstanceName:             instanceName,
		InstanceType:             vmDetails.MachineName,
		ImageID:                  ami,
	}, nil
}

// resolveSubnetName resolves a subnet name to its ID and the VPC ID. If no subnet with the
// given name exists, an error is returned.
func resolveSubnetName(ctx context.Context, awsClient *awsclient.Client, subnetName string) (subnetID string, vpcID string, err error) {
	subnets, err := awsClient.EC2.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: aws.StringSlice([]string{subnetName}),
			},
		},
	})
	if err != nil {
		return
	}

	if len(subnets.Subnets) == 0 {
		err = fmt.Errorf("subnet not found")
		return
	}

	subnetID = *subnets.Subnets[0].SubnetId
	vpcID = *subnets.Subnets[0].VpcId

	return
}

func getCloudProfileConfig(cluster *extensions.Cluster) (*awsv1alpha1.CloudProfileConfig, error) {
	if cluster.CloudProfile.Spec.ProviderConfig.Raw == nil {
		return nil, fmt.Errorf("no cloud provider config set in cluster's CloudProfile")
	}

	var (
		cloudProfileConfig = &awsv1alpha1.CloudProfileConfig{}
		decoder            = kubernetes.GardenCodec.UniversalDeserializer()
	)

	if _, _, err := decoder.Decode(cluster.CloudProfile.Spec.ProviderConfig.Raw, nil, cloudProfileConfig); err != nil {
		return nil, err
	}

	return cloudProfileConfig, nil
}

// getProviderSpecificImage returns the provider specific MachineImageVersion that matches with the given VmDetails
func getProviderSpecificImage(images []awsv1alpha1.MachineImages, vm VmDetails) (awsv1alpha1.MachineImageVersion, error) {
	imageIndex := slices.IndexFunc(images, func(image awsv1alpha1.MachineImages) bool {
		return image.Name == vm.ImageBaseName
	})

	if imageIndex == -1 {
		return awsv1alpha1.MachineImageVersion{},
			fmt.Errorf("machine image with name %s not found in cloudProfileConfig", vm.ImageBaseName)
	}

	versions := images[imageIndex].Versions
	versionIndex := slices.IndexFunc(versions, func(version awsv1alpha1.MachineImageVersion) bool {
		return version.Version == vm.ImageVersion
	})

	if versionIndex == -1 {
		return awsv1alpha1.MachineImageVersion{},
			fmt.Errorf("version %s for arch %s of image %s not found in cloudProfileConfig",
				vm.ImageVersion, vm.Architecture, vm.ImageBaseName)
	}

	return versions[versionIndex], nil
}

func findImageAMIByRegion(image awsv1alpha1.MachineImageVersion, vmDetails VmDetails, region string) (string, error) {
	regionIndex := slices.IndexFunc(image.Regions, func(RegionAMIMapping awsv1alpha1.RegionAMIMapping) bool {
		return RegionAMIMapping.Name == region && RegionAMIMapping.Architecture != nil && *RegionAMIMapping.Architecture == vmDetails.Architecture
	})

	if regionIndex == -1 {
		return "", fmt.Errorf("image '%s' with version '%s' and architecture '%s' not found in region '%s'",
			vmDetails.ImageBaseName, image.Version, vmDetails.Architecture, region)
	}

	return image.Regions[regionIndex].AMI, nil
}
