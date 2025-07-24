// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion

import (
	"context"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	extensionsbastion "github.com/gardener/gardener/extensions/pkg/bastion"
	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// BaseOptions contain the information needed for deleting a Bastion on AWS.
type BaseOptions struct {
	InstanceName             string
	BastionSecurityGroupName string
	WorkerSecurityGroupName  string
	WorkerSecurityGroupID    string
	VpcID                    string
	SubnetID                 string
	BastionSecurityGroupID   string
}

// Options contains provider-related information required for setting up
// a bastion instance. This struct combines precomputed values like the
// bastion instance name with the IDs of pre-existing cloud provider
// resources, like the VPC ID, subnet ID etc.
type Options struct {
	Shoot        *gardencorev1beta1.Shoot
	InstanceType string
	ImageID      string
	IPv6         bool
	// needed for creation and deletion
	BaseOptions
}

// NewBaseOpts determines base opts that are required for creating and deleting a Bastion on AWS.
func NewBaseOpts(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster, awsClient *awsclient.Client) (BaseOptions, error) {
	name := cluster.ObjectMeta.Name
	subnetName := name + "-public-utility-z0"
	instanceName := fmt.Sprintf("%s-%s-bastion", name, bastion.Name)

	// this security group will be created during reconciliation
	bastionSecurityGroupName := fmt.Sprintf("%s-%s-bsg", name, bastion.Name)

	subnetID, vpcID, err := resolveSubnetName(ctx, awsClient, subnetName)
	if err != nil {
		return BaseOptions{}, fmt.Errorf("failed to find subnet %q: %w", subnetName, err)
	}

	// this security group exists already and just needs to be resolved to its ID
	workerSecurityGroupName := name + "-nodes"
	workerSecurityGroup, err := getSecurityGroup(ctx, awsClient, vpcID, workerSecurityGroupName)
	if err != nil {
		return BaseOptions{}, fmt.Errorf("failed to check for worker security group: %w", err)
	}
	if workerSecurityGroup == nil || workerSecurityGroup.GroupId == nil {
		return BaseOptions{}, fmt.Errorf("worker security group %q not found in VPC %q", workerSecurityGroupName, vpcID)
	}

	return BaseOptions{
		SubnetID:                 subnetID,
		VpcID:                    vpcID,
		BastionSecurityGroupName: bastionSecurityGroupName,
		WorkerSecurityGroupName:  workerSecurityGroupName,
		WorkerSecurityGroupID:    *workerSecurityGroup.GroupId,
		InstanceName:             instanceName,
	}, nil
}

// NewOpts determines the information that is required to reconcile a Bastion.
func NewOpts(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster, awsClient *awsclient.Client) (Options, error) {
	baseOpts, err := NewBaseOpts(ctx, bastion, cluster, awsClient)
	if err != nil {
		return Options{}, err
	}

	region := cluster.Shoot.Spec.Region

	vmDetails, err := extensionsbastion.GetMachineSpecFromCloudProfile(cluster.CloudProfile)
	if err != nil {
		return Options{}, fmt.Errorf("failed to determine VM details for bastion host: %w", err)
	}

	cloudProfileConfig, err := helper.CloudProfileConfigFromCluster(cluster)
	if err != nil {
		return Options{}, fmt.Errorf("failed to extract cloud provider config from cluster: %w", err)
	}

	machineImageVersion, err := getProviderSpecificImage(cloudProfileConfig.MachineImages, vmDetails)
	if err != nil {
		return Options{}, fmt.Errorf("failed to extract image from provider config: %w", err)
	}

	ami, err := findImageAMIByRegion(machineImageVersion, vmDetails, region)
	if err != nil {
		return Options{}, fmt.Errorf("failed to find image AMI by region: %w", err)
	}

	ipV6 := cluster.Shoot.Spec.Networking != nil && slices.Contains(cluster.Shoot.Spec.Networking.IPFamilies, gardencorev1beta1.IPFamilyIPv6)

	return Options{
		Shoot:        cluster.Shoot,
		InstanceType: vmDetails.MachineTypeName,
		ImageID:      ami,
		IPv6:         ipV6,
		BaseOptions:  baseOpts,
	}, nil
}

// resolveSubnetName resolves a subnet name to its ID and the VPC ID. If no subnet with the
// given name exists, an error is returned.
func resolveSubnetName(ctx context.Context, awsClient *awsclient.Client, subnetName string) (subnetID string, vpcID string, err error) {
	subnets, err := awsClient.EC2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []string{subnetName},
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

// getProviderSpecificImage returns the provider specific MachineImageVersion that matches with the given VmDetails
func getProviderSpecificImage(images []api.MachineImages, vm extensionsbastion.MachineSpec) (api.MachineImageVersion, error) {
	imageIndex := slices.IndexFunc(images, func(image api.MachineImages) bool {
		return image.Name == vm.ImageBaseName
	})

	if imageIndex == -1 {
		return api.MachineImageVersion{},
			fmt.Errorf("machine image with name %s not found in cloudProfileConfig", vm.ImageBaseName)
	}

	versions := images[imageIndex].Versions
	versionIndex := slices.IndexFunc(versions, func(version api.MachineImageVersion) bool {
		return version.Version == vm.ImageVersion
	})

	if versionIndex == -1 {
		return api.MachineImageVersion{},
			fmt.Errorf("version %s for arch %s of image %s not found in cloudProfileConfig",
				vm.ImageVersion, vm.Architecture, vm.ImageBaseName)
	}

	return versions[versionIndex], nil
}

func findImageAMIByRegion(image api.MachineImageVersion, vmDetails extensionsbastion.MachineSpec, region string) (string, error) {
	regionIndex := slices.IndexFunc(image.Regions, func(RegionAMIMapping api.RegionAMIMapping) bool {
		return RegionAMIMapping.Name == region && RegionAMIMapping.Architecture != nil && *RegionAMIMapping.Architecture == vmDetails.Architecture
	})

	if regionIndex == -1 {
		return "", fmt.Errorf("image '%s' with version '%s' and architecture '%s' not found in region '%s'",
			vmDetails.ImageBaseName, image.Version, vmDetails.Architecture, region)
	}

	return image.Regions[regionIndex].AMI, nil
}
