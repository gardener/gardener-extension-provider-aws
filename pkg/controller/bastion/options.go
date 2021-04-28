// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package bastion

import (
	"context"
	"fmt"
	"strings"

	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/pkg/errors"
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
	subnetName := name + "-public-utility-z0"
	instanceName := fmt.Sprintf("%s-%s-bastion", name, bastion.Name)

	// this security group will be created during reconciliation
	bastionSecurityGroupName := fmt.Sprintf("%s-%s-bsg", name, bastion.Name)

	subnetID, vpcID, err := resolveSubnetName(ctx, awsClient, subnetName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find subnet %q", subnetName)
	}

	// this security group exists already and just needs to be resolved to its ID
	workerSecurityGroupName := name + "-nodes"
	workerSecurityGroup, err := getSecurityGroup(ctx, awsClient, vpcID, workerSecurityGroupName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check for worker security group")
	}
	if workerSecurityGroup == nil {
		return nil, errors.New("security group for worker node does not exist yet")
	}

	cloudProfileConfig, err := getCloudProfileConfig(cluster)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract cloud provider config from cluster")
	}

	imageID, err := determineImageID(cluster.Shoot, cloudProfileConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to determine OS image for bastion host")
	}

	instanceType, err := determineInstanceType(ctx, awsClient)
	if err != nil {
		return nil, errors.Wrap(err, "failed to determine instance type")
	}

	return &Options{
		Shoot:                    cluster.Shoot,
		SubnetID:                 subnetID,
		VPCID:                    vpcID,
		BastionSecurityGroupName: bastionSecurityGroupName,
		WorkerSecurityGroupName:  workerSecurityGroupName,
		WorkerSecurityGroupID:    *workerSecurityGroup.GroupId,
		InstanceName:             instanceName,
		InstanceType:             instanceType,
		ImageID:                  imageID,
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
		err = errors.New("subnet not found")
		return
	}

	subnetID = *subnets.Subnets[0].SubnetId
	vpcID = *subnets.Subnets[0].VpcId

	return
}

func getCloudProfileConfig(cluster *extensions.Cluster) (*awsv1alpha1.CloudProfileConfig, error) {
	if cluster.CloudProfile.Spec.ProviderConfig.Raw == nil {
		return nil, errors.New("no cloud provider config set in cluster's CloudProfile")
	}

	var (
		cloudProfileConfig = &awsv1alpha1.CloudProfileConfig{}
		decoder            = extensions.NewGardenDecoder()
	)

	if _, _, err := decoder.Decode(cluster.CloudProfile.Spec.ProviderConfig.Raw, nil, cloudProfileConfig); err != nil {
		return nil, err
	}

	return cloudProfileConfig, nil
}

// determineImageID finds the first AMI that is configured for the same region as the shoot cluster.
// If no image is found, an error is returned.
func determineImageID(shoot *gardencorev1beta1.Shoot, providerConfig *awsv1alpha1.CloudProfileConfig) (string, error) {
	for _, image := range providerConfig.MachineImages {
		for _, version := range image.Versions {
			for _, region := range version.Regions {
				if region.Name == shoot.Spec.Region {
					return region.AMI, nil
				}
			}
		}
	}

	return "", fmt.Errorf("found no suitable AMI for machines in region %q", shoot.Spec.Region)
}

func determineInstanceType(ctx context.Context, awsClient *awsclient.Client) (string, error) {
	offerings, err := awsClient.EC2.DescribeInstanceTypeOfferingsWithContext(ctx, &ec2.DescribeInstanceTypeOfferingsInput{})
	if err != nil {
		return "", errors.Wrap(err, "failed to list instance types")
	}

	types := make([]string, len(offerings.InstanceTypeOfferings))
	for i, offering := range offerings.InstanceTypeOfferings {
		types[i] = *offering.InstanceType
	}

	// prefer t2.nano
	for _, t := range types {
		if t == "t2.nano" {
			return t, nil
		}
	}

	// fallback to the first (hopefully smallest) other general purpose instance type
	for _, t := range types {
		if strings.HasPrefix(t, "t") {
			return t, nil
		}
	}

	return "", errors.New("no t.* instance type available")
}
