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
	"time"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	reconcilerutils "github.com/gardener/gardener/pkg/controllerutils/reconciler"
	"github.com/go-logr/logr"
)

func (a *actuator) Delete(ctx context.Context, log logr.Logger, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	awsClient, err := a.getAWSClient(ctx, bastion, cluster.Shoot)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to create AWS client: %w", err))
	}

	opt, err := DetermineOptions(ctx, bastion, cluster, awsClient)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to setup AWS client options: %w", err))
	}

	// resolve security group name to its ID
	group, err := getSecurityGroup(ctx, awsClient, opt.VPCID, opt.BastionSecurityGroupName)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to list security groups: %w", err))
	}

	// if the security group still exists, remove it from the worker's security group
	if group != nil {
		opt.BastionSecurityGroupID = *group.GroupId

		if err := removeWorkerPermissions(ctx, log, awsClient, opt); err != nil {
			return helper.DetermineError(fmt.Errorf("failed to remove bastion host from worker security group: %w", err))
		}
	}

	if err := removeBastionInstance(ctx, log, awsClient, opt); err != nil {
		return helper.DetermineError(fmt.Errorf("failed to remove bastion instance: %w", err))
	}

	terminated, err := instanceIsTerminated(ctx, awsClient, opt)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to check for bastion instance: %w", err))
	}

	if !terminated {
		return &reconcilerutils.RequeueAfterError{
			RequeueAfter: 10 * time.Second,
			Cause:        fmt.Errorf("bastion instance is still terminating"),
		}
	}

	if err := removeSecurityGroup(ctx, log, awsClient, opt); err != nil {
		return helper.DetermineError(fmt.Errorf("failed to remove security group: %w", err))
	}

	return nil
}

func removeWorkerPermissions(ctx context.Context, logger logr.Logger, awsClient *awsclient.Client, opt *Options) error {
	workerSecurityGroup, err := getSecurityGroup(ctx, awsClient, opt.VPCID, opt.WorkerSecurityGroupName)
	if err != nil {
		return fmt.Errorf("failed to fetch worker security group: %w", err)
	}

	// if for some reason the worker's SG is already gone, that's fine, no need to cleanup any further
	if workerSecurityGroup == nil {
		return nil
	}

	permission := workerSecurityGroupPermission(opt)

	if securityGroupHasPermissions(workerSecurityGroup.IpPermissions, permission) {
		logger.Info("Removing SSH ingress from worker nodes")

		_, err = awsClient.EC2.RevokeSecurityGroupIngressWithContext(ctx, &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(opt.WorkerSecurityGroupID),
			IpPermissions: []*ec2.IpPermission{permission},
		})
	}

	return err
}

// instanceIsTerminated returns true if a machine is in Terminated state.
func instanceIsTerminated(ctx context.Context, awsClient *awsclient.Client, opt *Options) (bool, error) {
	instances, err := awsClient.EC2.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []*string{aws.String(opt.InstanceName)},
			},
		},
	})
	if err != nil {
		return false, err
	}

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			if *instance.State.Code != InstanceStateTerminated {
				return false, nil
			}
		}
	}

	return true, nil
}

func removeBastionInstance(ctx context.Context, logger logr.Logger, awsClient *awsclient.Client, opt *Options) error {
	instance, err := getFirstMatchingInstance(ctx, awsClient, []*ec2.Filter{
		{
			Name:   aws.String("tag:Name"),
			Values: []*string{aws.String(opt.InstanceName)},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to list instances: %w", err)
	}

	// nothing to do
	if instance == nil {
		return nil
	}

	logger.Info("Terminating bastion instance")

	_, err = awsClient.EC2.TerminateInstancesWithContext(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: aws.StringSlice([]string{*instance.InstanceId}),
	})
	if err != nil {
		return fmt.Errorf("failed to terminate instance: %w", err)
	}

	return nil
}

func removeSecurityGroup(ctx context.Context, logger logr.Logger, awsClient *awsclient.Client, opt *Options) error {
	group, err := getSecurityGroup(ctx, awsClient, opt.VPCID, opt.BastionSecurityGroupName)
	if err != nil {
		return fmt.Errorf("failed to list security groups: %w", err)
	}

	// nothing to do
	if group == nil {
		return nil
	}

	logger.Info("Removing security group")

	_, err = awsClient.EC2.DeleteSecurityGroupWithContext(ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: group.GroupId,
	})
	if err != nil {
		return fmt.Errorf("failed to remove security group: %w", err)
	}

	return nil
}
