// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	reconcilerutils "github.com/gardener/gardener/pkg/controllerutils/reconciler"
	"github.com/go-logr/logr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

func (a *actuator) Delete(ctx context.Context, log logr.Logger, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	awsClient, err := a.getAWSClient(ctx, bastion, cluster.Shoot)
	if err != nil {
		return util.DetermineError(fmt.Errorf("failed to create AWS client: %w", err), helper.KnownCodes)
	}

	opt, err := DetermineOptions(ctx, bastion, cluster, awsClient)
	if err != nil {
		return util.DetermineError(fmt.Errorf("failed to setup AWS client options: %w", err), helper.KnownCodes)
	}

	// resolve security group name to its ID
	group, err := getSecurityGroup(ctx, awsClient, opt.VPCID, opt.BastionSecurityGroupName)
	if err != nil {
		return util.DetermineError(fmt.Errorf("failed to list security groups: %w", err), helper.KnownCodes)
	}

	// if the security group still exists, remove it from the worker's security group
	if group != nil {
		opt.BastionSecurityGroupID = *group.GroupId

		if err := removeWorkerPermissions(ctx, log, awsClient, opt); err != nil {
			return util.DetermineError(fmt.Errorf("failed to remove bastion host from worker security group: %w", err), helper.KnownCodes)
		}
	}

	if err := removeBastionInstance(ctx, log, awsClient, opt); err != nil {
		return util.DetermineError(fmt.Errorf("failed to remove bastion instance: %w", err), helper.KnownCodes)
	}

	terminated, err := instanceIsTerminated(ctx, awsClient, opt)
	if err != nil {
		return util.DetermineError(fmt.Errorf("failed to check for bastion instance: %w", err), helper.KnownCodes)
	}

	if !terminated {
		return &reconcilerutils.RequeueAfterError{
			RequeueAfter: 10 * time.Second,
			Cause:        fmt.Errorf("bastion instance is still terminating"),
		}
	}

	if err := removeSecurityGroup(ctx, log, awsClient, opt); err != nil {
		return util.DetermineError(fmt.Errorf("failed to remove security group: %w", err), helper.KnownCodes)
	}

	return nil
}

func (a *actuator) ForceDelete(_ context.Context, _ logr.Logger, _ *extensionsv1alpha1.Bastion, _ *controller.Cluster) error {
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
