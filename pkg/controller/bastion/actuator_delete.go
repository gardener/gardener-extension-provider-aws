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
	"time"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/extensions/pkg/controller"
	ctrlerror "github.com/gardener/gardener/extensions/pkg/controller/error"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Delete(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	logger := a.logger.WithValues("bastion", client.ObjectKeyFromObject(bastion), "operation", "delete")

	awsClient, err := a.getAWSClient(ctx, bastion, cluster.Shoot)
	if err != nil {
		return errors.Wrap(err, "failed to create AWS client")
	}

	opt, err := determineOptions(ctx, bastion, cluster, awsClient)
	if err != nil {
		return errors.Wrap(err, "failed to setup AWS client options")
	}

	// resolve security group name to its ID
	group, err := getSecurityGroup(ctx, awsClient, opt.vpcID, opt.bastionSecurityGroupName)
	if err != nil {
		return errors.Wrap(err, "failed to list security groups")
	}

	// if the security group doesn't exist anymore, everything else must also be gone already
	if group == nil {
		return nil
	}

	opt.bastionSecurityGroupID = *group.GroupId

	if err := removeWorkerPermissions(ctx, logger, awsClient, opt); err != nil {
		return errors.Wrap(err, "failed to remove bastion host from worker security group")
	}

	if err := removeBastionInstance(ctx, logger, awsClient, opt); err != nil {
		return errors.Wrap(err, "failed to remove bastion instance")
	}

	terminated, err := instanceIsTerminated(ctx, awsClient, opt)
	if err != nil {
		return errors.Wrap(err, "failed to check for bastion instance")
	}

	if !terminated {
		return &ctrlerror.RequeueAfterError{
			RequeueAfter: 10 * time.Second,
			Cause:        errors.New("bastion instance is still terminating"),
		}
	}

	if err := removeSecurityGroup(ctx, logger, awsClient, opt); err != nil {
		return errors.Wrap(err, "failed to remove security group")
	}

	return nil
}

func removeWorkerPermissions(ctx context.Context, logger logr.Logger, awsClient *awsclient.Client, opt *options) error {
	workerSecurityGroup, err := getSecurityGroup(ctx, awsClient, opt.vpcID, opt.workerSecurityGroupName)
	if err != nil {
		return errors.Wrap(err, "failed to fetch worker security group")
	}

	// if for some reason the worker's SG is already gone, that's fine, no need to cleanup any further
	if workerSecurityGroup == nil {
		return nil
	}

	permission := workerSecurityGroupPermission(opt)

	if securityGroupHasPermissions(workerSecurityGroup.IpPermissions, permission) {
		logger.Info("Removing SSH ingress from worker nodes")

		_, err = awsClient.EC2.RevokeSecurityGroupIngressWithContext(ctx, &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(opt.workerSecurityGroupID),
			IpPermissions: []*ec2.IpPermission{permission},
		})
	}

	return err
}

// instanceIsTerminated returns true if a machine is in Terminated state.
func instanceIsTerminated(ctx context.Context, awsClient *awsclient.Client, opt *options) (bool, error) {
	instances, err := awsClient.EC2.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []*string{aws.String(opt.instanceName)},
			},
		},
	})
	if err != nil {
		return false, err
	}

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			if *instance.State.Code == instanceStateTerminated {
				return true, nil
			}
		}
	}

	return false, nil
}

func removeBastionInstance(ctx context.Context, logger logr.Logger, awsClient *awsclient.Client, opt *options) error {
	instance, err := getFirstMatchingInstance(ctx, awsClient, []*ec2.Filter{
		{
			Name:   aws.String("tag:Name"),
			Values: []*string{aws.String(opt.instanceName)},
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to list instances")
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
		return errors.Wrap(err, "failed to terminate instance")
	}

	return nil
}

func removeSecurityGroup(ctx context.Context, logger logr.Logger, awsClient *awsclient.Client, opt *options) error {
	group, err := getSecurityGroup(ctx, awsClient, opt.vpcID, opt.bastionSecurityGroupName)
	if err != nil {
		return errors.Wrap(err, "failed to list security groups")
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
		return errors.Wrap(err, "failed to remove security group")
	}

	return nil
}
