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
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	reconcilerutils "github.com/gardener/gardener/pkg/controllerutils/reconciler"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	awsClient, err := a.getAWSClient(ctx, bastion, cluster.Shoot)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to create AWS client: %w", err))
	}

	opt, err := DetermineOptions(ctx, bastion, cluster, awsClient)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to setup AWS client options: %w", err))
	}

	opt.BastionSecurityGroupID, err = ensureSecurityGroup(ctx, log, bastion, awsClient, opt)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to ensure security group: %w", err))
	}

	endpoints, err := ensureBastionInstance(ctx, log, bastion, awsClient, opt)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to ensure bastion instance: %w", err))
	}

	if err := ensureWorkerPermissions(ctx, log, awsClient, opt); err != nil {
		return helper.DetermineError(fmt.Errorf("failed to authorize bastion host in worker security group: %w", err))
	}

	// reconcile again if the instance has not all endpoints yet
	if !endpoints.Ready() {
		return &reconcilerutils.RequeueAfterError{
			// requeue rather soon, so that the user (most likely gardenctl eventually)
			// doesn't have to wait too long for the public endpoint to become available
			RequeueAfter: 5 * time.Second,
			Cause:        fmt.Errorf("bastion instance has no public/private endpoints yet"),
		}
	}

	// once a public endpoint is available, publish the endpoint on the
	// Bastion resource to notify upstream about the ready instance
	patch := client.MergeFrom(bastion.DeepCopy())
	bastion.Status.Ingress = endpoints.public
	return a.Client().Status().Patch(ctx, bastion, patch)
}

func ensureSecurityGroup(ctx context.Context, logger logr.Logger, bastion *extensionsv1alpha1.Bastion, awsClient *awsclient.Client, opt *Options) (string, error) {
	group, err := getSecurityGroup(ctx, awsClient, opt.VPCID, opt.BastionSecurityGroupName)
	if err != nil {
		return "", err
	}

	// prepare rules
	ingressPermission, err := ingressPermissions(ctx, bastion)
	if err != nil {
		return "", fmt.Errorf("invalid ingress rules configured for bastion: %w", err)
	}

	egressPermission := &ec2.IpPermission{
		FromPort:   aws.Int64(SSHPort),
		ToPort:     aws.Int64(SSHPort),
		IpProtocol: aws.String("tcp"),
		UserIdGroupPairs: []*ec2.UserIdGroupPair{
			{
				GroupId: aws.String(opt.WorkerSecurityGroupID),
			},
		},
	}

	// create group if it doesn't exist yet
	var (
		groupID               *string
		hasIngressPermissions = false
		hasEgressPermissions  = false
	)

	if group == nil {
		logger.Info("Creating security group")
		output, err := awsClient.EC2.CreateSecurityGroupWithContext(ctx, &ec2.CreateSecurityGroupInput{
			Description: aws.String("SSH access for Bastion"),
			GroupName:   aws.String(opt.BastionSecurityGroupName),
			VpcId:       aws.String(opt.VPCID),
			TagSpecifications: []*ec2.TagSpecification{
				{
					ResourceType: aws.String("security-group"),
					Tags: []*ec2.Tag{
						{
							Key:   aws.String("Name"),
							Value: aws.String(opt.BastionSecurityGroupName),
						},
					},
				},
			},
		})
		if err != nil {
			return "", fmt.Errorf("could not create security group: %w", err)
		}

		groupID = output.GroupId
	} else {
		groupID = group.GroupId
		hasIngressPermissions = securityGroupHasPermissions(group.IpPermissions, ingressPermission)
		hasEgressPermissions = securityGroupHasPermissions(group.IpPermissionsEgress, egressPermission)
	}

	if !hasIngressPermissions {
		logger.Info("Authorizing SSH ingress")

		_, err = awsClient.EC2.AuthorizeSecurityGroupIngressWithContext(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       groupID,
			IpPermissions: []*ec2.IpPermission{ingressPermission},
		})
		if err != nil {
			return "", fmt.Errorf("failed to authorize ingress: %w", err)
		}
	}

	if !hasEgressPermissions {
		logger.Info("Revoking bastion egress")

		_, err = awsClient.EC2.AuthorizeSecurityGroupEgressWithContext(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
			GroupId:       groupID,
			IpPermissions: []*ec2.IpPermission{egressPermission},
		})
		if err != nil {
			return "", fmt.Errorf("failed to revoke egress: %w", err)
		}
	}

	// remove all additional egress rules (like the default "allow all" rule created by AWS)
	group, err = getSecurityGroup(ctx, awsClient, opt.VPCID, opt.BastionSecurityGroupName)
	if err != nil {
		return "", err
	}

	permsToDelete := []*ec2.IpPermission{}
	for i, perm := range group.IpPermissionsEgress {
		if !ipPermissionsEqual(perm, egressPermission) {
			permsToDelete = append(permsToDelete, group.IpPermissionsEgress[i])
		}
	}

	if len(permsToDelete) > 0 {
		logger.Info("Revoking default bastion egress")

		_, err = awsClient.EC2.RevokeSecurityGroupEgressWithContext(ctx, &ec2.RevokeSecurityGroupEgressInput{
			GroupId:       groupID,
			IpPermissions: permsToDelete,
		})
		if err != nil {
			return "", fmt.Errorf("failed to revoke egress: %w", err)
		}
	}

	return *groupID, nil
}

// ingressPermissions converts the Ingress rules from the Bastion resource to EC2-compatible
// IP permissions.
func ingressPermissions(ctx context.Context, bastion *extensionsv1alpha1.Bastion) (*ec2.IpPermission, error) {
	permission := &ec2.IpPermission{
		FromPort:   aws.Int64(SSHPort),
		ToPort:     aws.Int64(SSHPort),
		IpProtocol: aws.String("tcp"),
		// Do not set IpRanges and Ipv6Ranges to empty slices here,
		// as AWS makes a distinction between empty slices and nil,
		// and empty slices are invalid.
	}

	for _, ingress := range bastion.Spec.Ingress {
		cidr := ingress.IPBlock.CIDR

		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid ingress CIDR %q: %w", cidr, err)
		}

		// Make sure to not set a description, otherwise the equality checks in
		// securityGroupHasPermissions() can lead to false negatives.
		// Likewise, do not take the user-supplied CIDR, but the parsed in order
		// to normalise the base address (i.e. turn "1.2.3.4/8" into "1.0.0.0/8");
		// AWS performs the same normalisation internally.
		normalisedCIDR := ipNet.String()

		if ip.To4() != nil {
			if permission.IpRanges == nil {
				permission.IpRanges = []*ec2.IpRange{}
			}

			permission.IpRanges = append(permission.IpRanges, &ec2.IpRange{
				CidrIp: &normalisedCIDR,
			})
		} else if ip.To16() != nil {
			if permission.Ipv6Ranges == nil {
				permission.Ipv6Ranges = []*ec2.Ipv6Range{}
			}

			permission.Ipv6Ranges = append(permission.Ipv6Ranges, &ec2.Ipv6Range{
				CidrIpv6: &normalisedCIDR,
			})
		}
	}

	return permission, nil
}

// bastionEndpoints collects the endpoints the bastion host provides; the
// private endpoint is important for opening a port on the worker node
// security group to allow SSH from that node, the public endpoint is where
// the enduser connects to to establish the SSH connection.
type bastionEndpoints struct {
	private *corev1.LoadBalancerIngress
	public  *corev1.LoadBalancerIngress
}

// Ready returns true if both public and private interfaces each have either
// an IP or a hostname or both.
func (be *bastionEndpoints) Ready() bool {
	return be != nil && IngressReady(be.private) && IngressReady(be.public)
}

// IngressReady returns true if either an IP or a hostname or both are set.
func IngressReady(ingress *corev1.LoadBalancerIngress) bool {
	return ingress != nil && (ingress.Hostname != "" || ingress.IP != "")
}

func ensureBastionInstance(ctx context.Context, logger logr.Logger, bastion *extensionsv1alpha1.Bastion, awsClient *awsclient.Client, opt *Options) (*bastionEndpoints, error) {
	// check if the instance already exists and has an IP
	endpoints, err := getInstanceEndpoints(ctx, awsClient, opt.InstanceName)
	if err != nil { // could not check for instance
		return nil, fmt.Errorf("failed to check for EC2 instance: %w", err)
	}

	// instance exists, though it may not be ready yet
	if endpoints != nil {
		return endpoints, nil
	}

	// prepare to create a new instance
	input := &ec2.RunInstancesInput{
		ImageId:      aws.String(opt.ImageID),
		InstanceType: aws.String(opt.InstanceType),
		UserData:     aws.String(base64.StdEncoding.EncodeToString(bastion.Spec.UserData)),
		MinCount:     aws.Int64(1),
		MaxCount:     aws.Int64(1),
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(opt.InstanceName),
					},
				},
			},
		},
		NetworkInterfaces: []*ec2.InstanceNetworkInterfaceSpecification{
			{
				DeviceIndex:              aws.Int64(0),
				Groups:                   aws.StringSlice([]string{opt.BastionSecurityGroupID}),
				SubnetId:                 aws.String(opt.SubnetID),
				AssociatePublicIpAddress: aws.Bool(true),
			},
		},
	}

	logger.Info("Running new bastion instance")

	_, err = awsClient.EC2.RunInstancesWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to run instance: %w", err)
	}

	// check again for the current endpoints and return them
	// (for new instances, they will most likely not be ready yet,
	// so the caller should re-call this function until they get
	// ready endpoints)
	return getInstanceEndpoints(ctx, awsClient, opt.InstanceName)
}

// getInstanceEndpoints returns the public and private IPs/hostnames for the
// given instance. If the instance does not exist, nil is returned.
// Note that the public endpoint can be nil if no IP has been associated with
// the instance yet.
func getInstanceEndpoints(ctx context.Context, awsClient *awsclient.Client, instanceName string) (*bastionEndpoints, error) {
	instance, err := getFirstMatchingInstance(ctx, awsClient, []*ec2.Filter{
		{
			Name:   aws.String("tag:Name"),
			Values: []*string{aws.String(instanceName)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list instances: %w", err)
	}
	if instance == nil {
		return nil, nil
	}

	endpoints := &bastionEndpoints{}

	if ingress := addressToIngress(instance.PrivateDnsName, instance.PrivateIpAddress); ingress != nil {
		endpoints.private = ingress
	}

	if ingress := addressToIngress(instance.PublicDnsName, instance.PublicIpAddress); ingress != nil {
		endpoints.public = ingress
	}

	return endpoints, nil
}

// addressToIngress converts the optional DNS name and IP address into a
// corev1.LoadBalancerIngress resource. If both arguments are nil, then
// nil is returned.
func addressToIngress(dnsName *string, ipAddress *string) *corev1.LoadBalancerIngress {
	var ingress *corev1.LoadBalancerIngress

	if ipAddress != nil || dnsName != nil {
		ingress = &corev1.LoadBalancerIngress{}

		if dnsName != nil {
			ingress.Hostname = *dnsName
		}

		if ipAddress != nil {
			ingress.IP = *ipAddress
		}
	}

	return ingress
}

// ensureWorkerPermissions authorizes the bastion host's private IP to access
// the worker nodes on port 22.
func ensureWorkerPermissions(ctx context.Context, logger logr.Logger, awsClient *awsclient.Client, opt *Options) error {
	workerSecurityGroup, err := getSecurityGroup(ctx, awsClient, opt.VPCID, opt.WorkerSecurityGroupName)
	if err != nil {
		return fmt.Errorf("failed to fetch worker security group: %w", err)
	}
	if workerSecurityGroup == nil {
		return fmt.Errorf("cannot find security group for workers")
	}

	permission := workerSecurityGroupPermission(opt)

	if !securityGroupHasPermissions(workerSecurityGroup.IpPermissions, permission) {
		logger.Info("Authorizing SSH ingress to worker nodes")

		_, err = awsClient.EC2.AuthorizeSecurityGroupIngressWithContext(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(opt.WorkerSecurityGroupID),
			IpPermissions: []*ec2.IpPermission{permission},
		})
	}

	return err
}

// getFirstMatchingInstance returns the first EC2 instances that matches
// the filter and is not in a Terminating/Shutting-down state. If no
// instances match, nil and no error are returned.
func getFirstMatchingInstance(ctx context.Context, awsClient *awsclient.Client, filter []*ec2.Filter) (*ec2.Instance, error) {
	instances, err := awsClient.EC2.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{Filters: filter})
	if err != nil {
		return nil, err
	}

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			state := *instance.State.Code

			if state == InstanceStateShuttingDown || state == InstanceStateTerminated {
				continue
			}

			return instance, nil
		}
	}

	return nil, nil
}

func getSecurityGroup(ctx context.Context, awsClient *awsclient.Client, vpcID string, groupName string) (*ec2.SecurityGroup, error) {
	// try to find existing SG
	groups, err := awsClient.EC2.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(vpcID)},
			},
			{
				Name:   aws.String("group-name"),
				Values: []*string{aws.String(groupName)},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list security groups: %w", err)
	}

	if len(groups.SecurityGroups) == 0 {
		return nil, nil
	}

	return groups.SecurityGroups[0], nil
}
