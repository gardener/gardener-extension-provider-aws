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
	"net"
	"time"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	"github.com/gardener/gardener/extensions/pkg/controller"
	ctrlerror "github.com/gardener/gardener/extensions/pkg/controller/error"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Reconcile(ctx context.Context, bastion *extensionsv1alpha1.Bastion) error {
	logger := a.logger.WithValues("bastion", client.ObjectKeyFromObject(bastion), "operation", "reconcile")

	cluster, err := extensions.GetCluster(ctx, a.Client(), bastion.Namespace)
	if err != nil {
		return errors.Wrap(err, "failed to get shoot")
	}

	awsClient, err := a.getAWSClient(ctx, bastion, cluster.Shoot)
	if err != nil {
		return errors.Wrap(err, "failed to create AWS client")
	}

	opt, err := determineOptions(ctx, bastion, cluster, awsClient)
	if err != nil {
		return errors.Wrap(err, "failed to setup AWS client options")
	}

	opt.bastionSecurityGroupID, err = ensureSecurityGroup(ctx, logger, bastion, awsClient, opt)
	if err != nil {
		return errors.Wrap(err, "failed to ensure security group")
	}

	endpoints, err := ensureBastionInstance(ctx, logger, bastion, awsClient, opt)
	if err != nil {
		return errors.Wrap(err, "failed to ensure bastion instance")
	}

	// reconcile again if the instance has not all endpoints yet
	if endpoints == nil || !ingressReady(endpoints.private) || !ingressReady(endpoints.public) {
		return &ctrlerror.RequeueAfterError{
			// requeue rather soon, so that the user (most likely gardenctl eventually)
			// doesn't have to wait too long for the public endpoint to become available
			RequeueAfter: 5 * time.Second,
			Cause:        errors.New("bastion instance has no public/private endpoints yet"),
		}
	}

	if err := ensureWorkerPermissions(ctx, logger, awsClient, opt); err != nil {
		return errors.Wrap(err, "failed to authorize bastion host in worker security group")
	}

	// once a public endpoint is available, publish the endpoint on the
	// Bastion resource to notify upstream about the ready instance
	if ingressReady(endpoints.public) {
		return controller.TryUpdateStatus(ctx, retry.DefaultBackoff, a.Client(), bastion, func() error {
			bastion.Status.Ingress = *endpoints.public
			return nil
		})
	}

	return nil
}

func ensureSecurityGroup(ctx context.Context, logger logr.Logger, bastion *extensionsv1alpha1.Bastion, awsClient *awsclient.Client, opt *options) (string, error) {
	group, err := getSecurityGroup(ctx, awsClient, opt.vpcID, opt.bastionSecurityGroupName)
	if err != nil {
		return "", err
	}

	// prepare ingress rules
	permission, err := ingressPermissions(ctx, bastion)
	if err != nil {
		return "", errors.Wrap(err, "invalid ingress rules configured for bastion")
	}

	// create group if it doesn't exist yet
	var (
		groupID        *string
		hasPermissions = false
	)

	if group == nil {
		logger.Info("Creating security group")
		output, err := awsClient.EC2.CreateSecurityGroupWithContext(ctx, &ec2.CreateSecurityGroupInput{
			Description: awssdk.String("SSH access for Bastion"),
			GroupName:   awssdk.String(opt.bastionSecurityGroupName),
			VpcId:       awssdk.String(opt.vpcID),
			TagSpecifications: []*ec2.TagSpecification{
				{
					ResourceType: awssdk.String("security-group"),
					Tags: []*ec2.Tag{
						{
							Key:   awssdk.String("Name"),
							Value: awssdk.String(opt.bastionSecurityGroupName),
						},
					},
				},
			},
		})
		if err != nil {
			return "", errors.Wrap(err, "could not create security group")
		}

		groupID = output.GroupId
	} else {
		groupID = group.GroupId
		hasPermissions = securityGroupHasPermissions(group, permission)
	}

	if !hasPermissions {
		logger.Info("Authorizing SSH ingress")
		// ensure ingress rules
		_, err = awsClient.EC2.AuthorizeSecurityGroupIngressWithContext(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       groupID,
			IpPermissions: []*ec2.IpPermission{permission},
		})
		if err != nil {
			return "", errors.Wrap(err, "failed to authorize ingress")
		}
	}

	return *groupID, nil
}

// ingressPermissions converts the Ingress rules from the Bastion resource to EC2-compatible
// IP permissions.
func ingressPermissions(ctx context.Context, bastion *extensionsv1alpha1.Bastion) (*ec2.IpPermission, error) {
	permission := &ec2.IpPermission{
		FromPort:   awssdk.Int64(sshPort),
		ToPort:     awssdk.Int64(sshPort),
		IpProtocol: awssdk.String("tcp"),
		// Do not set IpRanges and Ipv6Ranges to empty slices here,
		// as AWS makes a distinction between empty slices and nil,
		// and empty slices are invalid.
	}

	for _, ingress := range bastion.Spec.Ingress {
		ip, _, err := net.ParseCIDR(ingress.IPBlock.CIDR)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid ingress CIDR %q", ingress.IPBlock.CIDR)
		}

		// Make sure to not set a description, otherwise the equality checks in
		// securityGroupHasPermissions() can lead to false negatives.

		if ip.To4() != nil {
			if permission.IpRanges == nil {
				permission.IpRanges = []*ec2.IpRange{}
			}

			permission.IpRanges = append(permission.IpRanges, &ec2.IpRange{
				CidrIp: &ingress.IPBlock.CIDR,
			})
		} else if ip.To16() != nil {
			if permission.Ipv6Ranges == nil {
				permission.Ipv6Ranges = []*ec2.Ipv6Range{}
			}

			permission.Ipv6Ranges = append(permission.Ipv6Ranges, &ec2.Ipv6Range{
				CidrIpv6: &ingress.IPBlock.CIDR,
			})
		}
	}

	return permission, nil
}

// bastionEndpoints collects the endpoints the bastion host providers; the
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
	return be != nil && ingressReady(be.private) && ingressReady(be.public)
}

// ingressReady returns true if either an IP or a hostname or both are set.
func ingressReady(ingress *corev1.LoadBalancerIngress) bool {
	return ingress != nil && (ingress.Hostname != "" || ingress.IP != "")
}

func ensureBastionInstance(ctx context.Context, logger logr.Logger, bastion *extensionsv1alpha1.Bastion, awsClient *awsclient.Client, opt *options) (*bastionEndpoints, error) {
	// check if the instance already exists and has an IP
	endpoints, err := getInstanceEndpoints(ctx, awsClient, opt.instanceName)
	if err != nil { // could not check for instance
		return nil, errors.Wrap(err, "failed to check for EC2 instance")
	}

	// instance exists, though it may not be ready yet
	if endpoints != nil {
		return endpoints, nil
	}

	// prepare to create a new instance
	input := &ec2.RunInstancesInput{
		ImageId:      awssdk.String(opt.imageID),
		InstanceType: awssdk.String(opt.instanceType),
		UserData:     awssdk.String(bastion.Spec.UserData),
		MinCount:     awssdk.Int64(1),
		MaxCount:     awssdk.Int64(1),
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: awssdk.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(opt.instanceName),
					},
				},
			},
		},
		NetworkInterfaces: []*ec2.InstanceNetworkInterfaceSpecification{
			{
				DeviceIndex:              awssdk.Int64(0),
				Groups:                   awssdk.StringSlice([]string{opt.bastionSecurityGroupID}),
				SubnetId:                 awssdk.String(opt.subnetID),
				AssociatePublicIpAddress: awssdk.Bool(true),
			},
		},
	}

	logger.Info("Running new bastion instance")

	_, err = awsClient.EC2.RunInstancesWithContext(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, "failed to run instance")
	}

	// check again for the current endpoints and return them
	// (for new instances, they will most likely not be ready yet,
	// so the caller should re-call this function until they get
	// ready endpoints)
	return getInstanceEndpoints(ctx, awsClient, opt.instanceName)
}

// getInstanceEndpoints returns the public and private IPs/hostnames for the
// given instance. If the instance does not exist, nil is returned.
// Note that the public endpoint can be nil if no IP has been associated with
// the instance yet.
func getInstanceEndpoints(ctx context.Context, awsClient *awsclient.Client, instanceName string) (*bastionEndpoints, error) {
	instance, err := getFirstMatchingInstance(ctx, awsClient, []*ec2.Filter{
		{
			Name:   awssdk.String("tag:Name"),
			Values: []*string{awssdk.String(instanceName)},
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list instances")
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
func ensureWorkerPermissions(ctx context.Context, logger logr.Logger, awsClient *awsclient.Client, opt *options) error {
	workerSecurityGroup, err := getSecurityGroup(ctx, awsClient, opt.vpcID, opt.workerSecurityGroupName)
	if err != nil {
		return errors.Wrap(err, "failed to fetch worker security group")
	}
	if workerSecurityGroup == nil {
		return errors.New("cannot find security group for workers")
	}

	permission := workerSecurityGroupPermission(opt)

	if !securityGroupHasPermissions(workerSecurityGroup, permission) {
		logger.Info("Authorizing SSH ingress to worker nodes")

		_, err = awsClient.EC2.AuthorizeSecurityGroupIngressWithContext(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       awssdk.String(opt.workerSecurityGroupID),
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

			if state == instanceStateShuttingDown || state == instanceStateTerminated {
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
				Name:   awssdk.String("vpc-id"),
				Values: []*string{awssdk.String(vpcID)},
			},
			{
				Name:   awssdk.String("group-name"),
				Values: []*string{awssdk.String(groupName)},
			},
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list security groups")
	}

	if len(groups.SecurityGroups) == 0 {
		return nil, nil
	}

	return groups.SecurityGroups[0], nil
}
