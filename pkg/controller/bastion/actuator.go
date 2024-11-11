// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion

import (
	"context"
	"fmt"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/extensions/pkg/controller/bastion"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

const (
	// SSHPort is the default SSH port.
	SSHPort = 22
	// InstanceStateShuttingDown is the AWS status code for an EC2 instance that
	// is currently shutting down.
	InstanceStateShuttingDown = 32
	// InstanceStateTerminated is the AWS status code for an EC2 instance that
	// has been terminated.
	InstanceStateTerminated = 48
)

type actuator struct {
	client client.Client
}

func newActuator(mgr manager.Manager) bastion.Actuator {
	return &actuator{
		client: mgr.GetClient(),
	}
}

func (a *actuator) getAWSClient(ctx context.Context, bastion *extensionsv1alpha1.Bastion, shoot *gardencorev1beta1.Shoot) (*awsclient.Client, error) {
	secret := &corev1.Secret{}
	key := client.ObjectKey{Namespace: bastion.Namespace, Name: v1beta1constants.SecretNameCloudProvider}

	if err := a.client.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to find %q Secret: %w", v1beta1constants.SecretNameCloudProvider, err)
	}

	credentials, err := aws.ReadCredentialsSecret(secret, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials Secret: %w", err)
	}

	return awsclient.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), shoot.Spec.Region)
}

// securityGroupHasPermissions checks if the given group has at least
// the desired permission, but possibly more. Comments on IP ranges
// are not considered when comparing current and desired states.
func securityGroupHasPermissions(current []ec2types.IpPermission, desired ec2types.IpPermission) bool {
	// find a matching permission in the security group
	for _, perm := range current {
		if ipPermissionsEqual(perm, desired) {
			return true
		}
	}

	// no matching permissions found
	return false
}

func ipPermissionsEqual(a ec2types.IpPermission, b ec2types.IpPermission) bool {
	// ports must match
	if !equality.Semantic.DeepEqual(a.FromPort, b.FromPort) || !equality.Semantic.DeepEqual(a.ToPort, b.ToPort) {
		return false
	}

	// protocol must match
	if !equality.Semantic.DeepEqual(a.IpProtocol, b.IpProtocol) {
		return false
	}

	// check that the current IP ranges are a superset of the desired ranges;
	// note that these are not just CIDR, but there can also be subnet names
	// among the values
	aIpRanges := getIpRangeCidrs(b.IpRanges)
	bIpRanges := getIpRangeCidrs(a.IpRanges)
	if !bIpRanges.IsSuperset(aIpRanges) {
		return false
	}

	aIpRanges = getIpv6RangeCidrs(b.Ipv6Ranges)
	bIpRanges = getIpv6RangeCidrs(a.Ipv6Ranges)
	if !bIpRanges.IsSuperset(aIpRanges) {
		return false
	}

	// compare assigned security groups (do not take the UserID into account,
	// as it won't be set on the creation request and so would never be
	// equal to the value reported by AWS)
	aGroups := getSecurityGroupIDs(b.UserIdGroupPairs)
	bGroups := getSecurityGroupIDs(a.UserIdGroupPairs)

	return bGroups.IsSuperset(aGroups)
}

func getIpRangeCidrs(ipRanges []ec2types.IpRange) sets.Set[string] {
	result := sets.New[string]()
	for _, ipRange := range ipRanges {
		result.Insert(*ipRange.CidrIp)
	}
	return result
}

func getIpv6RangeCidrs(ipRanges []ec2types.Ipv6Range) sets.Set[string] {
	result := sets.New[string]()
	for _, ipRange := range ipRanges {
		result.Insert(*ipRange.CidrIpv6)
	}
	return result
}

func getSecurityGroupIDs(userGroupPairs []ec2types.UserIdGroupPair) sets.Set[string] {
	result := sets.New[string]()
	for _, pair := range userGroupPairs {
		result.Insert(*pair.GroupId)
	}
	return result
}

// workerSecurityGroupPermission returns the set of permissions that need to be added
// to the worker security group to allow SSH ingress from the bastion instance.
func workerSecurityGroupPermission(opt *Options) ec2types.IpPermission {
	return ec2types.IpPermission{
		IpProtocol: ptr.To("tcp"),
		FromPort:   ptr.To(int32(SSHPort)),
		ToPort:     ptr.To(int32(SSHPort)),
		UserIdGroupPairs: []ec2types.UserIdGroupPair{
			{
				GroupId: ptr.To(opt.BastionSecurityGroupID),
			},
		},
	}
}
