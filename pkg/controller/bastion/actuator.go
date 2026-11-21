// SPDX-FileCopyrightText: Contributors to the Gardener project
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

	authConfig, err := aws.ReadCredentialsSecret(secret, false, shoot.Spec.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials Secret: %w", err)
	}

	return awsclient.NewClient(*authConfig)
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
		if ipRange.CidrIp != nil {
			result.Insert(*ipRange.CidrIp)
		}
	}
	return result
}

func getIpv6RangeCidrs(ipRanges []ec2types.Ipv6Range) sets.Set[string] {
	result := sets.New[string]()
	for _, ipRange := range ipRanges {
		if ipRange.CidrIpv6 != nil {
			result.Insert(*ipRange.CidrIpv6)
		}
	}
	return result
}

func getSecurityGroupIDs(userGroupPairs []ec2types.UserIdGroupPair) sets.Set[string] {
	result := sets.New[string]()
	for _, pair := range userGroupPairs {
		if pair.GroupId != nil {
			result.Insert(*pair.GroupId)
		}
	}
	return result
}

// missingIngressPermissions returns an IpPermission containing only the IPv4/IPv6
// CIDRs from desired that are not yet present in current. Returns nil when all
// desired CIDRs are already authorized.
func missingIngressPermissions(current []ec2types.IpPermission, desired ec2types.IpPermission) *ec2types.IpPermission {
	currentIPv4 := sets.New[string]()
	currentIPv6 := sets.New[string]()

	for _, perm := range current {
		if !equality.Semantic.DeepEqual(perm.FromPort, desired.FromPort) ||
			!equality.Semantic.DeepEqual(perm.ToPort, desired.ToPort) ||
			!equality.Semantic.DeepEqual(perm.IpProtocol, desired.IpProtocol) {
			continue
		}
		currentIPv4 = currentIPv4.Union(getIpRangeCidrs(perm.IpRanges))
		currentIPv6 = currentIPv6.Union(getIpv6RangeCidrs(perm.Ipv6Ranges))
	}

	var missingIPv4 []ec2types.IpRange
	for _, r := range desired.IpRanges {
		if r.CidrIp != nil && !currentIPv4.Has(*r.CidrIp) {
			missingIPv4 = append(missingIPv4, r)
		}
	}

	var missingIPv6 []ec2types.Ipv6Range
	for _, r := range desired.Ipv6Ranges {
		if r.CidrIpv6 != nil && !currentIPv6.Has(*r.CidrIpv6) {
			missingIPv6 = append(missingIPv6, r)
		}
	}

	if len(missingIPv4) == 0 && len(missingIPv6) == 0 {
		return nil
	}

	return &ec2types.IpPermission{
		FromPort:   desired.FromPort,
		ToPort:     desired.ToPort,
		IpProtocol: desired.IpProtocol,
		IpRanges:   missingIPv4,
		Ipv6Ranges: missingIPv6,
	}
}

// staleIngressPermissions returns the subset of current permissions whose IPv4/IPv6
// CIDRs are not present in the desired permission. Only permissions that share the
// same port range and protocol as desired are considered; unrelated rules are left
// untouched.
func staleIngressPermissions(current []ec2types.IpPermission, desired ec2types.IpPermission) []ec2types.IpPermission {
	desiredIPv4 := getIpRangeCidrs(desired.IpRanges)
	desiredIPv6 := getIpv6RangeCidrs(desired.Ipv6Ranges)

	var stale []ec2types.IpPermission
	for _, perm := range current {
		if !equality.Semantic.DeepEqual(perm.FromPort, desired.FromPort) ||
			!equality.Semantic.DeepEqual(perm.ToPort, desired.ToPort) ||
			!equality.Semantic.DeepEqual(perm.IpProtocol, desired.IpProtocol) {
			continue
		}

		var staleIPv4 []ec2types.IpRange
		for _, r := range perm.IpRanges {
			if r.CidrIp != nil && !desiredIPv4.Has(*r.CidrIp) {
				staleIPv4 = append(staleIPv4, r)
			}
		}

		var staleIPv6 []ec2types.Ipv6Range
		for _, r := range perm.Ipv6Ranges {
			if r.CidrIpv6 != nil && !desiredIPv6.Has(*r.CidrIpv6) {
				staleIPv6 = append(staleIPv6, r)
			}
		}

		if len(staleIPv4) > 0 || len(staleIPv6) > 0 {
			stale = append(stale, ec2types.IpPermission{
				FromPort:   perm.FromPort,
				ToPort:     perm.ToPort,
				IpProtocol: perm.IpProtocol,
				IpRanges:   staleIPv4,
				Ipv6Ranges: staleIPv6,
			})
		}
	}
	return stale
}

// workerSecurityGroupPermission returns the set of permissions that need to be added
// to the worker security group to allow SSH ingress from the bastion instance.
func workerSecurityGroupPermission(opt BaseOptions) ec2types.IpPermission {
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
