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

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gardener/gardener/extensions/pkg/controller/bastion"
	"github.com/gardener/gardener/extensions/pkg/controller/common"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	SSHPort                   = 22
	InstanceStateShuttingDown = 32
	InstanceStateTerminated   = 48
)

type actuator struct {
	common.ClientContext

	logger logr.Logger
}

func newActuator() bastion.Actuator {
	return &actuator{
		logger: logger,
	}
}

func (a *actuator) getAWSClient(ctx context.Context, bastion *extensionsv1alpha1.Bastion, shoot *gardencorev1beta1.Shoot) (*awsclient.Client, error) {
	secret := &corev1.Secret{}
	key := kubernetes.Key(bastion.Namespace, v1beta1constants.SecretNameCloudProvider)

	if err := a.Client().Get(ctx, key, secret); err != nil {
		return nil, errors.Wrapf(err, "failed to find %q Secret", v1beta1constants.SecretNameCloudProvider)
	}

	credentials, err := aws.ReadCredentialsSecret(secret)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read credentials Secret")
	}

	return awsclient.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), shoot.Spec.Region)
}

// securityGroupHasPermissions checks if the given group has at least
// the desired permission, but possibly more. Comments on IP ranges
// are not considered when comparing current and desired states.
func securityGroupHasPermissions(current []*ec2.IpPermission, desired *ec2.IpPermission) bool {
	// find a matching permission in the security group
	for _, perm := range current {
		if ipPermissionsEqual(perm, desired) {
			return true
		}
	}

	// no matching permissions found
	return false
}

func ipPermissionsEqual(a *ec2.IpPermission, b *ec2.IpPermission) bool {
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
	if !bGroups.IsSuperset(aGroups) {
		return false
	}

	return true
}

func getIpRangeCidrs(ipRanges []*ec2.IpRange) sets.String {
	result := sets.NewString()
	for _, ipRange := range ipRanges {
		result.Insert(*ipRange.CidrIp)
	}
	return result
}

func getIpv6RangeCidrs(ipRanges []*ec2.Ipv6Range) sets.String {
	result := sets.NewString()
	for _, ipRange := range ipRanges {
		result.Insert(*ipRange.CidrIpv6)
	}
	return result
}

func getSecurityGroupIDs(userGroupPairs []*ec2.UserIdGroupPair) sets.String {
	result := sets.NewString()
	for _, pair := range userGroupPairs {
		result.Insert(*pair.GroupId)
	}
	return result
}

// workerSecurityGroupPermission returns the set of permissions that need to be added
// to the worker security group to allow SSH ingress from the bastion instance.
func workerSecurityGroupPermission(opt *Options) *ec2.IpPermission {
	return &ec2.IpPermission{
		IpProtocol: awssdk.String("tcp"),
		FromPort:   awssdk.Int64(SSHPort),
		ToPort:     awssdk.Int64(SSHPort),
		UserIdGroupPairs: []*ec2.UserIdGroupPair{
			{
				GroupId: awssdk.String(opt.BastionSecurityGroupID),
			},
		},
	}
}
