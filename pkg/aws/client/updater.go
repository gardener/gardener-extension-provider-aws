// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/go-logr/logr"
	"k8s.io/utils/ptr"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// Updater provides methods to update selected AWS client objects.
type Updater interface {
	UpdateVpc(ctx context.Context, desired, current *VPC) (modified bool, err error)
	UpdateSecurityGroup(ctx context.Context, desired, current *SecurityGroup) (modified bool, err error)
	UpdateRouteTable(ctx context.Context, log logr.Logger, desired, current *RouteTable) (modified bool, err error)
	UpdateSubnet(ctx context.Context, desired, current *Subnet) (modified bool, err error)
	UpdateIAMInstanceProfile(ctx context.Context, desired, current *IAMInstanceProfile) (modified bool, err error)
	UpdateIAMRole(ctx context.Context, desired, current *IAMRole) (modified bool, err error)
	UpdateEC2Tags(ctx context.Context, id string, desired, current Tags) (modified bool, err error)
}

type updater struct {
	client     Interface
	ignoreTags *awsapi.IgnoreTags
}

// NewUpdater creates a new updater instance.
func NewUpdater(client Interface, ignoreTags *awsapi.IgnoreTags) Updater {
	return &updater{
		client:     client,
		ignoreTags: ignoreTags,
	}
}

func (u *updater) UpdateVpc(ctx context.Context, desired, current *VPC) (modified bool, err error) {
	if desired.CidrBlock != current.CidrBlock {
		return false, fmt.Errorf("cannot change CIDR block")
	}
	modified, err = u.updateVpcAttributes(ctx, desired, current)
	if err != nil {
		return
	}
	if !reflect.DeepEqual(desired.DhcpOptionsId, current.DhcpOptionsId) {
		if err = u.client.AddVpcDhcpOptionAssociation(current.VpcId, desired.DhcpOptionsId); err != nil {
			return
		}
		modified = true
	}
	ipv6Modified, err := u.client.UpdateAmazonProvidedIPv6CidrBlock(ctx, desired, current)
	modified = modified || ipv6Modified
	if err != nil {
		return
	}
	ec2TagsModified, err := u.UpdateEC2Tags(ctx, current.VpcId, desired.Tags, current.Tags)
	modified = modified || ec2TagsModified
	if err != nil {
		return
	}
	return
}

func (u *updater) updateVpcAttributes(ctx context.Context, desired, current *VPC) (modified bool, err error) {
	if desired.EnableDnsSupport != current.EnableDnsSupport {
		if err = u.client.UpdateVpcAttribute(ctx, current.VpcId, string(ec2types.VpcAttributeNameEnableDnsSupport), desired.EnableDnsSupport); err != nil {
			return
		}
		modified = true
	}
	if desired.EnableDnsHostnames != current.EnableDnsHostnames {
		if err = u.client.UpdateVpcAttribute(ctx, current.VpcId, string(ec2types.VpcAttributeNameEnableDnsHostnames), desired.EnableDnsHostnames); err != nil {
			return
		}
		modified = true
	}
	return
}

func (u *updater) UpdateSecurityGroup(ctx context.Context, desired, current *SecurityGroup) (modified bool, err error) {
	added, removed := desired.DiffRules(current)
	if len(added) == 0 && len(removed) == 0 {
		return
	}
	if err = u.client.RevokeSecurityGroupRules(ctx, current.GroupId, removed); err != nil {
		return
	}
	if err = u.client.AuthorizeSecurityGroupRules(ctx, current.GroupId, added); err != nil {
		return
	}
	if _, err = u.UpdateEC2Tags(ctx, current.GroupId, desired.Tags, current.Tags); err != nil {
		return
	}
	return true, nil
}

// TODO: Consider IPv4 xor IPv6 xor destination prefix lists as destination.
func (u *updater) UpdateRouteTable(ctx context.Context, log logr.Logger, desired, current *RouteTable) (bool, error) {
	var (
		routesToDelete = []*Route{}
		routesToCreate = []*Route{}
		modified       = false
	)

	for _, r := range current.Routes {
		if r == nil {
			continue
		}
		if !slices.Contains(desired.Routes, r) {
			routesToDelete = append(routesToDelete, r)
		}
	}
	for _, r := range desired.Routes {
		if r == nil {
			continue
		}
		if !slices.Contains(current.Routes, r) {
			routesToCreate = append(routesToCreate, r)
		}
	}

	for _, route := range routesToDelete {
		if route.GatewayId != nil && *route.GatewayId == "local" {
			// ignore local gateway route
			continue
		}

		deletionCandidateDestination, err := route.DestinationId()
		if err != nil {
			log.Error(err, "error deleting route", "route", route)
			return false, err
		}

		// The current route table may contain routes not created by the infrastructure controller e.g. the aws-custom-route-controller.
		// These extra routes will be included in the routesToDelete, but they need to be skipped.
		if !slices.ContainsFunc(desired.Routes, func(r *Route) bool {
			desiredRouteDestination, err := r.DestinationId()
			if err != nil {
				log.Error(err, "error deleting route", "route", route)
				return false
			}
			return deletionCandidateDestination == desiredRouteDestination
		}) {
			continue
		}

		if err := u.client.DeleteRoute(ctx, current.RouteTableId, route); err != nil {
			return modified, err
		}

		log.Info("Deleted route", "cidr", deletionCandidateDestination)
	}

	for _, route := range routesToCreate {
		if err := u.client.CreateRoute(ctx, current.RouteTableId, route); err != nil {
			return modified, err
		}

		log.Info("Created route", "cidr", ptr.Deref(route.DestinationCidrBlock, ""))
		modified = true
	}

	return modified, nil
}

func (u *updater) UpdateSubnet(ctx context.Context, desired, current *Subnet) (modified bool, err error) {
	modified, err = u.client.UpdateSubnetAttributes(ctx, desired, current)
	if err != nil {
		return
	}

	mod2, err := u.UpdateEC2Tags(ctx, current.SubnetId, desired.Tags, current.Tags)
	if err != nil {
		return
	}
	return modified || mod2, nil
}

func (u *updater) UpdateIAMInstanceProfile(ctx context.Context, desired, current *IAMInstanceProfile) (modified bool, err error) {
	if current.RoleName == desired.RoleName {
		return
	}
	if desired.RoleName != "" {
		if err = u.client.AddRoleToIAMInstanceProfile(ctx, current.InstanceProfileName, desired.RoleName); err != nil {
			return
		}
		modified = true
	}
	if current.RoleName != "" {
		if err = u.client.RemoveRoleFromIAMInstanceProfile(ctx, current.InstanceProfileName, current.RoleName); err != nil {
			return
		}
		modified = true
	}
	return
}

func (u *updater) UpdateIAMRole(ctx context.Context, desired, current *IAMRole) (modified bool, err error) {
	var equalDocument bool
	equalDocument, err = u.equalJSON(current.AssumeRolePolicyDocument, desired.AssumeRolePolicyDocument)
	if err != nil {
		return
	}
	if equalDocument {
		return
	}

	if err = u.client.UpdateAssumeRolePolicy(ctx, current.RoleName, desired.AssumeRolePolicyDocument); err != nil {
		return
	}
	modified = true
	return
}

func (u *updater) equalJSON(a, b string) (bool, error) {
	ma := map[string]any{}
	mb := map[string]any{}
	if err := json.Unmarshal([]byte(a), &ma); err != nil {
		return false, err
	}
	if err := json.Unmarshal([]byte(b), &mb); err != nil {
		return false, err
	}
	return reflect.DeepEqual(ma, mb), nil
}

func (u *updater) UpdateEC2Tags(ctx context.Context, id string, desired, current Tags) (bool, error) {
	modified := false
	toBeDeleted := Tags{}
	toBeCreated := Tags{}
	toBeIgnored := Tags{}
	for k, v := range current {
		if dv, ok := desired[k]; ok {
			if dv != v {
				toBeDeleted[k] = v
				toBeCreated[k] = dv
			}
		} else if u.ignoreTag(k) {
			toBeIgnored[k] = v
		} else {
			toBeDeleted[k] = v
		}
	}
	for k, v := range desired {
		if _, ok := current[k]; !ok && !u.ignoreTag(k) {
			toBeCreated[k] = v
		}
	}

	if len(toBeDeleted) > 0 {
		if err := u.client.DeleteEC2Tags(ctx, []string{id}, toBeDeleted); err != nil {
			return false, err
		}
		modified = true
	}
	if len(toBeCreated) > 0 {
		if err := u.client.CreateEC2Tags(ctx, []string{id}, toBeCreated); err != nil {
			return false, err
		}
		modified = true
	}

	return modified, nil
}

func (u *updater) ignoreTag(key string) bool {
	if u.ignoreTags == nil {
		return false
	}
	for _, ignoreKey := range u.ignoreTags.Keys {
		if ignoreKey == key {
			return true
		}
	}
	for _, ignoreKeyPrefix := range u.ignoreTags.KeyPrefixes {
		if strings.HasPrefix(key, ignoreKeyPrefix) {
			return true
		}
	}
	return false
}
