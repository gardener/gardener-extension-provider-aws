// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	"go.uber.org/atomic"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

// ErrorMultipleMatches is returned when multiple matches are found
var ErrorMultipleMatches = fmt.Errorf("error multiple matches")

type zoneDependencies map[string][]flow.TaskIDer

func newZoneDependencies() zoneDependencies {
	return zoneDependencies{}
}

func (d zoneDependencies) Append(zoneName string, taskIDers ...flow.TaskIDer) {
	taskIDs := d[zoneName]
	if taskIDs == nil {
		taskIDs = []flow.TaskIDer{}
		d[zoneName] = taskIDs
	}
	d[zoneName] = append(d[zoneName], taskIDers...)
}

func (d zoneDependencies) Get(zoneName string) []flow.TaskIDer {
	return d[zoneName]
}

func diffByID[T any](desired, current []T, unique func(item T) string) (toBeDeleted, toBeCreated []T, toBeChecked []struct{ desired, current T }) {
outerDelete:
	for _, c := range current {
		cuniq := unique(c)
		for _, d := range desired {
			if cuniq == unique(d) {
				toBeChecked = append(toBeChecked, struct{ desired, current T }{
					desired: d,
					current: c,
				})
				continue outerDelete
			}
		}
		toBeDeleted = append(toBeDeleted, c)
	}
outerCreate:
	for _, d := range desired {
		duniq := unique(d)
		for _, c := range current {
			if duniq == unique(c) {
				continue outerCreate
			}
		}
		toBeCreated = append(toBeCreated, d)
	}
	return
}

// FindExisting is a generic function to find resources based on their ID or tags.
func FindExisting[T any](ctx context.Context, id *string, tags awsclient.Tags,
	getter func(ctx context.Context, id string) (*T, error),
	finder func(ctx context.Context, tags awsclient.Tags) ([]*T, error),
	selector ...func(item *T) bool) (*T, error) {
	if id != nil {
		found, err := getter(ctx, *id)
		if err != nil {
			return nil, err
		}
		if found != nil && (len(selector) == 0 || selector[0](found)) {
			return found, nil
		}
	}

	found, err := finder(ctx, tags)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}

	if len(selector) == 0 {
		if len(found) > 1 {
			return nil, fmt.Errorf("%w: found matches: %v", ErrorMultipleMatches, deref(found))
		}
		return found[0], nil
	}

	var res *T
	for _, item := range found {
		if selector[0](item) {
			if res != nil {
				return nil, fmt.Errorf("%w: found matches: %v, %v", ErrorMultipleMatches, res, item)
			}
			res = item
		}
	}
	return res, nil
}

type waiter struct {
	log           logr.Logger
	start         time.Time
	period        time.Duration
	message       atomic.String
	keysAndValues []any
	done          chan struct{}
}

//nolint:unparam
func informOnWaiting(log logr.Logger, period time.Duration, message string, keysAndValues ...any) *waiter {
	w := &waiter{
		log:           log,
		start:         time.Now(),
		period:        period,
		keysAndValues: keysAndValues,
		done:          make(chan struct{}),
	}
	w.message.Store(message)
	go w.run()
	return w
}

func (w *waiter) UpdateMessage(message string) {
	w.message.Store(message)
}

func (w *waiter) run() {
	ticker := time.NewTicker(w.period)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			delta := int(time.Since(w.start).Seconds())
			w.log.Info(fmt.Sprintf("%s [%ds]", w.message.Load(), delta), w.keysAndValues...)
		}
	}
}

func (w *waiter) Done(err error) {
	w.done <- struct{}{}
	if err != nil {
		w.log.Info("failed: " + err.Error())
	} else {
		w.log.Info("succeeded")
	}
}

func deref[T any](ts []*T) []T {
	if reflect.TypeOf(ts).Elem().Kind() != reflect.Pointer {
		panic("dereferenced type is not a pointer")
	}
	var res []T
	for _, t := range ts {
		if t == nil {
			continue
		}
		res = append(res, *t)
	}
	return res
}

func containsIPv6(ipFamilies []gardencorev1beta1.IPFamily) bool {
	return slices.Contains(ipFamilies, gardencorev1beta1.IPFamilyIPv6)
}

func containsIPv4(ipFamilies []gardencorev1beta1.IPFamily) bool {
	return slices.Contains(ipFamilies, gardencorev1beta1.IPFamilyIPv4)
}

func toEc2IpAddressType(ipFamilies []gardencorev1beta1.IPFamily) ec2types.IpAddressType {
	if gardencorev1beta1.IsIPv4SingleStack(ipFamilies) {
		return ec2types.IpAddressTypeIpv4
	}
	if gardencorev1beta1.IsIPv6SingleStack(ipFamilies) {
		return ec2types.IpAddressTypeIpv6
	}
	// TODO: make use of helper function from g/g once they support dual-stack
	if slices.Contains(ipFamilies, gardencorev1beta1.IPFamilyIPv4) && slices.Contains(ipFamilies, gardencorev1beta1.IPFamilyIPv6) {
		return ec2types.IpAddressTypeDualstack
	}

	// fallback to IPv4
	return ec2types.IpAddressTypeIpv4
}

// a failed NAT will automatically be deleted by AWS
// https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-troubleshooting.html#nat-gateway-troubleshooting-failed
func isNATGatewayDeletingOrFailed(nat *awsclient.NATGateway) bool {
	return strings.EqualFold(nat.State, string(ec2types.StateDeleting)) || strings.EqualFold(nat.State, string(ec2types.StateFailed))
}

func mmap[T any, R any](in []T, f func(t T) R) []R {
	res := make([]R, 0, len(in))
	for _, v := range in {
		res = append(res, f(v))
	}
	return res
}

func mountTargetsContainSubnet(mountTargets []efstypes.MountTargetDescription, subnetID string) (bool, string) {
	for _, mt := range mountTargets {
		if mt.SubnetId != nil && mt.MountTargetId != nil && *mt.SubnetId == subnetID {
			return true, *mt.MountTargetId
		}
	}
	return false, ""
}

// BuildInfrastructureStatus constructs an InfrastructureStatus from flow state and config.
func BuildInfrastructureStatus(
	state shared.Whiteboard,
	cfg *awsapi.InfrastructureConfig,
) *awsv1alpha1.InfrastructureStatus {
	status := &awsv1alpha1.InfrastructureStatus{
		TypeMeta: metav1.TypeMeta{
			APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
			Kind:       "InfrastructureStatus",
		},
	}

	vpcID := ptr.Deref(state.Get(IdentifierVPC), "")
	groupID := ptr.Deref(state.Get(IdentifierNodesSecurityGroup), "")
	ec2KeyName := ptr.Deref(state.Get(NameKeyPair), "")
	iamInstanceProfileName := ptr.Deref(state.Get(NameIAMInstanceProfile), "")
	arnIAMRole := ptr.Deref(state.Get(ARNIAMRole), "")
	efsID := ptr.Deref(state.Get(IdentifierManagedEfsID), "")

	// config overrides
	if cfg != nil {
		if cfg.ElasticFileSystem != nil && cfg.ElasticFileSystem.ID != nil {
			efsID = *cfg.ElasticFileSystem.ID
		}
		if cfg.Networks.VPC.ID != nil {
			vpcID = *cfg.Networks.VPC.ID
		}
	}

	if vpcID != "" {
		var subnets []awsv1alpha1.Subnet
		prefix := ChildIdZones + shared.Separator
		for k, v := range state.ExportAsFlatMap() {
			if !shared.IsValidValue(v) {
				continue
			}
			if strings.HasPrefix(k, prefix) {
				parts := strings.Split(k, shared.Separator)
				if len(parts) != 3 {
					continue
				}
				var purpose string
				switch parts[2] {
				case IdentifierZoneSubnetPublic:
					purpose = awsapi.PurposePublic
				case IdentifierZoneSubnetWorkers:
					purpose = awsapi.PurposeNodes
				default:
					continue
				}
				subnets = append(subnets, awsv1alpha1.Subnet{
					ID:      v,
					Purpose: purpose,
					Zone:    parts[1],
				})
			}
		}

		status.VPC = awsv1alpha1.VPCStatus{
			ID:      vpcID,
			Subnets: subnets,
		}
		if groupID != "" {
			status.VPC.SecurityGroups = []awsv1alpha1.SecurityGroup{
				{
					Purpose: awsapi.PurposeNodes,
					ID:      groupID,
				},
			}
		}
	}

	if ec2KeyName != "" {
		status.EC2.KeyName = ec2KeyName
	}

	if iamInstanceProfileName != "" {
		status.IAM.InstanceProfiles = []awsv1alpha1.InstanceProfile{
			{
				Purpose: awsapi.PurposeNodes,
				Name:    iamInstanceProfileName,
			},
		}
	}
	if arnIAMRole != "" {
		status.IAM.Roles = []awsv1alpha1.Role{
			{
				Purpose: awsapi.PurposeNodes,
				ARN:     arnIAMRole,
			},
		}
	}

	if efsID != "" {
		status.ElasticFileSystem.ID = efsID
	}

	return status
}

// routeTableAssociationSpec contains the specification to associate a route table with a subnet.
type routeTableAssociationSpec struct {
	subnetKey      string
	assocKey       string
	zoneRouteTable bool
}
