// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	awsmachineapi "github.com/gardener/machine-controller-manager-provider-aws/pkg/aws/apis"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// BuildNetworkInterfacesTyped exposes buildNetworkInterfacesTyped for testing.
var BuildNetworkInterfacesTyped = func(workerConfig *api.WorkerConfig, defaultSubnetID, defaultSecurityGroupID string) ([]awsmachineapi.AWSNetworkInterfaceSpec, error) {
	return buildNetworkInterfacesTyped(workerConfig, defaultSubnetID, defaultSecurityGroupID)
}
