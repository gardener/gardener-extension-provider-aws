// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package infrastructure

import (
	"fmt"
	"strings"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	"k8s.io/apimachinery/pkg/runtime"
)

func migrateTerraformStateToFlowState(rawExtension *runtime.RawExtension, zones []awsapi.Zone) (*infraflow.PersistentState, error) {
	var (
		tfRawState *terraformer.RawState
		tfState    *shared.TerraformState
		err        error
	)

	flowState := infraflow.NewPersistentState()

	if rawExtension == nil {
		return flowState, nil
	}

	if tfRawState, err = getTerraformerRawState(rawExtension); err != nil {
		return nil, err
	}
	if tfState, err = shared.UnmarshalTerraformStateFromTerraformer(tfRawState); err != nil {
		return nil, err
	}

	if tfState.Outputs == nil {
		return flowState, nil
	}

	value := tfState.Outputs[aws.VPCIDKey].Value
	if value != "" {
		setFlowStateData(flowState, infraflow.IdentifierVPC, &value)
	}
	setFlowStateData(flowState, infraflow.IdentifierDHCPOptions,
		tfState.GetManagedResourceInstanceID("aws_vpc_dhcp_options", "vpc_dhcp_options"))
	setFlowStateData(flowState, infraflow.IdentifierDefaultSecurityGroup,
		tfState.GetManagedResourceInstanceID("aws_default_security_group", "default"))
	setFlowStateData(flowState, infraflow.IdentifierInternetGateway,
		tfState.GetManagedResourceInstanceID("aws_internet_gateway", "igw"))
	setFlowStateData(flowState, infraflow.IdentifierMainRouteTable,
		tfState.GetManagedResourceInstanceID("aws_route_table", "public"))
	setFlowStateData(flowState, infraflow.IdentifierNodesSecurityGroup,
		tfState.GetManagedResourceInstanceID("aws_security_group", "nodes"))

	if instances := tfState.GetManagedResourceInstances("aws_vpc_endpoint"); len(instances) > 0 {
		for name, id := range instances {
			key := infraflow.ChildIdVPCEndpoints + shared.Separator + strings.TrimPrefix(name, "vpc_gwep_")
			setFlowStateData(flowState, key, &id)
		}
	}

	tfNamePrefixes := []string{"nodes_", "private_utility_", "public_utility"}
	flowNames := []string{infraflow.IdentifierZoneSubnetWorkers, infraflow.IdentifierZoneSubnetPrivate, infraflow.IdentifierZoneSubnetPublic}
	for i, zone := range zones {
		keyPrefix := infraflow.ChildIdZones + shared.Separator + zone.Name + shared.Separator
		suffix := fmt.Sprintf("z%d", i)
		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierZoneSuffix, &suffix)

		for j := 0; j < len(tfNamePrefixes); j++ {
			setFlowStateData(flowState, keyPrefix+flowNames[j],
				tfState.GetManagedResourceInstanceID("aws_subnet", tfNamePrefixes[j]+suffix))
		}
		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierZoneNATGWElasticIP,
			tfState.GetManagedResourceInstanceID("aws_eip", "eip_natgw_"+suffix))
		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierZoneNATGateway,
			tfState.GetManagedResourceInstanceID("aws_nat_gateway", "natgw_"+suffix))
		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierZoneNATGateway,
			tfState.GetManagedResourceInstanceID("aws_route_table", "private_utility_"+suffix))

		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierZoneSubnetPublicRouteTableAssoc,
			tfState.GetManagedResourceInstanceID("aws_route_table_association", "routetable_main_association_public_utility_"+suffix))
		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierZoneSubnetPrivateRouteTableAssoc,
			tfState.GetManagedResourceInstanceID("aws_route_table_association", "routetable_private_utility_"+suffix+"_association_private_utility_"+suffix))
		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierZoneSubnetWorkersRouteTableAssoc,
			tfState.GetManagedResourceInstanceID("aws_route_table_association", "routetable_private_utility_"+suffix+"_association_nodes_"+suffix))
	}

	setFlowStateData(flowState, infraflow.NameIAMRole,
		tfState.GetManagedResourceInstanceName("aws_iam_role", "nodes"))
	setFlowStateData(flowState, infraflow.NameIAMInstanceProfile,
		tfState.GetManagedResourceInstanceName("aws_iam_instance_profile", "nodes"))
	setFlowStateData(flowState, infraflow.NameIAMRolePolicy,
		tfState.GetManagedResourceInstanceName("aws_iam_role_policy", "nodes"))
	setFlowStateData(flowState, infraflow.ARNIAMRole,
		tfState.GetManagedResourceInstanceAttribute("aws_iam_role", "nodes", "arn"))

	setFlowStateData(flowState, infraflow.NameKeyPair,
		tfState.GetManagedResourceInstanceAttribute("aws_key_pair", "nodes", "key_pair_id"))

	flowState.SetMigratedFromTerraform()

	return flowState, nil
}

func setFlowStateData(state *infraflow.PersistentState, key string, id *string) {
	if id == nil {
		delete(state.Data, key)
	} else {
		state.Data[key] = *id
	}
}

func getTerraformerRawState(state *runtime.RawExtension) (*terraformer.RawState, error) {
	if state == nil {
		return nil, nil
	}
	tfRawState, err := terraformer.UnmarshalRawState(state)
	if err != nil {
		return nil, fmt.Errorf("could not decode terraform raw state: %+v", err)
	}
	return tfRawState, nil
}
