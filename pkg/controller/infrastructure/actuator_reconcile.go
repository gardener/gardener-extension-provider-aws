// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	flowState, err := a.getStateFromInfraStatus(infrastructure)
	if err != nil {
		return err
	}
	if flowState != nil {
		return a.reconcileWithFlow(ctx, log, infrastructure, flowState)
	}
	if a.shouldUseFlow(infrastructure, cluster) {
		flowState, err = a.migrateFromTerraformerState(ctx, log, infrastructure)
		if err != nil {
			return err
		}
		return a.reconcileWithFlow(ctx, log, infrastructure, flowState)
	}

	infrastructureStatus, state, err := ReconcileWithTerraformer(
		ctx,
		log,
		a.RESTConfig(),
		a.Client(),
		a.Decoder(),
		infrastructure, terraformer.StateConfigMapInitializerFunc(terraformer.CreateState),
		a.disableProjectedTokenMount,
	)
	if err != nil {
		return err
	}
	return updateProviderStatusTf(ctx, a.Client(), infrastructure, infrastructureStatus, state)
}

// shouldUseFlow checks if flow reconciliation should be used, by any of these conditions:
// - annotation `aws.provider.extensions.gardener.cloud/use-flow=true` on infrastructure resource
// - annotation `aws.provider.extensions.gardener.cloud/use-flow=true` on shoot resource
// - label `aws.provider.extensions.gardener.cloud/use-flow=true` on seed resource (label instead of annotation, as only labels are transported from managedseed to seed object)
// Note: if the label `aws.provider.extensions.gardener.cloud/use-flow=on-creation` is set for the seed, new shoot clusters will
// be annotated with `aws.provider.extensions.gardener.cloud/use-flow=true` and use the flow reconciliation
// (see /pkg/webhook/shoot/mutator.go)
func (a *actuator) shouldUseFlow(infrastructure *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) bool {
	return strings.EqualFold(infrastructure.Annotations[awsapi.AnnotationKeyUseFlow], "true") ||
		(cluster.Shoot != nil && strings.EqualFold(cluster.Shoot.Annotations[awsapi.AnnotationKeyUseFlow], "true")) ||
		(cluster.Seed != nil && strings.EqualFold(cluster.Seed.Labels[awsapi.SeedLabelKeyUseFlow], "true"))
}

func (a *actuator) getStateFromInfraStatus(infrastructure *extensionsv1alpha1.Infrastructure) (*infraflow.PersistentState, error) {
	if infrastructure.Status.State != nil {
		return infraflow.NewPersistentStateFromJSON(infrastructure.Status.State.Raw)
	}
	return nil, nil
}

func (a *actuator) migrateFromTerraformerState(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure) (*infraflow.PersistentState, error) {
	log.Info("starting terraform state migration")
	infrastructureConfig, err := a.decodeInfrastructureConfig(infrastructure)
	if err != nil {
		return nil, err
	}
	state, err := migrateTerraformStateToFlowState(infrastructure.Status.State, infrastructureConfig.Networks.Zones)
	if err != nil {
		return nil, fmt.Errorf("migration from terraform state failed: %w", err)
	}

	if err := a.updateStatusState(ctx, infrastructure, state); err != nil {
		return nil, fmt.Errorf("updating status state failed: %w", err)
	}
	log.Info("terraform state migrated successfully")

	return state, nil
}

func (a *actuator) decodeInfrastructureConfig(infrastructure *extensionsv1alpha1.Infrastructure) (*awsapi.InfrastructureConfig, error) {
	infrastructureConfig := &awsapi.InfrastructureConfig{}
	if _, _, err := a.Decoder().Decode(infrastructure.Spec.ProviderConfig.Raw, nil, infrastructureConfig); err != nil {
		return nil, fmt.Errorf("could not decode provider config: %w", err)
	}
	return infrastructureConfig, nil
}

func (a *actuator) createFlowContext(ctx context.Context, log logr.Logger,
	infrastructure *extensionsv1alpha1.Infrastructure, oldState *infraflow.PersistentState) (*infraflow.FlowContext, error) {
	if oldState.MigratedFromTerraform() && !oldState.TerraformCleanedUp() {
		err := a.cleanupTerraformerResources(ctx, log, infrastructure)
		if err != nil {
			return nil, fmt.Errorf("cleaning up terraformer resources failed: %w", err)
		}
		oldState.SetTerraformCleanedUp()
		if err := a.updateStatusState(ctx, infrastructure, oldState); err != nil {
			return nil, fmt.Errorf("updating status state failed: %w", err)
		}
	}

	infrastructureConfig, err := a.decodeInfrastructureConfig(infrastructure)
	if err != nil {
		return nil, err
	}

	awsClient, err := aws.NewClientFromSecretRef(ctx, a.Client(), infrastructure.Spec.SecretRef, infrastructure.Spec.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AWS client: %w", err)
	}

	infraObjectKey := client.ObjectKey{
		Namespace: infrastructure.Namespace,
		Name:      infrastructure.Name,
	}
	persistor := func(ctx context.Context, flatState shared.FlatMap) error {
		state := infraflow.NewPersistentStateFromFlatMap(flatState)
		infra := &extensionsv1alpha1.Infrastructure{}
		if err := a.Client().Get(ctx, infraObjectKey, infra); err != nil {
			return err
		}
		return a.updateStatusState(ctx, infra, state)
	}

	var oldFlatState shared.FlatMap
	if oldState != nil {
		if valid, err := oldState.HasValidVersion(); !valid {
			return nil, err
		}
		oldFlatState = oldState.ToFlatMap()
	}

	return infraflow.NewFlowContext(log, awsClient, infrastructure, infrastructureConfig, oldFlatState, persistor)
}

func (a *actuator) cleanupTerraformerResources(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure) error {
	tf, err := newTerraformer(log, a.RESTConfig(), aws.TerraformerPurposeInfra, infrastructure, a.disableProjectedTokenMount)
	if err != nil {
		return fmt.Errorf("could not create terraformer object: %w", err)
	}

	if err := tf.CleanupConfiguration(ctx); err != nil {
		return err
	}
	return tf.RemoveTerraformerFinalizerFromConfig(ctx)
}

func (a *actuator) reconcileWithFlow(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure,
	oldState *infraflow.PersistentState) error {
	log.Info("reconcileWithFlow")

	flowContext, err := a.createFlowContext(ctx, log, infrastructure, oldState)
	if err != nil {
		return err
	}
	if err = flowContext.Reconcile(ctx); err != nil {
		_ = flowContext.PersistState(ctx, true)
		return util.DetermineError(err, helper.KnownCodes)
	}
	return flowContext.PersistState(ctx, true)
}

func (a *actuator) updateStatusState(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, state *infraflow.PersistentState) error {
	infrastructureConfig, err := a.decodeInfrastructureConfig(infra)
	if err != nil {
		return err
	}

	infrastructureStatus, err := computeProviderStatusFromFlowState(infrastructureConfig, state)
	if err != nil {
		return err
	}

	stateBytes, err := state.ToJSON()
	if err != nil {
		return err
	}

	return updateProviderStatus(ctx, a.Client(), infra, infrastructureStatus, stateBytes)
}

func computeProviderStatusFromFlowState(config *awsapi.InfrastructureConfig, state *infraflow.PersistentState) (*awsv1alpha1.InfrastructureStatus, error) {
	if len(state.Data) == 0 {
		return nil, nil
	}
	status := &awsv1alpha1.InfrastructureStatus{
		TypeMeta: metav1.TypeMeta{
			APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
			Kind:       "InfrastructureStatus",
		},
	}

	vpcID := ""
	if config.Networks.VPC.ID != nil {
		vpcID = *config.Networks.VPC.ID
	} else {
		vpcID = state.Data[infraflow.IdentifierVPC]
		if !shared.IsValidValue(vpcID) {
			vpcID = ""
		}
	}

	if vpcID != "" {
		var subnets []awsv1alpha1.Subnet
		prefix := infraflow.ChildIdZones + shared.Separator
		for k, v := range state.Data {
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
				case infraflow.IdentifierZoneSubnetPublic:
					purpose = awsapi.PurposePublic
				case infraflow.IdentifierZoneSubnetWorkers:
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
		if groupID := state.Data[infraflow.IdentifierNodesSecurityGroup]; shared.IsValidValue(groupID) {
			status.VPC.SecurityGroups = []awsv1alpha1.SecurityGroup{
				{
					Purpose: awsapi.PurposeNodes,
					ID:      groupID,
				},
			}
		}
	}

	if keyName := state.Data[infraflow.NameKeyPair]; shared.IsValidValue(keyName) {
		status.EC2.KeyName = keyName
	}

	if name := state.Data[infraflow.NameIAMInstanceProfile]; shared.IsValidValue(name) {
		status.IAM.InstanceProfiles = []awsv1alpha1.InstanceProfile{
			{
				Purpose: awsapi.PurposeNodes,
				Name:    name,
			},
		}
	}
	if arn := state.Data[infraflow.ARNIAMRole]; shared.IsValidValue(arn) {
		status.IAM.Roles = []awsv1alpha1.Role{
			{
				Purpose: awsapi.PurposeNodes,
				ARN:     arn,
			},
		}
	}

	return status, nil

}

// ReconcileWithTerraformer reconciles the given Infrastructure object with terraform. It returns the provider specific status and the Terraform state.
func ReconcileWithTerraformer(
	ctx context.Context,
	logger logr.Logger,
	restConfig *rest.Config,
	c client.Client,
	decoder runtime.Decoder,
	infrastructure *extensionsv1alpha1.Infrastructure,
	stateInitializer terraformer.StateConfigMapInitializer,
	disableProjectedTokenMount bool,
) (
	*awsv1alpha1.InfrastructureStatus,
	*terraformer.RawState,
	error,
) {
	infrastructureConfig := &awsapi.InfrastructureConfig{}
	if _, _, err := decoder.Decode(infrastructure.Spec.ProviderConfig.Raw, nil, infrastructureConfig); err != nil {
		return nil, nil, fmt.Errorf("could not decode provider config: %+v", err)
	}

	awsClient, err := aws.NewClientFromSecretRef(ctx, c, infrastructure.Spec.SecretRef, infrastructure.Spec.Region)
	if err != nil {
		return nil, nil, util.DetermineError(fmt.Errorf("failed to create new AWS client: %+v", err), helper.KnownCodes)
	}

	terraformConfig, err := generateTerraformInfraConfig(ctx, infrastructure, infrastructureConfig, awsClient)
	if err != nil {
		return nil, nil, util.DetermineError(fmt.Errorf("failed to generate Terraform config: %+v", err), helper.KnownCodes)
	}

	var mainTF bytes.Buffer
	if err := tplMainTF.Execute(&mainTF, terraformConfig); err != nil {
		return nil, nil, util.DetermineError(fmt.Errorf("could not render Terraform template: %+v", err), helper.KnownCodes)
	}

	tf, err := newTerraformer(logger, restConfig, aws.TerraformerPurposeInfra, infrastructure, disableProjectedTokenMount)
	if err != nil {
		return nil, nil, util.DetermineError(fmt.Errorf("could not create terraformer object: %+v", err), helper.KnownCodes)
	}

	if err := tf.
		SetEnvVars(generateTerraformerEnvVars(infrastructure.Spec.SecretRef)...).
		InitializeWith(
			ctx,
			terraformer.DefaultInitializer(
				c,
				mainTF.String(),
				variablesTF,
				[]byte(terraformTFVars),
				stateInitializer,
			)).
		Apply(ctx); err != nil {

		return nil, nil, util.DetermineError(fmt.Errorf("failed to apply the terraform config: %w", err), helper.KnownCodes)
	}

	return computeProviderStatus(ctx, tf, infrastructureConfig)
}

func generateTerraformInfraConfig(ctx context.Context, infrastructure *extensionsv1alpha1.Infrastructure, infrastructureConfig *awsapi.InfrastructureConfig, awsClient awsclient.Interface) (map[string]interface{}, error) {
	var (
		dhcpDomainName    = "ec2.internal"
		createVPC         = true
		vpcID             = "aws_vpc.vpc.id"
		vpcCIDR           = ""
		internetGatewayID = "aws_internet_gateway.igw.id"

		ignoreTagKeys        []string
		ignoreTagKeyPrefixes []string
	)

	if infrastructure.Spec.Region != "us-east-1" {
		dhcpDomainName = fmt.Sprintf("%s.compute.internal", infrastructure.Spec.Region)
	}

	switch {
	case infrastructureConfig.Networks.VPC.ID != nil:
		createVPC = false
		existingVpcID := *infrastructureConfig.Networks.VPC.ID
		existingInternetGatewayID, err := awsClient.GetVPCInternetGateway(ctx, existingVpcID)
		if err != nil {
			return nil, err
		}
		vpcID = strconv.Quote(existingVpcID)
		internetGatewayID = strconv.Quote(existingInternetGatewayID)

	case infrastructureConfig.Networks.VPC.CIDR != nil:
		vpcCIDR = *infrastructureConfig.Networks.VPC.CIDR
	}

	var zones []map[string]interface{}
	for _, zone := range infrastructureConfig.Networks.Zones {
		zones = append(zones, map[string]interface{}{
			"name":                  zone.Name,
			"worker":                zone.Workers,
			"public":                zone.Public,
			"internal":              zone.Internal,
			"elasticIPAllocationID": zone.ElasticIPAllocationID,
		})
	}

	enableECRAccess := true
	if v := infrastructureConfig.EnableECRAccess; v != nil {
		enableECRAccess = *v
	}

	if tags := infrastructureConfig.IgnoreTags; tags != nil {
		ignoreTagKeys = tags.Keys
		ignoreTagKeyPrefixes = tags.KeyPrefixes
	}

	terraformInfraConfig := map[string]interface{}{
		"aws": map[string]interface{}{
			"region": infrastructure.Spec.Region,
		},
		"create": map[string]interface{}{
			"vpc": createVPC,
		},
		"enableECRAccess": enableECRAccess,
		"sshPublicKey":    string(infrastructure.Spec.SSHPublicKey),
		"vpc": map[string]interface{}{
			"id":                vpcID,
			"cidr":              vpcCIDR,
			"dhcpDomainName":    dhcpDomainName,
			"internetGatewayID": internetGatewayID,
			"gatewayEndpoints":  infrastructureConfig.Networks.VPC.GatewayEndpoints,
		},
		"clusterName": infrastructure.Namespace,
		"zones":       zones,
		"ignoreTags": map[string]interface{}{
			"keys":        ignoreTagKeys,
			"keyPrefixes": ignoreTagKeyPrefixes,
		},
		"outputKeys": map[string]interface{}{
			"vpcIdKey":                aws.VPCIDKey,
			"subnetsPublicPrefix":     aws.SubnetPublicPrefix,
			"subnetsNodesPrefix":      aws.SubnetNodesPrefix,
			"securityGroupsNodes":     aws.SecurityGroupsNodes,
			"iamInstanceProfileNodes": aws.IAMInstanceProfileNodes,
			"nodesRole":               aws.NodesRole,
		},
	}

	if infrastructure.Spec.SSHPublicKey != nil {
		terraformInfraConfig["outputKeys"].(map[string]interface{})["sshKeyName"] = aws.SSHKeyName
	}
	return terraformInfraConfig, nil
}

func updateProviderStatusTf(ctx context.Context, c client.Client, infrastructure *extensionsv1alpha1.Infrastructure, infrastructureStatus *awsv1alpha1.InfrastructureStatus, state *terraformer.RawState) error {
	var stateBytes []byte
	if state != nil {
		var err error
		stateBytes, err = state.Marshal()
		if err != nil {
			return err
		}
	}
	return updateProviderStatus(ctx, c, infrastructure, infrastructureStatus, stateBytes)
}

func updateProviderStatus(ctx context.Context, c client.Client, infrastructure *extensionsv1alpha1.Infrastructure, infrastructureStatus *awsv1alpha1.InfrastructureStatus, stateBytes []byte) error {

	patch := client.MergeFrom(infrastructure.DeepCopy())
	infrastructure.Status.ProviderStatus = &runtime.RawExtension{Object: infrastructureStatus}
	infrastructure.Status.State = &runtime.RawExtension{Raw: stateBytes}
	return c.Status().Patch(ctx, infrastructure, patch)
}

func computeProviderStatus(ctx context.Context, tf terraformer.Terraformer, infrastructureConfig *awsapi.InfrastructureConfig) (*awsv1alpha1.InfrastructureStatus, *terraformer.RawState, error) {
	state, err := tf.GetRawState(ctx)
	if err != nil {
		return nil, nil, err
	}

	outputVarKeys := []string{
		aws.VPCIDKey,
		aws.IAMInstanceProfileNodes,
		aws.NodesRole,
		aws.SecurityGroupsNodes,
	}

	if _, err := tf.GetStateOutputVariables(ctx, aws.SSHKeyName); err == nil {
		outputVarKeys = append(outputVarKeys, aws.SSHKeyName)
	}

	for zoneIndex := range infrastructureConfig.Networks.Zones {
		outputVarKeys = append(outputVarKeys, fmt.Sprintf("%s%d", aws.SubnetNodesPrefix, zoneIndex))
		outputVarKeys = append(outputVarKeys, fmt.Sprintf("%s%d", aws.SubnetPublicPrefix, zoneIndex))
	}

	output, err := tf.GetStateOutputVariables(ctx, outputVarKeys...)
	if err != nil {
		return nil, nil, err
	}

	subnets, err := computeProviderStatusSubnets(infrastructureConfig, output)
	if err != nil {
		return nil, nil, err
	}

	infrastructureStatus := &awsv1alpha1.InfrastructureStatus{
		TypeMeta: metav1.TypeMeta{
			APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
			Kind:       "InfrastructureStatus",
		},
		VPC: awsv1alpha1.VPCStatus{
			ID:      output[aws.VPCIDKey],
			Subnets: subnets,
			SecurityGroups: []awsv1alpha1.SecurityGroup{
				{
					Purpose: awsapi.PurposeNodes,
					ID:      output[aws.SecurityGroupsNodes],
				},
			},
		},
		IAM: awsv1alpha1.IAM{
			InstanceProfiles: []awsv1alpha1.InstanceProfile{
				{
					Purpose: awsapi.PurposeNodes,
					Name:    output[aws.IAMInstanceProfileNodes],
				},
			},
			Roles: []awsv1alpha1.Role{
				{
					Purpose: awsapi.PurposeNodes,
					ARN:     output[aws.NodesRole],
				},
			},
		},
	}

	if keyName, ok := output[aws.SSHKeyName]; ok {
		infrastructureStatus.EC2 = awsv1alpha1.EC2{
			KeyName: keyName,
		}
	}

	return infrastructureStatus, state, nil
}

func computeProviderStatusSubnets(infrastructure *awsapi.InfrastructureConfig, values map[string]string) ([]awsv1alpha1.Subnet, error) {
	var subnetsToReturn []awsv1alpha1.Subnet

	for key, value := range values {
		var prefix, purpose string
		if strings.HasPrefix(key, aws.SubnetPublicPrefix) {
			prefix = aws.SubnetPublicPrefix
			purpose = awsapi.PurposePublic
		}
		if strings.HasPrefix(key, aws.SubnetNodesPrefix) {
			prefix = aws.SubnetNodesPrefix
			purpose = awsv1alpha1.PurposeNodes
		}

		if len(prefix) == 0 {
			continue
		}

		zoneID, err := strconv.Atoi(strings.TrimPrefix(key, prefix))
		if err != nil {
			return nil, err
		}
		subnetsToReturn = append(subnetsToReturn, awsv1alpha1.Subnet{
			ID:      value,
			Purpose: purpose,
			Zone:    infrastructure.Networks.Zones[zoneID].Name,
		})
	}

	return subnetsToReturn, nil
}
