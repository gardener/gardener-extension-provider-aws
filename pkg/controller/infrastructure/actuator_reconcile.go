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

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, _ *extensionscontroller.Cluster) error {
	infrastructureStatus, state, err := Reconcile(
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
	return updateProviderStatus(ctx, a.Client(), infrastructure, infrastructureStatus, state)
}

// Reconcile reconciles the given Infrastructure object. It returns the provider specific status and the Terraform state.
func Reconcile(
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
		return nil, nil, helper.DetermineError(fmt.Errorf("could not decode provider config: %+v", err))
	}

	awsClient, err := aws.NewClientFromSecretRef(ctx, c, infrastructure.Spec.SecretRef, infrastructure.Spec.Region)
	if err != nil {
		return nil, nil, helper.DetermineError(fmt.Errorf("failed to create new AWS client: %+v", err))
	}

	terraformConfig, err := generateTerraformInfraConfig(ctx, infrastructure, infrastructureConfig, awsClient)
	if err != nil {
		return nil, nil, helper.DetermineError(fmt.Errorf("failed to generate Terraform config: %+v", err))
	}

	var mainTF bytes.Buffer
	if err := tplMainTF.Execute(&mainTF, terraformConfig); err != nil {
		return nil, nil, helper.DetermineError(fmt.Errorf("could not render Terraform template: %+v", err))
	}

	tf, err := newTerraformer(logger, restConfig, aws.TerraformerPurposeInfra, infrastructure, disableProjectedTokenMount)
	if err != nil {
		return nil, nil, helper.DetermineError(fmt.Errorf("could not create terraformer object: %+v", err))
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

		return nil, nil, helper.DetermineError(fmt.Errorf("failed to apply the terraform config: %w", err))
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

	return map[string]interface{}{
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
			"sshKeyName":              aws.SSHKeyName,
			"iamInstanceProfileNodes": aws.IAMInstanceProfileNodes,
			"nodesRole":               aws.NodesRole,
		},
	}, nil
}

func updateProviderStatus(ctx context.Context, c client.Client, infrastructure *extensionsv1alpha1.Infrastructure, infrastructureStatus *awsv1alpha1.InfrastructureStatus, state *terraformer.RawState) error {
	stateByte, err := state.Marshal()
	if err != nil {
		return err
	}

	patch := client.MergeFrom(infrastructure.DeepCopy())
	infrastructure.Status.ProviderStatus = &runtime.RawExtension{Object: infrastructureStatus}
	infrastructure.Status.State = &runtime.RawExtension{Raw: stateByte}
	return c.Status().Patch(ctx, infrastructure, patch)
}

func computeProviderStatus(ctx context.Context, tf terraformer.Terraformer, infrastructureConfig *awsapi.InfrastructureConfig) (*awsv1alpha1.InfrastructureStatus, *terraformer.RawState, error) {
	state, err := tf.GetRawState(ctx)
	if err != nil {
		return nil, nil, err
	}

	outputVarKeys := []string{
		aws.VPCIDKey,
		aws.SSHKeyName,
		aws.IAMInstanceProfileNodes,
		aws.NodesRole,
		aws.SecurityGroupsNodes,
	}

	for zoneIndex := range infrastructureConfig.Networks.Zones {
		outputVarKeys = append(outputVarKeys, fmt.Sprintf("%s%d", aws.SubnetNodesPrefix, zoneIndex))
		outputVarKeys = append(outputVarKeys, fmt.Sprintf("%s%d", aws.SubnetPublicPrefix, zoneIndex))
	}

	output, err := tf.GetStateOutputVariables(ctx, outputVarKeys...)
	if err != nil {
		return nil, nil, helper.DetermineError(err)
	}

	subnets, err := computeProviderStatusSubnets(infrastructureConfig, output)
	if err != nil {
		return nil, nil, helper.DetermineError(err)
	}

	return &awsv1alpha1.InfrastructureStatus{
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
		EC2: awsv1alpha1.EC2{
			KeyName: output[aws.SSHKeyName],
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
	}, state, nil
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
