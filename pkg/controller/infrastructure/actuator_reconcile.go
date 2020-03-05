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
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	extensionscontroller "github.com/gardener/gardener-extensions/pkg/controller"
	controllererrors "github.com/gardener/gardener-extensions/pkg/controller/error"
	"github.com/gardener/gardener-extensions/pkg/terraformer"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
)

func (a *actuator) Reconcile(ctx context.Context, infrastructure *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	credentials, err := aws.GetCredentialsFromSecretRef(ctx, a.Client(), infrastructure.Spec.SecretRef)
	if err != nil {
		return err
	}

	infrastructureConfig := &awsapi.InfrastructureConfig{}
	if _, _, err := a.Decoder().Decode(infrastructure.Spec.ProviderConfig.Raw, nil, infrastructureConfig); err != nil {
		return fmt.Errorf("could not decode provider config: %+v", err)
	}

	terraformConfig, err := generateTerraformInfraConfig(ctx, infrastructure, infrastructureConfig, credentials)
	if err != nil {
		return fmt.Errorf("failed to generate Terraform config: %+v", err)
	}

	terraformState, err := terraformer.UnmarshalRawState(infrastructure.Status.State)
	if err != nil {
		return err
	}

	release, err := a.ChartRenderer().Render(filepath.Join(aws.InternalChartsPath, "aws-infra"), "aws-infra", infrastructure.Namespace, terraformConfig)
	if err != nil {
		return fmt.Errorf("could not render Terraform chart: %+v", err)
	}

	tf, err := a.newTerraformer(aws.TerraformerPurposeInfra, infrastructure.Namespace, infrastructure.Name)
	if err != nil {
		return fmt.Errorf("could not create terraformer object: %+v", err)
	}

	if err := tf.
		SetVariablesEnvironment(generateTerraformInfraVariablesEnvironment(credentials)).
		InitializeWith(terraformer.DefaultInitializer(
			a.Client(),
			release.FileContent("main.tf"),
			release.FileContent("variables.tf"),
			[]byte(release.FileContent("terraform.tfvars")),
			terraformState.Data,
		)).
		Apply(); err != nil {

		a.logger.Error(err, "failed to apply the terraform config", "infrastructure", infrastructure.Name)
		return &controllererrors.RequeueAfterError{
			Cause:        err,
			RequeueAfter: 30 * time.Second,
		}
	}

	return a.updateProviderStatus(ctx, tf, infrastructure, infrastructureConfig)
}

func generateTerraformInfraConfig(ctx context.Context, infrastructure *extensionsv1alpha1.Infrastructure, infrastructureConfig *awsapi.InfrastructureConfig, credentials *aws.Credentials) (map[string]interface{}, error) {
	var (
		dhcpDomainName    = "ec2.internal"
		createVPC         = true
		vpcID             = "${aws_vpc.vpc.id}"
		vpcCIDR           = ""
		internetGatewayID = "${aws_internet_gateway.igw.id}"
	)

	if infrastructure.Spec.Region != "us-east-1" {
		dhcpDomainName = fmt.Sprintf("%s.compute.internal", infrastructure.Spec.Region)
	}

	switch {
	case infrastructureConfig.Networks.VPC.ID != nil:
		createVPC = false
		vpcID = *infrastructureConfig.Networks.VPC.ID
		awsClient, err := client.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), infrastructure.Spec.Region)
		if err != nil {
			return nil, err
		}
		igwID, err := awsClient.GetInternetGateway(ctx, vpcID)
		if err != nil {
			return nil, err
		}
		internetGatewayID = igwID
	case infrastructureConfig.Networks.VPC.CIDR != nil:
		vpcCIDR = string(*infrastructureConfig.Networks.VPC.CIDR)
	}

	var zones []map[string]interface{}
	for _, zone := range infrastructureConfig.Networks.Zones {
		zones = append(zones, map[string]interface{}{
			"name":     zone.Name,
			"worker":   zone.Workers,
			"public":   zone.Public,
			"internal": zone.Internal,
		})
	}

	enableECRAccess := true
	if v := infrastructureConfig.EnableECRAccess; v != nil {
		enableECRAccess = *v
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
		"outputKeys": map[string]interface{}{
			"vpcIdKey":                   aws.VPCIDKey,
			"subnetsPublicPrefix":        aws.SubnetPublicPrefix,
			"subnetsNodesPrefix":         aws.SubnetNodesPrefix,
			"securityGroupsNodes":        aws.SecurityGroupsNodes,
			"sshKeyName":                 aws.SSHKeyName,
			"iamInstanceProfileNodes":    aws.IAMInstanceProfileNodes,
			"iamInstanceProfileBastions": aws.IAMInstanceProfileBastions,
			"nodesRole":                  aws.NodesRole,
			"bastionsRole":               aws.BastionsRole,
		},
	}, nil
}

func (a *actuator) updateProviderStatus(ctx context.Context, tf terraformer.Terraformer, infrastructure *extensionsv1alpha1.Infrastructure, infrastructureConfig *awsapi.InfrastructureConfig) error {
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

	output, err := tf.GetStateOutputVariables(outputVarKeys...)
	if err != nil {
		return err
	}

	state, err := tf.GetRawState(ctx)
	if err != nil {
		return err
	}
	stateByte, err := state.Marshal()
	if err != nil {
		return err
	}

	subnets, err := computeProviderStatusSubnets(infrastructureConfig, output)
	if err != nil {
		return err
	}

	return extensionscontroller.TryUpdateStatus(ctx, retry.DefaultBackoff, a.Client(), infrastructure, func() error {
		infrastructure.Status.ProviderStatus = &runtime.RawExtension{
			Object: &awsv1alpha1.InfrastructureStatus{
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
			},
		}
		infrastructure.Status.State = &runtime.RawExtension{Raw: stateByte}
		return nil
	})
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
