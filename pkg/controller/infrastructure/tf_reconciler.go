// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
//

package infrastructure

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
)

// TerraformReconciler can manage infrastructure resources using Terraformer.
type TerraformReconciler struct {
	client                     k8sClient.Client
	restConfig                 *rest.Config
	log                        logr.Logger
	disableProjectedTokenMount bool
}

// NewTerraformReconciler returns a new instance of TerraformReconciler.
func NewTerraformReconciler(client k8sClient.Client, restConfig *rest.Config, log logr.Logger, disableProjectedTokenMount bool) *TerraformReconciler {
	return &TerraformReconciler{
		client:                     client,
		restConfig:                 restConfig,
		log:                        log,
		disableProjectedTokenMount: disableProjectedTokenMount,
	}
}

// Reconcile reconciles infrastructure using Terraformer.
func (t *TerraformReconciler) Reconcile(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, cluster *controller.Cluster) error {
	err := t.reconcile(ctx, infra, cluster, terraformer.StateConfigMapInitializerFunc(terraformer.CreateState))
	return util.DetermineError(err, helper.KnownCodes)
}

func (t *TerraformReconciler) reconcile(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, c *controller.Cluster, initializer terraformer.StateConfigMapInitializer) error {
	log := t.log

	log.Info("reconcile infrastructure using terraform reconciler")

	infrastructureConfig, err := helper.InfrastructureConfigFromInfrastructure(infra)
	if err != nil {
		return err
	}

	awsClient, err := aws.NewClientFromSecretRef(ctx, t.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return fmt.Errorf("failed to create new AWS client: %+v", err)
	}

	var ipfamilies []v1beta1.IPFamily
	if c.Shoot.Spec.Networking != nil {
		ipfamilies = c.Shoot.Spec.Networking.IPFamilies
	} else {
		ipfamilies = []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}
	}

	terraformConfig, err := generateTerraformInfraConfig(ctx, infra, infrastructureConfig, awsClient, ipfamilies)
	if err != nil {
		return fmt.Errorf("failed to generate Terraform config: %+v", err)
	}

	var mainTF bytes.Buffer
	if err := tplMainTF.Execute(&mainTF, terraformConfig); err != nil {
		return fmt.Errorf("could not render Terraform template: %+v", err)
	}

	tf, err := newTerraformer(t.log, t.restConfig, aws.TerraformerPurposeInfra, infra, t.disableProjectedTokenMount)
	if err != nil {
		return fmt.Errorf("could not create terraformer object: %+v", err)
	}

	if err := tf.
		SetEnvVars(generateTerraformerEnvVars(infra.Spec.SecretRef)...).
		InitializeWith(
			ctx,
			terraformer.DefaultInitializer(
				t.client,
				mainTF.String(),
				variablesTF,
				[]byte(terraformTFVars),
				initializer,
			)).
		Apply(ctx); err != nil {

		return fmt.Errorf("failed to apply the terraform config: %w", err)
	}

	status, state, err := t.computeTerraformStatusState(ctx, tf, infrastructureConfig)
	if err != nil {
		return err
	}

	var stateBytes []byte
	if state != nil {
		var err error
		stateBytes, err = state.Marshal()
		if err != nil {
			return err
		}
	}

	// For the TF reconciler, we will compute the NAT Gateway IPs using an external call. If the credentials were incorrect,
	// or another error prevented a successful terraformer run, the error would report before the updateProviderStatusTf.
	// Hence, we can freely make the external API call to get the NAT Gateways here.
	egressCIDRs, err := t.computeEgressCIDRs(ctx, infra)
	if err != nil {
		return err
	}

	if slices.Contains(ipfamilies, v1beta1.IPFamilyIPv6) {
		vpcIPv6CIDR, err := t.computeVPCIPv6CIDR(ctx, infra)
		if err != nil {
			return err
		}
		ipV6ServiceCIDR, err := t.computeIPv6ServiceCIDR(ctx, infra)
		if err != nil {
			return err
		}
		return infraflow.PatchProviderStatusAndState(ctx, t.client, infra, c.Shoot.Spec.Networking, status, &runtime.RawExtension{Raw: stateBytes}, egressCIDRs, &vpcIPv6CIDR, &ipV6ServiceCIDR)
	}
	return infraflow.PatchProviderStatusAndState(ctx, t.client, infra, c.Shoot.Spec.Networking, status, &runtime.RawExtension{Raw: stateBytes}, egressCIDRs, nil, nil)
}

// Delete deletes the infrastructure using Terraformer.
func (t *TerraformReconciler) Delete(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, c *extensions.Cluster) error {
	return util.DetermineError(t.delete(ctx, infra, c), helper.KnownCodes)
}

func (t *TerraformReconciler) getVPCID(ctx context.Context, infra *extensionsv1alpha1.Infrastructure) (string, error) {
	infrastructureConfig, err := helper.InfrastructureConfigFromInfrastructure(infra)
	var vpcID string
	if err != nil {
		return "", err
	}

	tf, err := newTerraformer(t.log, t.restConfig, aws.TerraformerPurposeInfra, infra, t.disableProjectedTokenMount)
	if err != nil {
		return "", util.DetermineError(fmt.Errorf("could not create the Terraformer: %+v", err), helper.KnownCodes)
	}

	if infrastructureConfig != nil && infrastructureConfig.Networks.VPC.ID != nil {
		vpcID = *infrastructureConfig.Networks.VPC.ID
	} else {
		stateVariables, err := tf.GetStateOutputVariables(ctx, aws.VPCIDKey)
		if err == nil {
			vpcID = stateVariables[aws.VPCIDKey]
		} else if !apierrors.IsNotFound(err) && !terraformer.IsVariablesNotFoundError(err) {
			return "", err
		}
	}
	return vpcID, nil
}

func (t *TerraformReconciler) delete(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, _ *extensions.Cluster) error {
	infrastructureConfig, err := helper.InfrastructureConfigFromInfrastructure(infra)
	if err != nil {
		return err
	}

	tf, err := newTerraformer(t.log, t.restConfig, aws.TerraformerPurposeInfra, infra, t.disableProjectedTokenMount)
	if err != nil {
		return util.DetermineError(fmt.Errorf("could not create the Terraformer: %+v", err), helper.KnownCodes)
	}

	// terraform pod from previous reconciliation might still be running, ensure they are gone before doing any operations
	if err := tf.EnsureCleanedUp(ctx); err != nil {
		return err
	}

	// If the Terraform state is empty then we can exit early as we didn't create anything. Though, we clean up potentially
	// created configmaps/secrets related to the Terraformer.
	if tf.IsStateEmpty(ctx) {
		t.log.Info("exiting early as infrastructure state is empty - nothing to do")
		return tf.CleanupConfiguration(ctx)
	}

	configExists, err := tf.ConfigExists(ctx)
	if err != nil {
		return fmt.Errorf("error while checking whether terraform config exists: %+v", err)
	}

	awsClient, err := aws.NewClientFromSecretRef(ctx, t.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return util.DetermineError(fmt.Errorf("failed to create new AWS client: %+v", err), helper.KnownCodes)
	}

	var (
		g = flow.NewGraph("AWS infrastructure destruction")

		destroyLoadBalancersAndSecurityGroups = g.Add(flow.Task{
			Name: "Destroying Kubernetes load balancers and security groups",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				var vpcID string

				if infrastructureConfig != nil && infrastructureConfig.Networks.VPC.ID != nil {
					vpcID = *infrastructureConfig.Networks.VPC.ID
				} else {
					stateVariables, err := tf.GetStateOutputVariables(ctx, aws.VPCIDKey)
					if err == nil {
						vpcID = stateVariables[aws.VPCIDKey]
					} else if !apierrors.IsNotFound(err) && !terraformer.IsVariablesNotFoundError(err) {
						return err
					}
				}

				if len(vpcID) == 0 {
					t.log.Info("Skipping explicit AWS load balancer and security group deletion because not all variables have been found in the Terraform state.")
					return nil
				}

				if err := infraflow.DestroyKubernetesLoadBalancersAndSecurityGroups(ctx, awsClient, vpcID, infra.Namespace); err != nil {
					return util.DetermineError(fmt.Errorf("failed to destroy load balancers and security groups: %w", err), helper.KnownCodes)
				}

				return nil
			}).RetryUntilTimeout(10*time.Second, 5*time.Minute),
			SkipIf: !configExists,
		})

		_ = g.Add(flow.Task{
			Name:         "Destroying Shoot infrastructure",
			Fn:           tf.SetEnvVars(generateTerraformerEnvVars(infra.Spec.SecretRef)...).Destroy,
			Dependencies: flow.NewTaskIDs(destroyLoadBalancersAndSecurityGroups),
		})

		f = g.Compile()
	)

	return f.Run(ctx, flow.Opts{Log: t.log})
}

// Restore restores the infrastructure after a control plane migration. Effectively it performs a recovery of data from the infrastructure.status.state and
// proceeds to reconcile.
func (t *TerraformReconciler) Restore(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, cluster *controller.Cluster) error {
	var initializer terraformer.StateConfigMapInitializer

	terraformState, err := terraformer.UnmarshalRawState(infra.Status.State)
	if err != nil {
		return err
	}

	initializer = terraformer.CreateOrUpdateState{State: &terraformState.Data}
	return t.reconcile(ctx, infra, cluster, initializer)
}

func (t *TerraformReconciler) computeTerraformStatusState(ctx context.Context, tf terraformer.Terraformer, infrastructureConfig *api.InfrastructureConfig) (*v1alpha1.InfrastructureStatus, *terraformer.RawState, error) {
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

	infrastructureStatus := &v1alpha1.InfrastructureStatus{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
			Kind:       "InfrastructureStatus",
		},
		VPC: v1alpha1.VPCStatus{
			ID:      output[aws.VPCIDKey],
			Subnets: subnets,
			SecurityGroups: []v1alpha1.SecurityGroup{
				{
					Purpose: api.PurposeNodes,
					ID:      output[aws.SecurityGroupsNodes],
				},
			},
		},
		IAM: v1alpha1.IAM{
			InstanceProfiles: []v1alpha1.InstanceProfile{
				{
					Purpose: api.PurposeNodes,
					Name:    output[aws.IAMInstanceProfileNodes],
				},
			},
			Roles: []v1alpha1.Role{
				{
					Purpose: api.PurposeNodes,
					ARN:     output[aws.NodesRole],
				},
			},
		},
	}

	if keyName, ok := output[aws.SSHKeyName]; ok {
		infrastructureStatus.EC2 = v1alpha1.EC2{
			KeyName: keyName,
		}
	}

	return infrastructureStatus, state, nil
}

func (t *TerraformReconciler) computeEgressCIDRs(ctx context.Context, infra *extensionsv1alpha1.Infrastructure) ([]string, error) {
	awsClient, err := aws.NewClientFromSecretRef(ctx, t.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AWS client: %w", err)
	}

	var egressIPs []string
	nats, err := awsClient.FindNATGatewaysByTags(ctx, map[string]string{
		fmt.Sprintf(infraflow.TagKeyClusterTemplate, infra.Namespace): infraflow.TagValueCluster,
	})
	if err != nil {
		return nil, err
	}
	for _, nat := range nats {
		egressIPs = append(egressIPs, fmt.Sprintf("%s/32", nat.PublicIP))
	}
	return egressIPs, nil
}

func (t *TerraformReconciler) computeVPCIPv6CIDR(ctx context.Context, infra *extensionsv1alpha1.Infrastructure) (string, error) {
	awsClient, err := aws.NewClientFromSecretRef(ctx, t.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return "", fmt.Errorf("failed to create new AWS client: %w", err)
	}
	vpcID, err := t.getVPCID(ctx, infra)
	if err != nil {
		return "", err
	}
	return awsClient.GetIPv6Cidr(ctx, vpcID)
}

func (t *TerraformReconciler) computeIPv6ServiceCIDR(ctx context.Context, infra *extensionsv1alpha1.Infrastructure) (string, error) {

	awsClient, err := aws.NewClientFromSecretRef(ctx, t.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return "", fmt.Errorf("failed to create new AWS client: %w", err)
	}
	vpcID, err := t.getVPCID(ctx, infra)
	if err != nil {
		return "", err
	}
	subnets, err := awsClient.FindSubnets(ctx, awsclient.WithFilters().WithVpcId(vpcID).WithTags(map[string]string{
		fmt.Sprintf(infraflow.TagKeyClusterTemplate, infra.Namespace): infraflow.TagValueCluster,
	}).Build())
	if err != nil {
		return "", err
	}

	var cidrs []string
	for _, subnet := range subnets {
		subnetCIDRS, err := awsClient.GetIPv6CIDRReservations(ctx, subnet)
		if err != nil {
			return "", err
		}
		cidrs = append(cidrs, subnetCIDRS...)
	}
	if len(cidrs) != 1 {
		return "", fmt.Errorf("unexpected number of CIDR reservations")
	}
	return cidrs[0], nil
}

func generateTerraformInfraConfig(ctx context.Context, infrastructure *extensionsv1alpha1.Infrastructure, infrastructureConfig *api.InfrastructureConfig, awsClient awsclient.Interface, ipFamilies []v1beta1.IPFamily) (map[string]interface{}, error) {
	var (
		dhcpDomainName              = "ec2.internal"
		createVPC                   = true
		vpcID                       = "aws_vpc.vpc.id"
		vpcCIDR                     = ""
		internetGatewayID           = "aws_internet_gateway.igw.id"
		egressOnlyInternetGatewayID = "aws_egress_only_internet_gateway.egw.id"
		ipv6CidrBlock               = "aws_vpc.vpc.ipv6_cidr_block"

		ignoreTagKeys        []string
		ignoreTagKeyPrefixes []string
	)

	if infrastructure.Spec.Region != "us-east-1" {
		dhcpDomainName = fmt.Sprintf("%s.compute.internal", infrastructure.Spec.Region)
	}

	isIPv4 := true
	isIPv6 := false
	if slices.Contains(ipFamilies, v1beta1.IPFamilyIPv6) {
		isIPv4 = false
		isIPv6 = true
	}

	enableDualStack := false
	if infrastructureConfig.DualStack != nil && !isIPv6 {
		enableDualStack = infrastructureConfig.DualStack.Enabled
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
		if isIPv6 {
			eogw, err := awsClient.FindEgressOnlyInternetGatewayByVPC(ctx, existingVpcID)
			if err != nil || eogw == nil {
				return nil, fmt.Errorf("Egress-Only Internet Gateway not found for VPC %s", existingVpcID)
			}
			existingEgressOnlyInternetGatewayID := eogw.EgressOnlyInternetGatewayId
			egressOnlyInternetGatewayID = strconv.Quote(existingEgressOnlyInternetGatewayID)
		}
		// if dual stack is enabled or ipFamily is IPv6, then we wait until the target VPC has a ipv6 CIDR assigned.
		if enableDualStack || isIPv6 {
			existingIPv6CidrBlock, err := awsClient.WaitForIPv6Cidr(ctx, existingVpcID)
			if err != nil {
				return nil, err
			}
			ipv6CidrBlock = strconv.Quote(existingIPv6CidrBlock)
		}

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
		"isIPv4":          isIPv4,
		"isIPv6":          isIPv6,
		"dualStack": map[string]interface{}{
			"enabled": enableDualStack,
		},
		"sshPublicKey": string(infrastructure.Spec.SSHPublicKey),
		"vpc": map[string]interface{}{
			"id":                          vpcID,
			"cidr":                        vpcCIDR,
			"dhcpDomainName":              dhcpDomainName,
			"internetGatewayID":           internetGatewayID,
			"egressOnlyInternetGatewayID": egressOnlyInternetGatewayID,
			"gatewayEndpoints":            infrastructureConfig.Networks.VPC.GatewayEndpoints,
			"ipv6CidrBlock":               ipv6CidrBlock,
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

func computeProviderStatusSubnets(infrastructure *api.InfrastructureConfig, values map[string]string) ([]v1alpha1.Subnet, error) {
	var subnetsToReturn []v1alpha1.Subnet

	for key, value := range values {
		var prefix, purpose string
		if strings.HasPrefix(key, aws.SubnetPublicPrefix) {
			prefix = aws.SubnetPublicPrefix
			purpose = api.PurposePublic
		}
		if strings.HasPrefix(key, aws.SubnetNodesPrefix) {
			prefix = aws.SubnetNodesPrefix
			purpose = v1alpha1.PurposeNodes
		}

		if len(prefix) == 0 {
			continue
		}

		zoneID, err := strconv.Atoi(strings.TrimPrefix(key, prefix))
		if err != nil {
			return nil, err
		}
		subnetsToReturn = append(subnetsToReturn, v1alpha1.Subnet{
			ID:      value,
			Purpose: purpose,
			Zone:    infrastructure.Networks.Zones[zoneID].Name,
		})
	}

	return subnetsToReturn, nil
}
