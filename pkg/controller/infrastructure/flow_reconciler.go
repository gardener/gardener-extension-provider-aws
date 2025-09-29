package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

// FlowReconciler an implementation of an infrastructure reconciler using native SDKs.
type FlowReconciler struct {
	client                     client.Client
	restConfig                 *rest.Config
	log                        logr.Logger
	disableProjectedTokenMount bool
}

// NewFlowReconciler creates a new flow reconciler.
func NewFlowReconciler(client client.Client, restConfig *rest.Config, log logr.Logger, projToken bool) Reconciler {
	return &FlowReconciler{
		client:                     client,
		restConfig:                 restConfig,
		log:                        log,
		disableProjectedTokenMount: projToken,
	}
}

// Reconcile reconciles the infrastructure and updates the Infrastructure status (state of the world), the state (input for the next loops) or reports any errors that occurred.
func (f *FlowReconciler) Reconcile(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, c *controller.Cluster) error {
	var (
		infraState *awsapi.InfrastructureState
	)

	// when the function is called, we may have: a. no state, b. terraform state (migration) or c. flow state. In case of a TF state
	// because no explicit migration to the new flow format is necessary, we simply return an empty state.
	fsOk, err := hasFlowState(infra.Status.State)
	if err != nil {
		return err
	}

	if fsOk {
		// if it had a flow state, then we just decode it.
		infraState, err = f.infrastructureStateFromRaw(infra)
		if err != nil {
			return err
		}
	} else {
		// otherwise migrate it from the terraform state if needed.
		infraState, err = f.migrateFromTerraform(ctx, infra, c.Shoot.Spec.Networking)
		if err != nil {
			return err
		}
	}

	awsClient, err := aws.NewClientFromSecretRef(ctx, f.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return fmt.Errorf("failed to create new AWS client: %w", err)
	}

	fctx, err := infraflow.NewFlowContext(infraflow.Opts{
		Log:            f.log,
		Infrastructure: infra,
		State:          infraState,
		RuntimeClient:  f.client,
		AwsClient:      awsClient,
		Shoot:          c.Shoot,
	})
	if err != nil {
		return fmt.Errorf("failed to create flow context: %w", err)
	}

	return fctx.Reconcile(ctx)
}

// Delete deletes the infrastructure resource using the flow reconciler.
func (f *FlowReconciler) Delete(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, c *controller.Cluster) error {
	f.log.V(1).Info("deleteWithFlow")

	awsClient, err := aws.NewClientFromSecretRef(ctx, f.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return fmt.Errorf("failed to create new AWS client: %w", err)
	}

	infraState, err := f.infrastructureStateFromRaw(infra)
	if err != nil {
		return err
	}

	fctx, err := infraflow.NewFlowContext(infraflow.Opts{
		Log:            f.log,
		Infrastructure: infra,
		State:          infraState,
		AwsClient:      awsClient,
		RuntimeClient:  f.client,
		Shoot:          c.Shoot,
	})
	if err != nil {
		return fmt.Errorf("failed to create flow context: %w", err)
	}
	err = fctx.Delete(ctx)
	if err != nil {
		return err
	}

	tf, err := newTerraformer(f.log, f.restConfig, aws.TerraformerPurposeInfra, infra, f.disableProjectedTokenMount)
	if err != nil {
		return err
	}
	// TODO optimisation: check if cleanup is necessary
	return CleanupTerraformerResources(ctx, tf)
}

// Restore implements the restoration of an infrastructure resource during the control plane migration.
func (f *FlowReconciler) Restore(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, cluster *controller.Cluster) error {
	return f.Reconcile(ctx, infra, cluster)
}

func (f *FlowReconciler) infrastructureStateFromRaw(infra *extensionsv1alpha1.Infrastructure) (*awsapi.InfrastructureState, error) {
	state := &awsapi.InfrastructureState{}
	raw := infra.Status.State

	if raw != nil {
		jsonBytes, err := raw.MarshalJSON()
		if err != nil {
			return nil, err
		}

		// todo(ka): for now we won't use the actuator decoder because the flow state kind was registered as "FlowState" and not "InfrastructureState". So we
		// shall use the simple json unmarshal for this release.
		if err := json.Unmarshal(jsonBytes, state); err != nil {
			return nil, err
		}
	}

	return state, nil
}

func (f *FlowReconciler) migrateFromTerraform(ctx context.Context, infra *extensionsv1alpha1.Infrastructure, networking *v1beta1.Networking) (*awsapi.InfrastructureState, error) {
	var (
		state = &awsapi.InfrastructureState{
			Data: map[string]string{},
		}
	)
	f.log.Info("starting terraform state migration")

	// we want to prevent the deletion of Infrastructure CR if there may be still resources in the cloudprovider. We will initialize the data
	// with a specific "marker" so that deletion attempts will not skip the deletion if we are certain that terraform had created infra resources
	// in past reconciliation.
	tf, err := newTerraformer(f.log, f.restConfig, aws.TerraformerPurposeInfra, infra, f.disableProjectedTokenMount)
	if err != nil {
		return nil, err
	}

	// nothing to do if state is empty
	if tf.IsStateEmpty(ctx) {
		return state, nil
	}

	// migrate state
	infrastructureConfig, err := helper.InfrastructureConfigFromInfrastructure(infra)
	if err != nil {
		return nil, err
	}
	state, err = migrateTerraformStateToFlowState(infra.Status.State, infrastructureConfig.Networks.Zones)
	if err != nil {
		return nil, fmt.Errorf("migration from terraform state failed: %w", err)
	}

	// TODO duplication of computeProviderStatusFromFlowState and fctx.computeInfrastructureStatus
	infrastructureStatus := computeProviderStatusFromFlowState(infrastructureConfig, state)

	if err := infraflow.PatchProviderStatusAndState(ctx, f.client, infra, networking, infrastructureStatus, &runtime.RawExtension{Object: state}, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("updating status state failed: %w", err)
	}

	return state, nil
}

func computeProviderStatusFromFlowState(config *awsapi.InfrastructureConfig, state *awsapi.InfrastructureState) *awsv1alpha1.InfrastructureStatus {
	if len(state.Data) == 0 {
		return nil
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

	return status
}

func migrateTerraformStateToFlowState(rawExtension *runtime.RawExtension, zones []awsapi.Zone) (*awsapi.InfrastructureState, error) {
	var (
		flowState = &awsapi.InfrastructureState{
			Data: map[string]string{},
		}
		tfRawState *terraformer.RawState
		tfState    *shared.TerraformState
		err        error
	)

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
	setFlowStateData(flowState, infraflow.IdentifierEgressOnlyInternetGateway,
		tfState.GetManagedResourceInstanceID("aws_egress_only_internet_gateway", "egw"))
	setFlowStateData(flowState, infraflow.IdentifierNodesSecurityGroup,
		tfState.GetManagedResourceInstanceID("aws_security_group", "nodes"))

	if instances := tfState.GetManagedResourceInstances("aws_vpc_endpoint"); len(instances) > 0 {
		for name, id := range instances {
			key := infraflow.ChildIdVPCEndpoints + shared.Separator + strings.TrimPrefix(name, "vpc_gwep_")
			setFlowStateData(flowState, key, &id)
		}
	}

	tfNamePrefixes := []string{"nodes_", "private_utility_", "public_utility_"}
	flowNames := []string{infraflow.IdentifierZoneSubnetWorkers, infraflow.IdentifierZoneSubnetPrivate, infraflow.IdentifierZoneSubnetPublic}

	processedZones := make(map[string]bool)
	for i, zone := range zones {
		if processedZones[zone.Name] {
			continue
		}
		processedZones[zone.Name] = true

		keyPrefix := infraflow.ChildIdZones + shared.Separator + zone.Name + shared.Separator
		suffix := fmt.Sprintf("z%d", i)
		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierZoneSuffix, &suffix)

		for j := 0; j < len(tfNamePrefixes); j++ {
			setFlowStateData(flowState, keyPrefix+flowNames[j],
				tfState.GetManagedResourceInstanceID("aws_subnet", tfNamePrefixes[j]+suffix))
		}
		setFlowStateData(flowState, keyPrefix+infraflow.IdentifierManagedZoneNATGWElasticIP,
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

	setFlowStateData(flowState, infraflow.MarkerMigratedFromTerraform, ptr.To("true"))

	return flowState, nil
}

func setFlowStateData(state *awsapi.InfrastructureState, key string, id *string) {
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
