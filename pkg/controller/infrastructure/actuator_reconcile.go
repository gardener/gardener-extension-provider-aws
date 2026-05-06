// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"fmt"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

// Reconcile the Infrastructure config.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, infra *extensionsv1alpha1.Infrastructure, cluster *controller.Cluster) error {
	return util.DetermineError(a.reconcile(ctx, log, infra, cluster), helper.KnownCodes)
}

func (a *actuator) reconcile(ctx context.Context, log logr.Logger, infra *extensionsv1alpha1.Infrastructure, cluster *controller.Cluster) error {
	var (
		infraState *awsapi.InfrastructureState
	)

	// when the function is called, we may have: a. no state, b. terraform state (migration) or c. flow state. In case of a TF state
	// because no explicit migration to the new flow format is necessary, we simply return an empty state.
	fsOk, err := helper.HasFlowState(infra.Status)
	if err != nil {
		return err
	}

	if fsOk {
		// if it had a flow state, then we just decode it.
		infraState, err = helper.InfrastructureStateFromRaw(infra.Status.State)
		if err != nil {
			return err
		}
	} else {
		// otherwise migrate it from the terraform state if needed.
		infraState, err = a.migrateFromTerraform(ctx, log, infra, cluster.Shoot.Spec.Networking)
		if err != nil {
			return err
		}
	}
	awsClient, err := aws.NewClientFromSecretRef(ctx, a.client, infra.Spec.SecretRef, infra.Spec.Region)
	if err != nil {
		return fmt.Errorf("failed to create new AWS client: %w", err)
	}

	effectiveSeed := a.resolveEffectiveSeed(ctx, log, cluster)

	// Check if this shoot IS a ManagedSeed by looking up a Seed with the shoot's name.
	// ManagedSeed shoots need special TGW handling: their VPC is the seed VPC for child
	// shoots and must be on hub RT with spoke propagation preserved.
	isManagedSeedShoot := false
	if a.gardenReader != nil {
		candidateSeed := &v1beta1.Seed{}
		if err := a.gardenReader.Get(ctx, client.ObjectKey{Name: cluster.Shoot.Name}, candidateSeed); err == nil {
			isManagedSeedShoot = true
			log.Info("shoot is a ManagedSeed — TGW attachment will use hub RT", "seedName", cluster.Shoot.Name)
		}
	}

	fctx, err := infraflow.NewFlowContext(infraflow.Opts{
		Log:                log,
		Infrastructure:     infra,
		State:              infraState,
		RuntimeClient:      a.client,
		AwsClient:          awsClient,
		Shoot:              cluster.Shoot,
		Seed:               effectiveSeed,
		Recorder:           a.recorder,
		IsManagedSeedShoot: isManagedSeedShoot,
	})
	if err != nil {
		return fmt.Errorf("failed to create flow context: %w", err)
	}

	if err := fctx.Reconcile(ctx); err != nil {
		return err
	}

	// If TGW drift was detected, log it but do NOT return RequeueAfterError.
	//
	// RequeueAfterError causes statusUpdater.Error to mark the Infrastructure (and
	// transitively the Shoot) as Error. For ManagedSeeds, the parent gardenlet's
	// ManagedSeed controller hard-blocks at managedseed/reconciler.go:157 on
	// shoot.LastOperation.State == Succeeded — so an Error shoot prevents the
	// ManagedSeed from ever propagating an updated gardenlet config to the seed
	// cluster, even when the user has already patched the ManagedSeed. The result
	// is a deadlock: the seed's gardenlet keeps reconciling with the OLD config,
	// every reconcile re-detects drift, the Shoot stays Error, the ManagedSeed
	// stays blocked, the gardenlet never gets the new config.
	//
	// Instead, mark the reconcile Succeeded. Phase 1 has already added the target
	// propagation (so routes appear), the attachment stays on its current RT (so
	// connectivity is preserved), and Phase 2 will fire naturally on the next
	// reconcile triggered by ManagedSeed propagation, syncPeriod, or any other
	// shoot's reconcile. Drift is a transient mid-switch state, not an error.
	if fctx.TGWDriftDetected() {
		log.Info("TGW drift detected — Phase 1/2 in progress, will resolve on next reconcile (not erroring to avoid ManagedSeed deadlock)")
	}

	// Fix #3: post-hoc DWD recovery — if assertSeedSideAssociations corrected
	// drift this reconcile, trigger reconciles on every child shoot so their
	// DWD-scaled deployments come back online without waiting for the next 1h
	// sync. Only the seed shoot can correct seed-side drift, so this is
	// effectively gated by isManagedSeedShoot via the helper itself.
	if fctx.DriftCorrectedThisReconcile() && a.gardenWriter != nil && isManagedSeedShoot {
		// context.WithoutCancel detaches from the reconcile's lifetime so the
		// trigger can complete after this reconcile returns, while preserving
		// logger/trace values from the parent context.
		bgCtx := context.WithoutCancel(ctx)
		go func() {
			if err := triggerShootReconciles(bgCtx, a.gardenWriter, cluster.Shoot.Name); err != nil {
				log.Info("post-drift DWD recovery: failed to trigger child shoot reconciles (will rely on next sync)",
					"error", err.Error())
			}
		}()
	}

	return nil
}

func (a *actuator) migrateFromTerraform(ctx context.Context, log logr.Logger, infra *extensionsv1alpha1.Infrastructure, networking *v1beta1.Networking) (*awsapi.InfrastructureState, error) {
	var (
		state = &awsapi.InfrastructureState{
			Data: map[string]string{},
		}
	)
	log.Info("starting terraform state migration")

	// we want to prevent the deletion of Infrastructure CR if there may be still resources in the cloudprovider. We will initialize the data
	// with a specific "marker" so that deletion attempts will not skip the deletion if we are certain that terraform had created infra resources
	// in past reconciliation.
	tf, err := newTerraformer(log, a.restConfig, aws.TerraformerPurposeInfra, infra)
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

	whiteboard := shared.NewWhiteboard()
	if state != nil {
		whiteboard.ImportFromFlatMap(state.Data)
	}
	infrastructureStatus := infraflow.BuildInfrastructureStatus(whiteboard, infrastructureConfig)

	if err := infraflow.PatchProviderStatusAndState(ctx, a.client, infra, networking, infrastructureStatus, &runtime.RawExtension{Object: state}, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("updating status state failed: %w", err)
	}

	return state, nil
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

	// TODO: @hebelsan - remove processedZones after migration of shoots with duplicated zone name entries
	processedZones := sets.New[string]()
	for i, zone := range zones {
		if processedZones.Has(zone.Name) {
			continue
		}
		processedZones.Insert(zone.Name)

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
