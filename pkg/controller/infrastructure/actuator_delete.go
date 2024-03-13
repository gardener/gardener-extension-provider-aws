// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"fmt"
	"time"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
)

func (a *actuator) Delete(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, cluster *extensionscontroller.Cluster) error {
	state, err := a.getStateFromInfraStatus(infrastructure)
	if err != nil {
		return err
	}
	if state != nil {
		return a.deleteWithFlow(ctx, log, infrastructure, cluster, state)
	}

	return Delete(ctx, log, a.restConfig, a.client, a.decoder, infrastructure, a.disableProjectedTokenMount)
}

func (a *actuator) ForceDelete(_ context.Context, _ logr.Logger, _ *extensionsv1alpha1.Infrastructure, _ *extensionscontroller.Cluster) error {
	return nil
}

func (a *actuator) deleteWithFlow(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure,
	_ *extensionscontroller.Cluster, oldState *infraflow.PersistentState) error {
	log.Info("deleteWithFlow")

	flowContext, err := a.createFlowContext(ctx, log, infrastructure, oldState)
	if err != nil {
		return err
	}
	if err = flowContext.Delete(ctx); err != nil {
		_ = flowContext.PersistState(ctx, true)
		return util.DetermineError(err, helper.KnownCodes)
	}
	return flowContext.PersistState(ctx, true)
}

// Delete deletes the given Infrastructure.
func Delete(
	ctx context.Context,
	logger logr.Logger,
	restConfig *rest.Config,
	c client.Client,
	decoder runtime.Decoder,
	infrastructure *extensionsv1alpha1.Infrastructure,
	disableProjectedTokenMount bool,
) error {
	infrastructureConfig := &awsapi.InfrastructureConfig{}
	if _, _, err := decoder.Decode(infrastructure.Spec.ProviderConfig.Raw, nil, infrastructureConfig); err != nil {
		// If we cannot decode the provider config, e.g. due to the recently introduced strict mode (see
		// https://github.com/gardener/gardener-extension-provider-aws/pull/307), we don't return here and just log the
		// error message.
		logger.Error(err, "could not decode provider config")
		infrastructureConfig = nil
	}

	tf, err := newTerraformer(logger, restConfig, aws.TerraformerPurposeInfra, infrastructure, disableProjectedTokenMount)
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
		logger.Info("exiting early as infrastructure state is empty - nothing to do")
		return tf.CleanupConfiguration(ctx)
	}

	configExists, err := tf.ConfigExists(ctx)
	if err != nil {
		return fmt.Errorf("error while checking whether terraform config exists: %+v", err)
	}

	awsClient, err := aws.NewClientFromSecretRef(ctx, c, infrastructure.Spec.SecretRef, infrastructure.Spec.Region)
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
					logger.Info("Skipping explicit AWS load balancer and security group deletion because not all variables have been found in the Terraform state.")
					return nil
				}

				if err := infraflow.DestroyKubernetesLoadBalancersAndSecurityGroups(ctx, awsClient, vpcID, infrastructure.Namespace); err != nil {
					return util.DetermineError(fmt.Errorf("failed to destroy load balancers and security groups: %w", err), helper.KnownCodes)
				}

				return nil
			}).RetryUntilTimeout(10*time.Second, 5*time.Minute),
			SkipIf: !configExists,
		})

		_ = g.Add(flow.Task{
			Name:         "Destroying Shoot infrastructure",
			Fn:           tf.SetEnvVars(generateTerraformerEnvVars(infrastructure.Spec.SecretRef)...).Destroy,
			Dependencies: flow.NewTaskIDs(destroyLoadBalancersAndSecurityGroups),
		})

		f = g.Compile()
	)

	if err := f.Run(ctx, flow.Opts{}); err != nil {
		return util.DetermineError(flow.Errors(err), helper.KnownCodes)
	}

	return nil
}
