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
	"time"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Delete(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, _ *extensionscontroller.Cluster) error {
	return Delete(ctx, log, a.RESTConfig(), a.Client(), a.Decoder(), infrastructure, a.disableProjectedTokenMount)
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
		return helper.DetermineError(fmt.Errorf("could not create the Terraformer: %+v", err))
	}

	// terraform pod from previous reconciliation might still be running, ensure they are gone before doing any operations
	if err := tf.EnsureCleanedUp(ctx); err != nil {
		return helper.DetermineError(err)
	}

	// If the Terraform state is empty then we can exit early as we didn't create anything. Though, we clean up potentially
	// created configmaps/secrets related to the Terraformer.
	if tf.IsStateEmpty(ctx) {
		logger.Info("exiting early as infrastructure state is empty - nothing to do")
		if err := tf.CleanupConfiguration(ctx); err != nil {
			return helper.DetermineError(err)
		}
	}

	configExists, err := tf.ConfigExists(ctx)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("error while checking whether terraform config exists: %+v", err))
	}

	awsClient, err := aws.NewClientFromSecretRef(ctx, c, infrastructure.Spec.SecretRef, infrastructure.Spec.Region)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("failed to create new AWS client: %+v", err))
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

				if err := destroyKubernetesLoadBalancersAndSecurityGroups(ctx, awsClient, vpcID, infrastructure.Namespace); err != nil {
					return helper.DetermineError(fmt.Errorf("Failed to destroy load balancers and security groups: %w", err))
				}

				return nil
			}).RetryUntilTimeout(10*time.Second, 5*time.Minute).DoIf(configExists),
		})

		_ = g.Add(flow.Task{
			Name:         "Destroying Shoot infrastructure",
			Fn:           tf.SetEnvVars(generateTerraformerEnvVars(infrastructure.Spec.SecretRef)...).Destroy,
			Dependencies: flow.NewTaskIDs(destroyLoadBalancersAndSecurityGroups),
		})

		f = g.Compile()
	)

	if err := f.Run(ctx, flow.Opts{}); err != nil {
		return helper.DetermineError(flow.Errors(err))
	}

	return nil
}

func destroyKubernetesLoadBalancersAndSecurityGroups(ctx context.Context, awsClient awsclient.Interface, vpcID, clusterName string) error {
	for _, v := range []struct {
		listFn   func(context.Context, string, string) ([]string, error)
		deleteFn func(context.Context, string) error
	}{
		{awsClient.ListKubernetesELBs, awsClient.DeleteELB},
		{awsClient.ListKubernetesELBsV2, awsClient.DeleteELBV2},
		{awsClient.ListKubernetesSecurityGroups, awsClient.DeleteSecurityGroup},
	} {
		results, err := v.listFn(ctx, vpcID, clusterName)
		if err != nil {
			return err
		}

		for _, result := range results {
			if err := v.deleteFn(ctx, result); err != nil {
				return err
			}
		}
	}

	return nil
}
