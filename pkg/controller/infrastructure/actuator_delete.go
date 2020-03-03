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

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	extensionscontroller "github.com/gardener/gardener-extensions/pkg/controller"
	controllererrors "github.com/gardener/gardener-extensions/pkg/controller/error"
	"github.com/gardener/gardener-extensions/pkg/terraformer"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	glogger "github.com/gardener/gardener/pkg/logger"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Delete(ctx context.Context, infrastructure *extensionsv1alpha1.Infrastructure, _ *extensionscontroller.Cluster) error {
	return Delete(ctx, a.logger, a.RESTConfig(), a.Client(), infrastructure)
}

// Delete deletes the given Infrastructure.
func Delete(
	ctx context.Context,
	logger logr.Logger,
	restConfig *rest.Config,
	c client.Client,
	infrastructure *extensionsv1alpha1.Infrastructure,
) error {
	tf, err := newTerraformer(restConfig, aws.TerraformerPurposeInfra, infrastructure.Namespace, infrastructure.Name)
	if err != nil {
		return fmt.Errorf("could not create the Terraformer: %+v", err)
	}

	// If the Terraform state is empty then we can exit early as we didn't create anything. Though, we clean up potentially
	// created configmaps/secrets related to the Terraformer.
	stateIsEmpty := tf.IsStateEmpty()
	if stateIsEmpty {
		logger.Info("exiting early as infrastructure state is empty - nothing to do")
		return tf.CleanupConfiguration(ctx)
	}

	configExists, err := tf.ConfigExists()
	if err != nil {
		return fmt.Errorf("error while checking whether terraform config exists: %+v", err)
	}

	stateVariables, err := tf.GetStateOutputVariables(aws.VPCIDKey)
	if err != nil {
		if apierrors.IsNotFound(err) || terraformer.IsVariablesNotFoundError(err) {
			logger.Info("Skipping explicit AWS load balancer and security group deletion because not all variables have been found in the Terraform state.")
			return nil
		}
		return err
	}
	vpcID := stateVariables[aws.VPCIDKey]

	credentials, err := aws.GetCredentialsFromSecretRef(ctx, c, infrastructure.Spec.SecretRef)
	if err != nil {
		return err
	}

	awsClient, err := awsclient.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), infrastructure.Spec.Region)
	if err != nil {
		return err
	}

	var (
		g = flow.NewGraph("AWS infrastructure destruction")

		destroyKubernetesLoadBalancersAndSecurityGroups = g.Add(flow.Task{
			Name: "Destroying Kubernetes load balancers and security groups",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if err := destroyKubernetesLoadBalancersAndSecurityGroups(ctx, awsClient, vpcID, infrastructure.Namespace); err != nil {
					return gardencorev1beta1helper.DetermineError(fmt.Sprintf("Failed to destroy load balancers and security groups: %+v", err.Error()))
				}
				return nil
			}).RetryUntilTimeout(10*time.Second, 5*time.Minute).DoIf(configExists && !stateIsEmpty),
		})

		_ = g.Add(flow.Task{
			Name:         "Destroying Shoot infrastructure",
			Fn:           flow.SimpleTaskFn(tf.SetVariablesEnvironment(generateTerraformInfraVariablesEnvironment(credentials)).Destroy),
			Dependencies: flow.NewTaskIDs(destroyKubernetesLoadBalancersAndSecurityGroups),
		})

		f = g.Compile()
	)

	if err := f.Run(flow.Opts{Context: ctx, Logger: glogger.NewFieldLogger(glogger.NewLogger("info"), "infrastructure", infrastructure.Name)}); err != nil {
		return &controllererrors.RequeueAfterError{
			Cause:        flow.Causes(err),
			RequeueAfter: 30 * time.Second,
		}
	}

	return nil
}

func destroyKubernetesLoadBalancersAndSecurityGroups(ctx context.Context, awsClient awsclient.Interface, vpcID, clusterName string) error {
	// first get a list of v1 loadbalancers (Classic)
	loadBalancersV1, err := awsClient.ListKubernetesELBs(ctx, vpcID, clusterName)
	if err != nil {
		return err
	}

	// then get a list of v2 loadbalancers (Network and Application)
	loadBalancersV2, err := awsClient.ListKubernetesELBsV2(ctx, vpcID, clusterName)
	if err != nil {
		return err
	}

	// get a list of security groups to delete
	securityGroups, err := awsClient.ListKubernetesSecurityGroups(ctx, vpcID, clusterName)
	if err != nil {
		return err
	}

	// first delete v1 loadbalancers (Classic)
	for _, loadBalancerName := range loadBalancersV1 {
		if err := awsClient.DeleteELB(ctx, loadBalancerName); err != nil {
			return err
		}
	}

	// then delete v2 loadbalancers (Network and Application)
	for _, loadBalancer := range loadBalancersV2 {
		if loadBalancer.Arn != nil {
			if err := awsClient.DeleteELBV2(ctx, loadBalancer.Arn); err != nil {
				return err
			}
		}
	}

	// finally delete security groups
	for _, securityGroupID := range securityGroups {
		if err := awsClient.DeleteSecurityGroup(ctx, securityGroupID); err != nil {
			return err
		}
	}

	return nil
}
