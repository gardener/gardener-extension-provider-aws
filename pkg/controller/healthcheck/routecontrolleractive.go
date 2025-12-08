// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package healthcheck

import (
	"context"
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

// routeControllerActiveHealthCheck creates a health check that verifies if the route controller is actively running
func routeControllerActiveHealthCheck(deploymentCheck healthcheck.HealthCheck) healthcheck.HealthCheck {
	return &routeControllerActiveCheck{
		deploymentCheck: deploymentCheck,
	}
}

type routeControllerActiveCheck struct {
	seedClient      client.Client
	logger          logr.Logger
	deploymentCheck healthcheck.HealthCheck
}

var _ healthcheck.HealthCheck = &routeControllerActiveCheck{}

// Check verifies if the route controller is actively running (replicas > 0)
func (hc *routeControllerActiveCheck) Check(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	deployment := &appsv1.Deployment{}
	deploymentName := types.NamespacedName{
		Name:      aws.AWSCustomRouteControllerName,
		Namespace: request.Namespace,
	}
	if err := hc.seedClient.Get(ctx, deploymentName, deployment); err != nil {
		err := fmt.Errorf("failed to get deployment %s: %w", aws.AWSCustomRouteControllerName, err)
		hc.logger.Error(err, "Failed to check if route controller is active")
		return nil, err
	}

	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas == 0 {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: "Route controller is not active (replicas=0)",
		}, nil
	}

	result, err := hc.deploymentCheck.Check(ctx, request)
	if err != nil {
		return nil, err
	}

	if result.Status == gardencorev1beta1.ConditionTrue {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionTrue,
			Detail: "Route controller is active and healthy",
		}, nil
	}

	return result, nil
}

// SetLoggerSuffix sets the logger suffix
func (hc *routeControllerActiveCheck) SetLoggerSuffix(provider, extension string) {
	hc.logger = log.Log.WithName(fmt.Sprintf("%s-healthcheck-route-controller-active", provider))
	hc.deploymentCheck.SetLoggerSuffix(provider, extension)
}

// InjectSeedClient injects the seed client
func (hc *routeControllerActiveCheck) InjectSeedClient(seedClient client.Client) {
	hc.seedClient = seedClient
	if itf, ok := hc.deploymentCheck.(healthcheck.SeedClient); ok {
		itf.InjectSeedClient(seedClient)
	}
}

// InjectShootClient injects the shoot client
func (hc *routeControllerActiveCheck) InjectShootClient(shootClient client.Client) {
	if itf, ok := hc.deploymentCheck.(healthcheck.ShootClient); ok {
		itf.InjectShootClient(shootClient)
	}
}

// DeepCopy creates a deep copy of the health check
func (hc *routeControllerActiveCheck) DeepCopy() healthcheck.HealthCheck {
	return &routeControllerActiveCheck{
		seedClient:      hc.seedClient,
		logger:          hc.logger,
		deploymentCheck: hc.deploymentCheck,
	}
}
