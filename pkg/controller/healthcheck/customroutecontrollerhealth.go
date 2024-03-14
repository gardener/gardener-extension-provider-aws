// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type customRouteControllerHealthCheck struct {
	shootClient     client.Client
	logger          logr.Logger
	deploymentCheck healthcheck.HealthCheck
}

var _ healthcheck.HealthCheck = &customRouteControllerHealthCheck{}

func newCustomRouteControllerHealthCheck(deploymentCheck healthcheck.HealthCheck) *customRouteControllerHealthCheck {
	return &customRouteControllerHealthCheck{deploymentCheck: deploymentCheck}
}

func (hc *customRouteControllerHealthCheck) Check(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	result, err := hc.deploymentCheck.Check(ctx, request)
	if err != nil || result.Status != gardencorev1beta1.ConditionTrue {
		return result, err
	}
	return hc.checkEvents(ctx, request)
}

func (hc *customRouteControllerHealthCheck) checkEvents(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	list := &v1.EventList{}
	selector := fields.AndSelectors(fields.OneTermEqualSelector("involvedObject.kind", "ServiceAccount"), fields.OneTermEqualSelector("involvedObject.name", "aws-custom-route-controller"))
	err := hc.shootClient.List(ctx, list, client.InNamespace(metav1.NamespaceSystem), client.MatchingFieldsSelector{Selector: selector})
	if err != nil {
		err := fmt.Errorf("failed to retrieve events for aws-custom-route-controller in namespace %q: %w", request.Namespace, err)
		hc.logger.Error(err, "Health check failed")
		return nil, err
	}

	var newestEvent *v1.Event
	for i := range list.Items {
		event := &list.Items[i]
		if newestEvent == nil || newestEvent.LastTimestamp.Time.Before(event.LastTimestamp.Time) {
			newestEvent = event
		}
	}
	if newestEvent != nil && newestEvent.Type == v1.EventTypeWarning {
		var codes []gardencorev1beta1.ErrorCode
		if strings.Contains(newestEvent.Message, "RouteLimitExceeded") {
			codes = append(codes, gardencorev1beta1.ErrorInfraQuotaExceeded)
		} else {
			codes = append(codes, gardencorev1beta1.ErrorRetryableInfraDependencies)
		}

		details := fmt.Sprintf("[aws-custom-route-controller] %s: %s", newestEvent.Reason, newestEvent.Message)
		hc.logger.Error(errors.New(details), "Health check failed")
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: details,
			Codes:  codes,
		}, nil
	}

	return &healthcheck.SingleCheckResult{
		Status: gardencorev1beta1.ConditionTrue,
	}, nil
}

func (hc *customRouteControllerHealthCheck) SetLoggerSuffix(provider, extension string) {
	hc.logger = log.Log.WithName(fmt.Sprintf("%s-healthcheck-custom-route-controller", provider))
	hc.deploymentCheck.SetLoggerSuffix(provider, extension)
}

// DeepCopy clones the healthCheck
func (hc *customRouteControllerHealthCheck) DeepCopy() healthcheck.HealthCheck {
	return &customRouteControllerHealthCheck{
		deploymentCheck: hc.deploymentCheck.DeepCopy(),
		shootClient:     hc.shootClient,
	}
}

// InjectSeedClient injects the seed client
func (hc *customRouteControllerHealthCheck) InjectSeedClient(seedClient client.Client) {
	if itf, ok := hc.deploymentCheck.(healthcheck.SeedClient); ok {
		itf.InjectSeedClient(seedClient)
	}
}

// InjectShootClient injects the shoot client
func (hc *customRouteControllerHealthCheck) InjectShootClient(shootClient client.Client) {
	if itf, ok := hc.deploymentCheck.(healthcheck.ShootClient); ok {
		itf.InjectShootClient(shootClient)
	}
	hc.shootClient = shootClient
}
