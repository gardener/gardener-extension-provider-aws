// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CustomRouteControllerHealthCheck is a health check that combines the deployment health check with an event-based check for the aws-custom-route-controller.
type CustomRouteControllerHealthCheck struct {
	ShootClient     client.Client
	Logger          logr.Logger
	deploymentCheck healthcheck.HealthCheck
}

const maxWarningEventAge = 5 * time.Minute

var _ healthcheck.HealthCheck = &CustomRouteControllerHealthCheck{}

// NewCustomRouteControllerHealthCheck creates a new instance of CustomRouteControllerHealthCheck with the provided deployment health check.
func NewCustomRouteControllerHealthCheck(deploymentCheck healthcheck.HealthCheck) *CustomRouteControllerHealthCheck {
	return &CustomRouteControllerHealthCheck{deploymentCheck: deploymentCheck}
}

// Check performs the health check by first checking the deployment and then checking for recent warning events related to the aws-custom-route-controller.
func (hc *CustomRouteControllerHealthCheck) Check(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	result, err := hc.deploymentCheck.Check(ctx, request)
	if err != nil || result.Status != gardencorev1beta1.ConditionTrue {
		return result, err
	}
	return hc.checkEvents(ctx, request)
}

func (hc *CustomRouteControllerHealthCheck) checkEvents(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	list := &corev1.EventList{}
	selector := fields.AndSelectors(fields.OneTermEqualSelector("involvedObject.kind", "ServiceAccount"), fields.OneTermEqualSelector("involvedObject.name", "aws-custom-route-controller"))
	err := hc.ShootClient.List(ctx, list, client.InNamespace(metav1.NamespaceSystem), client.MatchingFieldsSelector{Selector: selector})
	if err != nil {
		err := fmt.Errorf("failed to retrieve events for aws-custom-route-controller in namespace %q: %w", request.Namespace, err)
		hc.Logger.Error(err, "Health check failed")
		return nil, err
	}

	var newestEvent *corev1.Event
	for i := range list.Items {
		event := &list.Items[i]
		if newestEvent == nil || newestEvent.LastTimestamp.Time.Before(event.LastTimestamp.Time) {
			newestEvent = event
		}
	}
	if newestEvent != nil && newestEvent.Type == corev1.EventTypeWarning && time.Since(newestEvent.LastTimestamp.Time) <= maxWarningEventAge {
		var codes []gardencorev1beta1.ErrorCode
		if strings.Contains(newestEvent.Message, "RouteLimitExceeded") {
			codes = append(codes, gardencorev1beta1.ErrorInfraQuotaExceeded)
		} else {
			codes = append(codes, gardencorev1beta1.ErrorRetryableInfraDependencies)
		}

		details := fmt.Sprintf("[aws-custom-route-controller] %s: %s", newestEvent.Reason, newestEvent.Message)
		hc.Logger.Error(errors.New(details), "Health check failed")
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

// SetLoggerSuffix sets the logger suffix for the health check and also updates the logger suffix of the underlying deployment health check if it implements the same interface.
func (hc *CustomRouteControllerHealthCheck) SetLoggerSuffix(provider, extension string) {
	hc.Logger = log.Log.WithName(fmt.Sprintf("%s-healthcheck-custom-route-controller", provider))
	hc.deploymentCheck.SetLoggerSuffix(provider, extension)
}

// InjectSeedClient injects the seed client
func (hc *CustomRouteControllerHealthCheck) InjectSeedClient(seedClient client.Client) {
	if itf, ok := hc.deploymentCheck.(healthcheck.SeedClient); ok {
		itf.InjectSeedClient(seedClient)
	}
}

// InjectShootClient injects the shoot client
func (hc *CustomRouteControllerHealthCheck) InjectShootClient(shootClient client.Client) {
	if itf, ok := hc.deploymentCheck.(healthcheck.ShootClient); ok {
		itf.InjectShootClient(shootClient)
	}
	hc.ShootClient = shootClient
}
