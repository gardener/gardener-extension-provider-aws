package healthcheck

import (
	"context"
	"testing"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type fakeHealthCheck struct {
	result *healthcheck.SingleCheckResult
}

func (f fakeHealthCheck) Check(context.Context, types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	return f.result, nil
}

func (f fakeHealthCheck) SetLoggerSuffix(string, string) {
}

func TestCustomRouteControllerHealthCheck_CheckEvents(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	now := time.Now()

	tests := []struct {
		name           string
		events         []corev1.Event
		expectedStatus gardencorev1beta1.ConditionStatus
	}{
		{
			name:           "no events",
			events:         nil,
			expectedStatus: gardencorev1beta1.ConditionTrue,
		},
		{
			name: "recent warning event causes health check to fail",
			events: []corev1.Event{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "recent-warning",
						Namespace: metav1.NamespaceSystem,
					},
					InvolvedObject: corev1.ObjectReference{
						Kind: "ServiceAccount",
						Name: "aws-custom-route-controller",
					},
					Type:          corev1.EventTypeWarning,
					Reason:        "RoutesUpdateFailed",
					Message:       "temporary aws error",
					LastTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
				},
			},
			expectedStatus: gardencorev1beta1.ConditionFalse,
		},
		{
			name: "old warning event should be ignored (false-positive case)",
			events: []corev1.Event{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "old-warning",
						Namespace: metav1.NamespaceSystem,
					},
					InvolvedObject: corev1.ObjectReference{
						Kind: "ServiceAccount",
						Name: "aws-custom-route-controller",
					},
					Type:          corev1.EventTypeWarning,
					Reason:        "RoutesUpdateFailed",
					Message:       "instance shutting down",
					LastTimestamp: metav1.NewTime(now.Add(-50 * time.Minute)),
				},
			},
			expectedStatus: gardencorev1beta1.ConditionTrue,
		},
		{
			name: "normal event does not affect health",
			events: []corev1.Event{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "normal-event",
						Namespace: metav1.NamespaceSystem,
					},
					InvolvedObject: corev1.ObjectReference{
						Kind: "ServiceAccount",
						Name: "aws-custom-route-controller",
					},
					Type:          corev1.EventTypeNormal,
					Reason:        "RoutesUpdated",
					Message:       "routes updated successfully",
					LastTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
				},
			},
			expectedStatus: gardencorev1beta1.ConditionTrue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{}
			for i := range tt.events {
				objs = append(objs, &tt.events[i])
			}

			builder := fake.NewClientBuilder().
				WithScheme(scheme).
				WithIndex(&corev1.Event{}, "involvedObject.kind", func(obj client.Object) []string {
					return []string{obj.(*corev1.Event).InvolvedObject.Kind}
				}).
				WithIndex(&corev1.Event{}, "involvedObject.name", func(obj client.Object) []string {
					return []string{obj.(*corev1.Event).InvolvedObject.Name}
				})

			shootClient := builder.
				WithObjects(objs...).
				Build()

			deploymentCheck := &fakeHealthCheck{
				result: &healthcheck.SingleCheckResult{
					Status: gardencorev1beta1.ConditionTrue,
				},
			}

			hc := newCustomRouteControllerHealthCheck(deploymentCheck)
			hc.InjectShootClient(shootClient)
			hc.logger = logr.Discard()

			result, err := hc.Check(ctx, types.NamespacedName{
				Namespace: metav1.NamespaceSystem,
				Name:      "provider-aws",
			})

			require.NoError(t, err)
			require.Equal(t, tt.expectedStatus, result.Status)
		})
	}
}
