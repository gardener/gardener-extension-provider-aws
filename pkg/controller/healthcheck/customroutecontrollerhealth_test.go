// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package healthcheck_test

import (
	"context"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	chealthcheck "github.com/gardener/gardener-extension-provider-aws/pkg/controller/healthcheck"
)

type fakeHealthCheck struct {
	result *healthcheck.SingleCheckResult
}

func (f fakeHealthCheck) Check(context.Context, types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	return f.result, nil
}

func (f fakeHealthCheck) SetLoggerSuffix(string, string) {
}

var _ = Describe("Healthcheck validations", func() {
	Describe("#CheckEvents", func() {
		var (
			scheme *runtime.Scheme
			now    time.Time
		)
		BeforeEach(func() {
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			now = time.Now()
		})

		It("no events", func() {
			result, err := runHealthCheckWithEvent(nil, scheme)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.Status).To(Equal(gardencorev1beta1.ConditionTrue))
		})

		It("normal event does not affect health", func() {
			event := corev1.Event{
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
			}

			result, err := runHealthCheckWithEvent(&event, scheme)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.Status).To(Equal(gardencorev1beta1.ConditionTrue))
		})

		It("recent warning event causes health check to fail", func() {
			event := corev1.Event{
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
			}

			result, err := runHealthCheckWithEvent(&event, scheme)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.Status).To(Equal(gardencorev1beta1.ConditionFalse))
		})

		It("warning event should be ignored (false-positive case)", func() {
			event := corev1.Event{
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
			}

			result, err := runHealthCheckWithEvent(&event, scheme)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.Status).To(Equal(gardencorev1beta1.ConditionTrue))
		})
	})
})

func runHealthCheckWithEvent(event *corev1.Event, scheme *runtime.Scheme) (*healthcheck.SingleCheckResult, error) {
	objs := []client.Object{}
	if event != nil {
		objs = append(objs, event)
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

	hc := chealthcheck.NewCustomRouteControllerHealthCheck(deploymentCheck)
	hc.InjectShootClient(shootClient)
	hc.Logger = logr.Discard()

	return hc.Check(context.Background(), types.NamespacedName{
		Namespace: metav1.NamespaceSystem,
		Name:      "provider-aws",
	})
}
