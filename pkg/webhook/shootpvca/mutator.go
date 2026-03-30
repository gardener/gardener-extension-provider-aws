// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootpvca

import (
	"context"
	"fmt"
	"time"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	pvcautoscalingv1alpha1 "github.com/gardener/pvc-autoscaler/api/autoscaling/v1alpha1"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var defaultCooldownDuration = &metav1.Duration{Duration: 6 * time.Hour}

type mutator struct {
	logger logr.Logger
}

// NewMutator creates a new Mutator that mutates resources in the shoot cluster.
func NewMutator(logger logr.Logger) extensionswebhook.Mutator {
	return &mutator{logger: logger}
}

// Mutate mutates PersistentVolumeClaimAutoscaler resources by defaulting cooldownDuration.
func (m *mutator) Mutate(_ context.Context, newObj, _ client.Object) error {
	pvca, ok := newObj.(*pvcautoscalingv1alpha1.PersistentVolumeClaimAutoscaler)
	if !ok {
		return fmt.Errorf("could not mutate: object is not of type PersistentVolumeClaimAutoscaler")
	}

	extensionswebhook.LogMutation(m.logger, "PersistentVolumeClaimAutoscaler", pvca.GetNamespace(), pvca.GetName())

	for i := range pvca.Spec.VolumePolicies {
		if pvca.Spec.VolumePolicies[i].ScaleUp != nil &&
			pvca.Spec.VolumePolicies[i].ScaleUp.CooldownDuration == nil {
			pvca.Spec.VolumePolicies[i].ScaleUp.CooldownDuration = defaultCooldownDuration.DeepCopy()
		}
	}

	return nil
}
