// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pvca

import (
	"context"
	"time"

	pvcautoscalingv1alpha1 "github.com/gardener/pvc-autoscaler/api/autoscaling/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Mutator", func() {
	var (
		mutator = NewMutator(log.Log.WithName("test"))
	)

	It("should default cooldownDuration to 6h when missing", func() {
		threshold := 80
		pvca := &pvcautoscalingv1alpha1.PersistentVolumeClaimAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
			Spec: pvcautoscalingv1alpha1.PersistentVolumeClaimAutoscalerSpec{
				VolumePolicies: []pvcautoscalingv1alpha1.VolumePolicy{
					{
						MaxCapacity: resource.MustParse("10Gi"),
						ScaleUp: &pvcautoscalingv1alpha1.ScalingRules{
							UtilizationThresholdPercent: &threshold,
						},
					},
					{
						MaxCapacity: resource.MustParse("20Gi"),
						ScaleUp: &pvcautoscalingv1alpha1.ScalingRules{
							UtilizationThresholdPercent: &threshold,
						},
					},
				},
			},
		}

		err := mutator.Mutate(context.Background(), pvca, nil)
		Expect(err).ToNot(HaveOccurred())

		Expect(pvca.Spec.VolumePolicies).To(HaveLen(2))
		for i := range pvca.Spec.VolumePolicies {
			Expect(pvca.Spec.VolumePolicies[i].ScaleUp).ToNot(BeNil())
			Expect(pvca.Spec.VolumePolicies[i].ScaleUp.CooldownDuration).ToNot(BeNil())
			Expect(pvca.Spec.VolumePolicies[i].ScaleUp.CooldownDuration.Duration).To(Equal(6 * time.Hour))
		}
	})

	It("should overwrite existing cooldownDuration when smaller than 6h", func() {
		existing := metav1.Duration{Duration: 2 * time.Hour}
		pvca := &pvcautoscalingv1alpha1.PersistentVolumeClaimAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
			Spec: pvcautoscalingv1alpha1.PersistentVolumeClaimAutoscalerSpec{
				VolumePolicies: []pvcautoscalingv1alpha1.VolumePolicy{
					{
						MaxCapacity: resource.MustParse("10Gi"),
						ScaleUp: &pvcautoscalingv1alpha1.ScalingRules{
							CooldownDuration: &existing,
						},
					},
				},
			},
		}

		err := mutator.Mutate(context.Background(), pvca, nil)
		Expect(err).ToNot(HaveOccurred())

		Expect(pvca.Spec.VolumePolicies).To(HaveLen(1))
		Expect(pvca.Spec.VolumePolicies[0].ScaleUp).ToNot(BeNil())
		Expect(pvca.Spec.VolumePolicies[0].ScaleUp.CooldownDuration).ToNot(BeNil())
		Expect(pvca.Spec.VolumePolicies[0].ScaleUp.CooldownDuration.Duration).To(Equal(6 * time.Hour))
	})

	It("should keep existing cooldownDuration when already at least 6h", func() {
		existing := metav1.Duration{Duration: 8 * time.Hour}
		pvca := &pvcautoscalingv1alpha1.PersistentVolumeClaimAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
			Spec: pvcautoscalingv1alpha1.PersistentVolumeClaimAutoscalerSpec{
				VolumePolicies: []pvcautoscalingv1alpha1.VolumePolicy{
					{
						MaxCapacity: resource.MustParse("10Gi"),
						ScaleUp: &pvcautoscalingv1alpha1.ScalingRules{
							CooldownDuration: &existing,
						},
					},
				},
			},
		}

		err := mutator.Mutate(context.Background(), pvca, nil)
		Expect(err).ToNot(HaveOccurred())

		Expect(pvca.Spec.VolumePolicies).To(HaveLen(1))
		Expect(pvca.Spec.VolumePolicies[0].ScaleUp).ToNot(BeNil())
		Expect(pvca.Spec.VolumePolicies[0].ScaleUp.CooldownDuration).ToNot(BeNil())
		Expect(pvca.Spec.VolumePolicies[0].ScaleUp.CooldownDuration.Duration).To(Equal(8 * time.Hour))
	})
})
