// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"encoding/json"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/event"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

// seedWithTGW returns a v1beta1.Seed whose providerConfig encodes the given v1alpha1
// TransitGateway. Used to drive SeedTGWConfigChangedPredicate.Update through the
// real helper.SeedProviderConfigFromSeed decoder path.
func seedWithTGW(tgw *awsv1alpha1.TransitGateway) *gardencorev1beta1.Seed {
	cfg := &awsv1alpha1.SeedProviderConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: awsv1alpha1.SchemeGroupVersion.String(),
			Kind:       "SeedProviderConfig",
		},
		TransitGateway: tgw,
	}
	raw, err := json.Marshal(cfg)
	Expect(err).NotTo(HaveOccurred())
	return &gardencorev1beta1.Seed{
		Spec: gardencorev1beta1.SeedSpec{
			Provider: gardencorev1beta1.SeedProvider{
				Type:           "aws",
				ProviderConfig: &runtime.RawExtension{Raw: raw},
			},
		},
	}
}

// seedNoProviderConfig returns a Seed whose Spec.Provider.ProviderConfig is nil
// (decodes to nil SeedProviderConfig).
func seedNoProviderConfig() *gardencorev1beta1.Seed {
	return &gardencorev1beta1.Seed{}
}

var _ = Describe("effectiveTGWID", func() {
	It("returns empty string when the input is nil", func() {
		Expect(effectiveTGWID(nil)).To(BeEmpty())
	})

	It("returns empty string when TGW is not enabled (regardless of ID)", func() {
		Expect(effectiveTGWID(&awsapi.TransitGateway{Enabled: false})).To(BeEmpty())
		Expect(effectiveTGWID(&awsapi.TransitGateway{
			Enabled: false, ID: ptr.To("tgw-anything"),
		})).To(BeEmpty())
	})

	It("returns 'managed' when enabled with no ID set (managed mode)", func() {
		Expect(effectiveTGWID(&awsapi.TransitGateway{Enabled: true})).To(Equal("managed"))
		Expect(effectiveTGWID(&awsapi.TransitGateway{
			Enabled: true, ID: ptr.To(""),
		})).To(Equal("managed"))
	})

	It("returns the TGW ID when enabled with a non-empty ID (referenced mode)", func() {
		Expect(effectiveTGWID(&awsapi.TransitGateway{
			Enabled: true, ID: ptr.To("tgw-0abc"),
		})).To(Equal("tgw-0abc"))
	})
})

var _ = Describe("SeedTGWConfigChangedPredicate", func() {
	pred := SeedTGWConfigChangedPredicate{}

	Context("Create / Delete events", func() {
		It("returns false on Create (initial Seed creation handled by normal flow)", func() {
			Expect(pred.Create(event.CreateEvent{Object: seedNoProviderConfig()})).To(BeFalse())
		})

		It("returns false on Delete (Seed deletion handled by normal flow)", func() {
			Expect(pred.Delete(event.DeleteEvent{Object: seedNoProviderConfig()})).To(BeFalse())
		})
	})

	Context("Update events", func() {
		It("returns false when neither object is a Seed", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: &corev1.ConfigMap{}, ObjectNew: &corev1.ConfigMap{},
			})).To(BeFalse())
		})

		It("returns false when both Seeds have no provider config (oldConfig and newConfig both nil)", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedNoProviderConfig(),
				ObjectNew: seedNoProviderConfig(),
			})).To(BeFalse())
		})

		It("returns true when transitioning from no-config Seed to a Seed with TGW config", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedNoProviderConfig(),
				ObjectNew: seedWithTGW(&awsv1alpha1.TransitGateway{Enabled: true}),
			})).To(BeTrue())
		})

		It("returns true when transitioning from a TGW-configured Seed to a no-config Seed", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(&awsv1alpha1.TransitGateway{Enabled: true}),
				ObjectNew: seedNoProviderConfig(),
			})).To(BeTrue())
		})

		It("returns false when both configs exist but neither has a TransitGateway entry", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(nil),
				ObjectNew: seedWithTGW(nil),
			})).To(BeFalse())
		})

		It("returns true when adding a TransitGateway entry to an existing config", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(nil),
				ObjectNew: seedWithTGW(&awsv1alpha1.TransitGateway{Enabled: true}),
			})).To(BeTrue())
		})

		It("returns true when removing the TransitGateway entry from an existing config", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(&awsv1alpha1.TransitGateway{Enabled: true}),
				ObjectNew: seedWithTGW(nil),
			})).To(BeTrue())
		})

		It("returns false when both Seeds have an identical TransitGateway config", func() {
			tgw := &awsv1alpha1.TransitGateway{
				Enabled: true, ID: ptr.To("tgw-0abc"), IsolationMode: "hub-spoke",
			}
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(tgw),
				ObjectNew: seedWithTGW(tgw),
			})).To(BeFalse())
		})

		It("returns true when the TGW ID changes (referenced TGW swap)", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(&awsv1alpha1.TransitGateway{
					Enabled: true, ID: ptr.To("tgw-0abc"), IsolationMode: "hub-spoke",
				}),
				ObjectNew: seedWithTGW(&awsv1alpha1.TransitGateway{
					Enabled: true, ID: ptr.To("tgw-0def"), IsolationMode: "hub-spoke",
				}),
			})).To(BeTrue())
		})

		It("returns true when the isolation mode changes (hub-spoke ↔ shared)", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(&awsv1alpha1.TransitGateway{
					Enabled: true, ID: ptr.To("tgw-0abc"), IsolationMode: "hub-spoke",
				}),
				ObjectNew: seedWithTGW(&awsv1alpha1.TransitGateway{
					Enabled: true, ID: ptr.To("tgw-0abc"), IsolationMode: "shared",
				}),
			})).To(BeTrue())
		})

		It("returns true when toggling Enabled from true to false", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(&awsv1alpha1.TransitGateway{Enabled: true}),
				ObjectNew: seedWithTGW(&awsv1alpha1.TransitGateway{Enabled: false}),
			})).To(BeTrue())
		})

		It("returns true when transitioning from referenced to managed (ID nil-ed)", func() {
			Expect(pred.Update(event.UpdateEvent{
				ObjectOld: seedWithTGW(&awsv1alpha1.TransitGateway{
					Enabled: true, ID: ptr.To("tgw-0abc"),
				}),
				ObjectNew: seedWithTGW(&awsv1alpha1.TransitGateway{
					Enabled: true, // ID nil → managed
				}),
			})).To(BeTrue())
		})
	})
})
