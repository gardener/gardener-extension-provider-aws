// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"fmt"

	"github.com/gardener/gardener/pkg/apis/core"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

var _ = Describe("Shoot validation", func() {
	Describe("#ValidateNetworking", func() {
		var networkingPath = field.NewPath("spec", "networking")

		It("should return no error because nodes CIDR was provided", func() {
			networking := &core.Networking{
				Nodes: ptr.To("1.2.3.4/5"),
			}

			errorList := ValidateNetworking(networking, networkingPath)

			Expect(errorList).To(BeEmpty())
		})

		It("should return an error because no nodes CIDR was provided", func() {
			networking := &core.Networking{}
			networking.IPFamilies = []core.IPFamily{core.IPFamilyIPv4}

			errorList := ValidateNetworking(networking, networkingPath)

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("spec.networking.nodes"),
				})),
			))
		})
	})

	Describe("#ValidateWorkerConfig", func() {
		var (
			worker   core.Worker
			awsZones []apisaws.Zone
			iops     int64 = 1234
		)

		BeforeEach(func() {
			worker = core.Worker{
				Name: "worker1",
				Volume: &core.Volume{
					Type:       ptr.To("Volume"),
					VolumeSize: "30G",
				},
				Zones: []string{
					"zone1",
					"zone2",
				},
			}

			awsZones = []apisaws.Zone{
				{
					Name: "zone1",
				},
				{
					Name: "zone2",
				},
				{
					Name: "zone3",
				},
			}
		})

		Describe("#ValidateWorker", func() {
			It("should pass when the workerConfig is nil", func() {
				errorList := ValidateWorker(worker, awsZones, nil, field.NewPath(""))

				Expect(errorList).To(BeEmpty())
			})

			It("should pass because the worker is configured correctly", func() {
				errorList := ValidateWorker(worker, awsZones, &apisaws.WorkerConfig{}, field.NewPath(""))

				Expect(errorList).To(BeEmpty())
			})

			It("should forbid because volume is not configured", func() {
				worker.Volume = nil

				errorList := ValidateWorker(worker, awsZones, &apisaws.WorkerConfig{}, field.NewPath("workers").Index(0))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("workers[0].volume"),
					})),
				))
			})

			It("should forbid because volume type io1 is used but no worker config provided", func() {
				worker.Volume.Type = ptr.To(string(apisaws.VolumeTypeIO1))

				errorList := ValidateWorker(worker, awsZones, &apisaws.WorkerConfig{}, field.NewPath("workers").Index(0))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("workers[0].providerConfig"),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("workers[0].providerConfig.volume.iops"),
					})),
				))
			})

			It("should allow because volume type io1 and worker config provided", func() {
				worker.Volume.Type = ptr.To(string(apisaws.VolumeTypeIO1))
				worker.ProviderConfig = &runtime.RawExtension{}

				errorList := ValidateWorker(worker, awsZones, &apisaws.WorkerConfig{Volume: &apisaws.Volume{IOPS: &iops}}, field.NewPath("workers").Index(0))

				Expect(errorList).To(BeEmpty())
			})

			It("should forbid because volume type and size are not configured", func() {
				worker.Volume.Type = nil
				worker.Volume.VolumeSize = ""
				worker.DataVolumes = []core.DataVolume{{}}

				errorList := ValidateWorker(worker, awsZones, &apisaws.WorkerConfig{}, field.NewPath("workers").Index(0))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("workers[0].volume.type"),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("workers[0].volume.size"),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("workers[0].dataVolumes[0].type"),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("workers[0].dataVolumes[0].size"),
					})),
				))
			})

			It("should forbid because of too many data volumes", func() {
				for i := 0; i <= 11; i++ {
					worker.DataVolumes = append(worker.DataVolumes, core.DataVolume{
						Name:       fmt.Sprintf("foo%d", i),
						VolumeSize: "20Gi",
						Type:       ptr.To("foo"),
					})
				}

				errorList := ValidateWorker(worker, awsZones, &apisaws.WorkerConfig{}, field.NewPath("workers").Index(0))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeTooMany),
						"Field": Equal("workers[0].dataVolumes"),
					})),
				))
			})

			It("should forbid because worker does not specify a zone", func() {
				worker.Zones = nil

				errorList := ValidateWorker(worker, awsZones, &apisaws.WorkerConfig{}, field.NewPath("workers").Index(0))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("workers[0].zones"),
					})),
				))
			})

			It("should forbid because worker use zones which are not available", func() {
				worker.Zones[0] = ""
				worker.Zones[1] = "not-available"

				errorList := ValidateWorker(worker, awsZones, &apisaws.WorkerConfig{}, field.NewPath("workers").Index(0))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("workers[0].zones[0]"),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("workers[0].zones[1]"),
					})),
				))
			})
		})

		Describe("#ValidateWorkersUpdate", func() {
			var workers []core.Worker

			BeforeEach(func() {
				workers = []core.Worker{worker, worker}
			})

			It("should pass because workers are unchanged", func() {
				newWorkers := copyWorkers(workers)
				errorList := ValidateWorkersUpdate(workers, newWorkers, field.NewPath("workers"))

				Expect(errorList).To(BeEmpty())
			})

			It("should allow adding workers", func() {
				newWorkers := append(workers[:0:0], workers...)
				workers = workers[:1]
				errorList := ValidateWorkersUpdate(workers, newWorkers, field.NewPath("workers"))

				Expect(errorList).To(BeEmpty())
			})

			It("should allow adding a zone to a worker", func() {
				newWorkers := copyWorkers(workers)
				newWorkers[0].Zones = append(newWorkers[0].Zones, "another-zone")
				errorList := ValidateWorkersUpdate(workers, newWorkers, field.NewPath("workers"))

				Expect(errorList).To(BeEmpty())
			})

			It("should forbid removing a zone from a worker", func() {
				newWorkers := copyWorkers(workers)
				newWorkers[1].Zones = newWorkers[1].Zones[1:]
				errorList := ValidateWorkersUpdate(workers, newWorkers, field.NewPath("workers"))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("workers[1].zones"),
					})),
				))
			})

			It("should forbid changing the zone order", func() {
				newWorkers := copyWorkers(workers)
				newWorkers[0].Zones[0] = workers[0].Zones[1]
				newWorkers[0].Zones[1] = workers[0].Zones[0]
				newWorkers[1].Zones[0] = workers[1].Zones[1]
				newWorkers[1].Zones[1] = workers[1].Zones[0]
				errorList := ValidateWorkersUpdate(workers, newWorkers, field.NewPath("workers"))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("workers[0].zones"),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("workers[1].zones"),
					})),
				))
			})

			It("should forbid adding a zone while changing an existing one", func() {
				newWorkers := copyWorkers(workers)
				newWorkers = append(newWorkers, core.Worker{Name: "worker3", Zones: []string{"zone1"}})
				newWorkers[1].Zones[0] = workers[1].Zones[1]
				errorList := ValidateWorkersUpdate(workers, newWorkers, field.NewPath("workers"))

				Expect(errorList).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("workers[1].zones"),
					})),
				))
			})

			It("should forbid changing the providerConfig if the update strategy is in-place", func() {
				workers[0].UpdateStrategy = ptr.To(core.AutoInPlaceUpdate)
				workers[0].ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"foo":"bar"}`),
				}

				workers[1].Name = "worker2"
				workers[1].UpdateStrategy = ptr.To(core.ManualInPlaceUpdate)
				workers[1].ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"zoo":"dash"}`),
				}

				// provider config changed but update strategy is not in-place
				workers = append(workers, core.Worker{
					Name:           "worker3",
					UpdateStrategy: ptr.To(core.AutoRollingUpdate),
					ProviderConfig: &runtime.RawExtension{
						Raw: []byte(`{"bar":"foo"}`),
					},
				})

				// no change in provider config
				workers = append(workers, core.Worker{
					Name:           "worker4",
					UpdateStrategy: ptr.To(core.AutoInPlaceUpdate),
					ProviderConfig: &runtime.RawExtension{
						Raw: []byte(`{"bar":"foo"}`),
					},
				})

				newWorkers := copyWorkers(workers)
				newWorkers[0].ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"foo":"baz"}`),
				}
				newWorkers[1].ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"zoo":"bash"}`),
				}
				newWorkers[2].ProviderConfig = &runtime.RawExtension{
					Raw: []byte(`{"bar":"baz"}`),
				}

				Expect(ValidateWorkersUpdate(workers, newWorkers, field.NewPath("spec", "provider", "workers"))).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":   Equal(field.ErrorTypeInvalid),
						"Field":  Equal("spec.provider.workers[0].providerConfig"),
						"Detail": Equal("providerConfig is immutable when update strategy is in-place"),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":   Equal(field.ErrorTypeInvalid),
						"Field":  Equal("spec.provider.workers[1].providerConfig"),
						"Detail": Equal("providerConfig is immutable when update strategy is in-place"),
					})),
				))
			})

			It("should forbid changing the data volumes if the update strategy is in-place", func() {
				workers[0].UpdateStrategy = ptr.To(core.AutoInPlaceUpdate)
				workers[0].DataVolumes = []core.DataVolume{
					{
						Name:       "foo",
						VolumeSize: "20Gi",
						Type:       ptr.To("foo"),
					},
				}

				workers[1].Name = "worker2"
				workers[1].UpdateStrategy = ptr.To(core.ManualInPlaceUpdate)
				workers[1].DataVolumes = []core.DataVolume{
					{
						Name:       "bar",
						VolumeSize: "30Gi",
						Type:       ptr.To("bar"),
					},
				}

				newWorkers := copyWorkers(workers)
				newWorkers[0].DataVolumes = []core.DataVolume{
					{
						Name:       "baz",
						VolumeSize: "40Gi",
						Type:       ptr.To("baz"),
					},
				}
				newWorkers[1].DataVolumes = []core.DataVolume{
					{
						Name:       "qux",
						VolumeSize: "50Gi",
						Type:       ptr.To("qux"),
					},
				}

				Expect(ValidateWorkersUpdate(workers, newWorkers, field.NewPath("spec", "provider", "workers"))).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":   Equal(field.ErrorTypeInvalid),
						"Field":  Equal("spec.provider.workers[0].dataVolumes"),
						"Detail": Equal("dataVolumes are immutable when update strategy is in-place"),
					})),
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":   Equal(field.ErrorTypeInvalid),
						"Field":  Equal("spec.provider.workers[1].dataVolumes"),
						"Detail": Equal("dataVolumes are immutable when update strategy is in-place"),
					})),
				))
			})
		})
	})
})

func copyWorkers(workers []core.Worker) []core.Worker {
	cp := append(workers[:0:0], workers...)
	for i := range cp {
		cp[i].Zones = append(workers[i].Zones[:0:0], workers[i].Zones...)
	}
	return cp
}
