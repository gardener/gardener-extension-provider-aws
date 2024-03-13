// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controlplaneexposure

import (
	"context"
	"testing"

	druidv1alpha1 "github.com/gardener/etcd-druid/api/v1alpha1"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/config"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controlplane Exposure Webhook Suite")
}

var (
	ctx = context.TODO()
)

var _ = Describe("Ensurer", func() {
	var (
		etcdStorage = &config.ETCDStorage{
			ClassName: pointer.String("gardener.cloud-fast"),
			Capacity:  utils.QuantityPtr(resource.MustParse("80Gi")),
		}

		dummyContext = gcontext.NewGardenContext(nil, nil)
	)

	Describe("#EnsureETCD", func() {
		It("should add or modify elements to etcd-main statefulset", func() {
			var (
				etcd = &druidv1alpha1.Etcd{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.ETCDMain},
				}
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			// Call EnsureETCDStatefulSet method and check the result
			err := ensurer.EnsureETCD(ctx, dummyContext, etcd, nil)
			Expect(err).To(Not(HaveOccurred()))
			checkETCDMain(etcd)
		})

		It("should modify existing elements of etcd-main statefulset", func() {
			var (
				r    = resource.MustParse("10Gi")
				etcd = &druidv1alpha1.Etcd{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.ETCDMain},
					Spec: druidv1alpha1.EtcdSpec{
						StorageCapacity: &r,
					},
				}
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			// Call EnsureETCDStatefulSet method and check the result
			err := ensurer.EnsureETCD(ctx, dummyContext, etcd, nil)
			Expect(err).To(Not(HaveOccurred()))
			checkETCDMain(etcd)
		})

		It("should add or modify elements to etcd-events statefulset", func() {
			var (
				etcd = &druidv1alpha1.Etcd{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.ETCDEvents},
				}
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			// Call EnsureETCDStatefulSet method and check the result
			err := ensurer.EnsureETCD(ctx, dummyContext, etcd, nil)
			Expect(err).To(Not(HaveOccurred()))
			checkETCDEvents(etcd)
		})

		It("should modify existing elements of etcd-events statefulset", func() {
			var (
				r    = resource.MustParse("20Gi")
				etcd = &druidv1alpha1.Etcd{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.ETCDEvents},
					Spec: druidv1alpha1.EtcdSpec{
						StorageCapacity: &r,
					},
				}
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			// Call EnsureETCDStatefulSet method and check the result
			err := ensurer.EnsureETCD(ctx, dummyContext, etcd, nil)
			Expect(err).To(Not(HaveOccurred()))
			checkETCDEvents(etcd)
		})
	})
})

func checkETCDMain(etcd *druidv1alpha1.Etcd) {
	Expect(*etcd.Spec.StorageClass).To(Equal("gardener.cloud-fast"))
	Expect(*etcd.Spec.StorageCapacity).To(Equal(resource.MustParse("80Gi")))
}

func checkETCDEvents(etcd *druidv1alpha1.Etcd) {
	Expect(*etcd.Spec.StorageClass).To(Equal(""))
}
