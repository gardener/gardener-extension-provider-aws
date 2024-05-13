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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

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
			ClassName: ptr.To("gardener.cloud-fast"),
			Capacity:  ptr.To(resource.MustParse("25Gi")),
		}

		dummyContext = gcontext.NewGardenContext(nil, nil)
	)

	Describe("#EnsureETCD", func() {
		It("should add an etcd-main storage configuration when etcd-main is new and does not specify a storage configuration", func() {
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
			checkNewETCDMain(etcd)
		})

		It("should modify an etcd-main storage configuration when etcd-main is new and specifies a storage configuration", func() {
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
			checkNewETCDMain(etcd)
		})

		It("should not modify an etcd-main storage configuration when etcd-main is old with volume size 80Gi", func() {
			var (
				rOld    = resource.MustParse("80Gi")
				oldEtcd = &druidv1alpha1.Etcd{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.ETCDMain},
					Spec: druidv1alpha1.EtcdSpec{
						StorageCapacity: &rOld,
					},
				}
				rNew         = resource.MustParse("10Gi")
				modifiedEtcd = &druidv1alpha1.Etcd{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.ETCDMain},
					Spec: druidv1alpha1.EtcdSpec{
						StorageCapacity: &rNew,
					},
				}
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			// Call EnsureETCDStatefulSet method and check the result
			err := ensurer.EnsureETCD(ctx, dummyContext, modifiedEtcd, oldEtcd)
			Expect(err).To(Not(HaveOccurred()))
			checkOldETCDMain(modifiedEtcd)
		})

		It("should not modify an etcd-main storage configuration when etcd-main is old with volume size 25Gi", func() {
			var (
				rOld    = resource.MustParse("25Gi")
				oldEtcd = &druidv1alpha1.Etcd{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.ETCDMain},
					Spec: druidv1alpha1.EtcdSpec{
						StorageCapacity: &rOld,
					},
				}
				rNew         = resource.MustParse("10Gi")
				modifiedEtcd = &druidv1alpha1.Etcd{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.ETCDMain},
					Spec: druidv1alpha1.EtcdSpec{
						StorageCapacity: &rNew,
					},
				}
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			// Call EnsureETCDStatefulSet method and check the result
			err := ensurer.EnsureETCD(ctx, dummyContext, modifiedEtcd, oldEtcd)
			Expect(err).To(Not(HaveOccurred()))
			checkNewETCDMain(modifiedEtcd)
		})

		It("should add an etcd-events storage configuration when etcd-events is new and does not specify a storage configuration", func() {
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

		It("should always modify an existing etcd-events storage configuration", func() {
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

// checkOldETCDMain tests older Etcds which have volumes of size 80Gi
func checkOldETCDMain(etcd *druidv1alpha1.Etcd) {
	Expect(*etcd.Spec.StorageClass).To(Equal("gardener.cloud-fast"))
	Expect(*etcd.Spec.StorageCapacity).To(Equal(resource.MustParse("80Gi")))
}

// checkNewETCDMain tests newer Etcds which have volumes of size 25Gi
func checkNewETCDMain(etcd *druidv1alpha1.Etcd) {
	Expect(*etcd.Spec.StorageClass).To(Equal("gardener.cloud-fast"))
	Expect(*etcd.Spec.StorageCapacity).To(Equal(resource.MustParse("25Gi")))
}

func checkETCDEvents(etcd *druidv1alpha1.Etcd) {
	Expect(*etcd.Spec.StorageClass).To(Equal(""))
	Expect(*etcd.Spec.StorageCapacity).To(Equal(resource.MustParse("10Gi")))
}
