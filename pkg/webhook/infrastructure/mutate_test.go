// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"testing"

	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/pkg/mock/controller-runtime/manager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

const (
	shootNamespace = "shoot--foo--bar"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Infrastructure Webhook Suite")
}

var _ = Describe("Mutate", func() {
	var (
		ctrl *gomock.Controller
		c    *mockclient.MockClient
		mgr  *mockmanager.MockManager
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		c = mockclient.NewMockClient(ctrl)

		mgr = mockmanager.NewMockManager(ctrl)

		mgr.EXPECT().GetClient().Return(c)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#UseFlowAnnotation", func() {
		var (
			mutator extensionswebhook.Mutator
			cluster *controller.Cluster
			ctx     context.Context
		)

		Context("create", func() {
			BeforeEach(func() {
				mutator = New(mgr, logger)
				ctx = context.TODO()

				c.EXPECT().Get(ctx, client.ObjectKey{Name: shootNamespace}, gomock.AssignableToTypeOf(&extensionsv1alpha1.Cluster{})).
					DoAndReturn(
						func(_ context.Context, _ types.NamespacedName, obj *extensionsv1alpha1.Cluster, _ ...client.GetOption) error {
							sheedJSON, err := json.Marshal(cluster.Seed)
							Expect(err).NotTo(HaveOccurred())
							*obj = extensionsv1alpha1.Cluster{
								ObjectMeta: cluster.ObjectMeta,
								Spec: extensionsv1alpha1.ClusterSpec{
									Seed: runtime.RawExtension{Raw: sheedJSON},
								},
							}
							return nil
						})

				cluster = &controller.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: shootNamespace,
					},
					Seed: &gardencorev1beta1.Seed{
						ObjectMeta: metav1.ObjectMeta{
							Name:   shootNamespace,
							Labels: map[string]string{},
						},
					},
				}
			})

			It("should add use-flow annotation if seed label is set to new", func() {
				cluster.Seed.Labels[aws.SeedLabelKeyUseFlow] = aws.SeedLabelUseFlowValueNew
				newInfra := &extensionsv1alpha1.Infrastructure{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "dummy",
						Namespace: shootNamespace,
					},
				}

				err := mutator.Mutate(ctx, newInfra, nil)

				Expect(err).To(BeNil())
				Expect(err).To(BeNil())
				Expect(newInfra.Annotations[aws.AnnotationKeyUseFlow]).To(Equal("true"))
			})

			It("should do nothing if seed label is set to true", func() {
				cluster.Seed.Labels[aws.SeedLabelKeyUseFlow] = "true"
				newInfra := &extensionsv1alpha1.Infrastructure{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "dummy",
						Namespace: shootNamespace,
					},
				}
				err := mutator.Mutate(ctx, newInfra, nil)
				Expect(err).To(BeNil())
				Expect(newInfra.Annotations[aws.AnnotationKeyUseFlow]).To(Equal(""))
			})
		})

		Context("update", func() {
			BeforeEach(func() {
				mutator = New(mgr, logger)
				cluster = &controller.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: shootNamespace,
					},
				}
			})

			It("should do nothing on update", func() {
				newInfra := &extensionsv1alpha1.Infrastructure{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "dummy",
						Namespace: shootNamespace,
					},
				}
				err := mutator.Mutate(ctx, newInfra, newInfra)
				Expect(err).To(BeNil())
				Expect(newInfra.Annotations[aws.AnnotationKeyUseFlow]).To(Equal(""))
			})
		})
	})
})
