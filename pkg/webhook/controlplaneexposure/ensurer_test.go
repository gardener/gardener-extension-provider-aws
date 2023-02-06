// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplaneexposure

import (
	"context"
	"testing"

	druidv1alpha1 "github.com/gardener/etcd-druid/api/v1alpha1"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
			ClassName: pointer.StringPtr("gardener.cloud-fast"),
			Capacity:  utils.QuantityPtr(resource.MustParse("80Gi")),
		}

		dummyContext = gcontext.NewGardenContext(nil, nil)
	)

	Describe("#EnsureKubeAPIServerService", func() {
		var (
			svc     *corev1.Service
			ensurer genericmutator.Ensurer
		)

		BeforeEach(func() {
			svc = &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver"},
			}
			ensurer = NewEnsurer(etcdStorage, logger)
		})

		It("should not modify kube-apiserver service if SNI is enabled", func() {
			svc.Labels = map[string]string{"core.gardener.cloud/apiserver-exposure": "gardener-managed"}
			svcCopy := svc.DeepCopy()

			err := ensurer.EnsureKubeAPIServerService(ctx, dummyContext, svc, nil)
			Expect(err).To(Not(HaveOccurred()))

			Expect(svc).To(Equal(svcCopy))
		})

		It("should add annotations to kube-apiserver service", func() {
			err := ensurer.EnsureKubeAPIServerService(ctx, dummyContext, svc, nil)
			Expect(err).To(Not(HaveOccurred()))

			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-connection-idle-timeout", "3600"))
			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-backend-protocol", "ssl"))
			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ssl-ports", "443"))
			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-healthcheck-timeout", "5"))
			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-healthcheck-interval", "30"))
			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-healthcheck-healthy-threshold", "2"))
			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-healthcheck-unhealthy-threshold", "2"))
			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy", "ELBSecurityPolicy-TLS-1-2-2017-01"))
		})
	})

	Describe("#EnsureKubeAPIServerDeployment", func() {
		It("should not modify kube-apiserver deployment if SNI is enabled", func() {
			var (
				dep = &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:   v1beta1constants.DeploymentNameKubeAPIServer,
						Labels: map[string]string{"core.gardener.cloud/apiserver-exposure": "gardener-managed"},
					},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "kube-apiserver",
									},
								},
							},
						},
					},
				}
				depCopy = dep.DeepCopy()
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			err := ensurer.EnsureKubeAPIServerDeployment(ctx, dummyContext, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			Expect(dep).To(Equal(depCopy))
		})

		It("should add missing elements to kube-apiserver deployment", func() {
			var (
				dep = &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.DeploymentNameKubeAPIServer},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "kube-apiserver",
									},
								},
							},
						},
					},
				}
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			// Call EnsureKubeAPIServerDeployment method and check the result
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, dummyContext, dep, nil)
			Expect(err).To(Not(HaveOccurred()))
			checkKubeAPIServerDeployment(dep)
		})

		It("should modify existing elements of kube-apiserver deployment", func() {
			var (
				dep = &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.DeploymentNameKubeAPIServer},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:    "kube-apiserver",
										Command: []string{"--endpoint-reconciler-type=?"},
									},
								},
							},
						},
					},
				}
			)

			// Create ensurer
			ensurer := NewEnsurer(etcdStorage, logger)

			// Call EnsureKubeAPIServerDeployment method and check the result
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, dummyContext, dep, nil)
			Expect(err).To(Not(HaveOccurred()))
			checkKubeAPIServerDeployment(dep)
		})
	})

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

func checkKubeAPIServerDeployment(dep *appsv1.Deployment) {
	// Check that the kube-apiserver container still exists and contains all needed command line args
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "kube-apiserver")
	Expect(c).To(Not(BeNil()))
	Expect(c.Command).To(ContainElement("--endpoint-reconciler-type=none"))
}

func checkETCDMain(etcd *druidv1alpha1.Etcd) {
	Expect(*etcd.Spec.StorageClass).To(Equal("gardener.cloud-fast"))
	Expect(*etcd.Spec.StorageCapacity).To(Equal(resource.MustParse("80Gi")))
}

func checkETCDEvents(etcd *druidv1alpha1.Etcd) {
	Expect(*etcd.Spec.StorageClass).To(Equal(""))

}
