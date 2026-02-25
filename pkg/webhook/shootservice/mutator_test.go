// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootservice

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Mutator", func() {
	var (
		fakeShootClient            = fakeclient.NewClientBuilder().WithScheme(kubernetes.ShootScheme).Build()
		loadBalancerServiceMapMeta = metav1.ObjectMeta{Name: "externalLoadbalancer", Namespace: metav1.NamespaceSystem}
		ctxWithClient              = context.Background()
	)

	Expect(fakeShootClient.Create(context.TODO(), &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
		Spec: corev1.ServiceSpec{
			IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol},
		},
	})).To(Succeed())
	ctxWithClient = context.WithValue(ctxWithClient, extensionswebhook.ShootClientContextKey{}, fakeShootClient)
	mutator := &mutator{wantsShootClient: false} // we use the fake client from the ctx

	DescribeTable("#Mutate",
		func(service *corev1.Service) {
			service.Annotations = make(map[string]string, 1)
			err := mutator.Mutate(ctxWithClient, service, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(service.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack"))
			Expect(service.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))
			Expect(service.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
			Expect(service.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
		},

		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol}}}),
		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol, corev1.IPv4Protocol}}}),
	)

	DescribeTable("#Mutate",
		func(service *corev1.Service) {
			Expect(fakeShootClient.Patch(context.TODO(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
				},
			}, client.MergeFrom(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}}))).To(Succeed())
			service.Annotations = make(map[string]string, 1)
			err := mutator.Mutate(ctxWithClient, service, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
		},
		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol}}}),
	)

	DescribeTable("#Mutate",
		func(service *corev1.Service) {
			metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-scheme", "internal")
			Expect(fakeShootClient.Patch(context.TODO(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
				},
			}, client.MergeFrom(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}}))).To(Succeed())
			err := mutator.Mutate(ctxWithClient, service, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
		},

		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}}}),
	)

	DescribeTable("#Mutate",
		func(service *corev1.Service) {
			metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-internal", "true")
			Expect(fakeShootClient.Patch(context.TODO(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
				},
			}, client.MergeFrom(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}}))).To(Succeed())
			err := mutator.Mutate(ctxWithClient, service, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
		},

		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}}}),
	)

	DescribeTable("#Mutate",
		func(service *corev1.Service) {
			metav1.SetMetaDataAnnotation(&service.ObjectMeta, "extensions.gardener.cloud/ignore-load-balancer", "true")
			Expect(fakeShootClient.Patch(context.TODO(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
				},
			}, client.MergeFrom(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}}))).To(Succeed())
			err := mutator.Mutate(ctxWithClient, service, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
		},

		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}}}),
	)

	It("should return error if resource is not a Service", func() {
		err := mutator.Mutate(ctxWithClient, &corev1.ConfigMap{}, nil)
		Expect(err).To(HaveOccurred())
	})
	It("should return nil if Service is not a LoadBalancer", func() {
		service := &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol}}}
		err := mutator.Mutate(ctxWithClient, service, nil)
		Expect(err).To(Not(HaveOccurred()))
	})

	Context("Service updates", func() {
		BeforeEach(func() {
			Expect(fakeShootClient.Patch(context.TODO(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol},
				},
			}, client.MergeFrom(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}}))).To(Succeed())
		})

		It("should add ignore annotation when updating existing service without ignore annotation", func() {
			oldService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "test-lb", Namespace: metav1.NamespaceSystem},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			}
			newService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "test-lb", Namespace: metav1.NamespaceSystem},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			}

			err := mutator.Mutate(ctxWithClient, newService, oldService)
			Expect(err).To(Not(HaveOccurred()))
			Expect(newService.Annotations).To(HaveKeyWithValue("extensions.gardener.cloud/ignore-load-balancer", "true"))
			Expect(newService.Annotations).ToNot(HaveKey("service.beta.kubernetes.io/aws-load-balancer-ip-address-type"))
		})

		It("should apply dualstack annotations when user removes ignore annotation", func() {
			oldService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb",
					Namespace: metav1.NamespaceSystem,
					Annotations: map[string]string{
						"extensions.gardener.cloud/ignore-load-balancer": "true",
					},
				},
				Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			}
			newService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-lb",
					Namespace:   metav1.NamespaceSystem,
					Annotations: map[string]string{},
				},
				Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			}

			err := mutator.Mutate(ctxWithClient, newService, oldService)
			Expect(err).To(Not(HaveOccurred()))
			Expect(newService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack"))
			Expect(newService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))
			Expect(newService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
			Expect(newService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
		})

		It("should skip mutation when ignore annotation is still present", func() {
			oldService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb",
					Namespace: metav1.NamespaceSystem,
					Annotations: map[string]string{
						"extensions.gardener.cloud/ignore-load-balancer": "true",
					},
				},
				Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			}
			newService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-lb",
					Namespace: metav1.NamespaceSystem,
					Annotations: map[string]string{
						"extensions.gardener.cloud/ignore-load-balancer": "true",
					},
				},
				Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			}

			err := mutator.Mutate(ctxWithClient, newService, oldService)
			Expect(err).To(Not(HaveOccurred()))
			Expect(newService.Annotations).ToNot(HaveKey("service.beta.kubernetes.io/aws-load-balancer-ip-address-type"))
		})
	})
})
