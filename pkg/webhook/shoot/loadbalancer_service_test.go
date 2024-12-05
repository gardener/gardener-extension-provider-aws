// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shoot

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Mutator", func() {
	loadBalancerServiceMapMeta := metav1.ObjectMeta{Name: "externalLoadbalancer", Namespace: metav1.NamespaceSystem}
	DescribeTable("#mutateService",
		func(service *corev1.Service) {
			mutator := &mutator{}
			service.Annotations = make(map[string]string, 1)
			err := mutator.mutateService(context.TODO(), service)
			Expect(err).To(Not(HaveOccurred()))
			Expect(service.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack"))
			Expect(service.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))
			Expect(service.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
			Expect(service.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))

		},

		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol}}}),
		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}}}),
	)
	DescribeTable("#mutateService",
		func(service *corev1.Service) {
			mutator := &mutator{}
			service.Annotations = make(map[string]string, 1)
			err := mutator.mutateService(context.TODO(), service)
			Expect(err).To(Not(HaveOccurred()))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
			Expect(service.Annotations).ToNot(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))

		},

		Entry("no data", &corev1.Service{ObjectMeta: loadBalancerServiceMapMeta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol}}}),
	)
})
