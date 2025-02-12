// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootservice

import (
	"context"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (m *mutator) mutateService(ctx context.Context, service *corev1.Service, shootClient client.Client) error {
	if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if metav1.HasAnnotation(service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-scheme") &&
			service.Annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"] == "internal" ||
			metav1.HasAnnotation(service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-internal") &&
				service.Annotations["service.beta.kubernetes.io/aws-load-balancer-internal"] == "true" {
			return nil
		}
		kubeDNSService := &corev1.Service{}
		if err := shootClient.Get(ctx, types.NamespacedName{Name: "kube-dns", Namespace: "kube-system"}, kubeDNSService); err != nil {
			return err
		}
		if slices.Contains(kubeDNSService.Spec.IPFamilies, corev1.IPv6Protocol) {
			metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-ip-address-type", "dualstack")
			metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing")
			metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance")
			metav1.SetMetaDataAnnotation(&service.ObjectMeta, "service.beta.kubernetes.io/aws-load-balancer-type", "external")
		}
	}
	return nil
}
