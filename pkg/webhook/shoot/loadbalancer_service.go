// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shoot

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (m *mutator) mutateService(ctx context.Context, service *corev1.Service, shootClient client.Client) error {
	if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if service.Annotations == nil {
			service.Annotations = make(map[string]string, 1)
		}
		kubeDNSService := &corev1.Service{}
		if err := shootClient.Get(ctx, types.NamespacedName{Name: "kube-dns", Namespace: "kube-system"}, kubeDNSService); err != nil {
			return err
		}
		for _, v := range kubeDNSService.Spec.IPFamilies {
			if v == corev1.IPv6Protocol {
				service.Annotations["service.beta.kubernetes.io/aws-load-balancer-ip-address-type"] = "dualstack"
				service.Annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"] = "internet-facing"
				service.Annotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = "instance"
				service.Annotations["service.beta.kubernetes.io/aws-load-balancer-type"] = "external"
			}
		}
	}
	return nil
}
