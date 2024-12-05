// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shoot

import (
	"context"

	corev1 "k8s.io/api/core/v1"
)

func (m *mutator) mutateService(_ context.Context, service *corev1.Service) error {
	if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		for _, v := range service.Spec.IPFamilies {
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
