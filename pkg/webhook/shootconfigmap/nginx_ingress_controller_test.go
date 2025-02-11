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
	nginxIngressControllerConfigMapMeta := metav1.ObjectMeta{Name: "addons-nginx-ingress-controller", Namespace: metav1.NamespaceSystem}

	DescribeTable("#mutateNginxIngressControllerConfigMap",
		func(configmap *corev1.ConfigMap) {
			mutator := &mutator{}
			err := mutator.mutateNginxIngressControllerConfigMap(context.TODO(), configmap)

			Expect(err).To(Not(HaveOccurred()))
			Expect(configmap.Data).To(HaveKeyWithValue("use-proxy-protocol", "true"))
		},

		Entry("no data", &corev1.ConfigMap{ObjectMeta: nginxIngressControllerConfigMapMeta}),
		Entry("data with undesired field", &corev1.ConfigMap{ObjectMeta: nginxIngressControllerConfigMapMeta, Data: map[string]string{"use-proxy-protocol": "false"}}),
	)
})
