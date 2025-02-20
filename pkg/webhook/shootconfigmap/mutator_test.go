// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootconfigmap

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
			err := mutator.Mutate(context.TODO(), configmap, nil)

			Expect(err).To(Not(HaveOccurred()))
			Expect(configmap.Data).To(HaveKeyWithValue("use-proxy-protocol", "true"))
		},

		Entry("no data", &corev1.ConfigMap{ObjectMeta: nginxIngressControllerConfigMapMeta}),
		Entry("data with undesired field", &corev1.ConfigMap{ObjectMeta: nginxIngressControllerConfigMapMeta, Data: map[string]string{"use-proxy-protocol": "false"}}),
	)

	It("should return error if resource is not a ConfigMap", func() {
		mutator := &mutator{}
		err := mutator.Mutate(context.TODO(), &corev1.Service{}, nil)
		Expect(err).To(HaveOccurred())
	})
})
