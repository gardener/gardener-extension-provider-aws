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
