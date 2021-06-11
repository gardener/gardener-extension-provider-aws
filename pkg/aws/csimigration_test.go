// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package aws_test

import (
	. "github.com/gardener/gardener-extension-provider-aws/pkg/aws"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("CSIMigration", func() {
	DescribeTable("#GetCSIMigrationKubernetesVersion",
		func(cluster *extensionscontroller.Cluster, expectedVersion string) {
			Expect(GetCSIMigrationKubernetesVersion(cluster)).To(Equal(expectedVersion))
		},

		Entry("cluster nil", nil, "1.18"),
		Entry("shoot nil", &extensionscontroller.Cluster{}, "1.18"),
		Entry("shoot w/o annotation", &extensionscontroller.Cluster{Shoot: &gardencorev1beta1.Shoot{}}, "1.18"),
		Entry("shoot w/ annotation", &extensionscontroller.Cluster{Shoot: &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"alpha.csimigration.shoot.extensions.gardener.cloud/kubernetes-version": "1.24"}}}}, "1.24"),
	)
})
