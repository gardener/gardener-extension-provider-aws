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

package infrastructure

import (
	"bytes"
	"context"
	"fmt"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	awsmockclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/golang/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Actuator", func() {
	var (
		ctrl *gomock.Controller
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Context("generateTerraformInfraConfig", func() {
		var (
			ctx                  context.Context
			infrastructure       *extensionsv1alpha1.Infrastructure
			infrastructureConfig *awsapi.InfrastructureConfig
			awsClient            awsclient.Interface
			cluster              *extensionscontroller.Cluster
		)
		BeforeEach(func() {
			ctx = context.TODO()
			infrastructure = &extensionsv1alpha1.Infrastructure{
				Spec: extensionsv1alpha1.InfrastructureSpec{
					Region:       "eu-central-1",
					SSHPublicKey: []byte("<Public Key>"),
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "shoot--test-shoot",
				},
			}
			infrastructureConfig = &awsapi.InfrastructureConfig{
				Networks: awsapi.Networks{
					VPC: awsapi.VPC{
						CIDR: pointer.StringPtr("10.250.0.0/16"),
					},
					Zones: []awsapi.Zone{
						{
							Internal: "10.250.48.0/20",
							Name:     "eu-central-1a",
							Public:   "10.250.32.0/20",
							Workers:  "10.250.0.0/19",
						},
						{
							Internal: "10.250.112.0/20",
							Name:     "eu-central-1b",
							Public:   "10.250.96.0/20",
							Workers:  "10.250.64.0/19",
						},
						{
							Internal: "10.250.176.0/20",
							Name:     "eu-central-1c",
							Public:   "10.250.160.0/20",
							Workers:  "10.250.128.0/19",
						},
					},
				},
			}
			awsClient = awsmockclient.NewMockInterface(ctrl)
			cluster = &extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"shoot.gardener.cloud/cordoned-zones": "eu-central-1b,eu-central-1a",
						},
					},
					Spec: gardencorev1beta1.ShootSpec{
						Provider: gardencorev1beta1.Provider{
							AutoCordonZones: pointer.BoolPtr(true),
						},
					},
				},
			}
		})
		It("should render correct terraform configuration for non-cordoned zones", func() {
			cluster.Shoot.Spec.Provider.AutoCordonZones = pointer.BoolPtr(false)
			terraformConfig, err := generateTerraformInfraConfig(ctx, infrastructure, infrastructureConfig, awsClient, cluster)
			Expect(err).NotTo(HaveOccurred())

			var mainTF bytes.Buffer
			err = tplMainTF.Execute(&mainTF, terraformConfig)
			Expect(err).NotTo(HaveOccurred())
			output := mainTF.String()
			fmt.Println(output)
		})

		It("should render correct terraform configuration for cordoned zones", func() {
			terraformConfig, err := generateTerraformInfraConfig(ctx, infrastructure, infrastructureConfig, awsClient, cluster)
			Expect(err).NotTo(HaveOccurred())

			var mainTF bytes.Buffer
			err = tplMainTF.Execute(&mainTF, terraformConfig)
			Expect(err).NotTo(HaveOccurred())
			output := mainTF.String()
			fmt.Println(output)
		})
	})

})
