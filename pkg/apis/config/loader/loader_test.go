// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package loader_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/config"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/config/loader"
	healthcheckconfig "github.com/gardener/gardener/extensions/pkg/controller/healthcheck/config"
	"k8s.io/apimachinery/pkg/api/resource"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/utils/pointer"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAPI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config V1alpha1 Suite")
}

var _ = Describe("LoadFromFile", func() {
	var (
		expected *config.ControllerConfiguration
	)

	BeforeEach(func() {
		expected = &config.ControllerConfiguration{
			ClientConnection: &componentbaseconfig.ClientConnectionConfiguration{
				AcceptContentTypes: "application/json",
				ContentType:        "application/json",
				Kubeconfig:         "/foo/bar",
				Burst:              1300,
				QPS:                3000,
			},
			ETCD: config.ETCD{
				Storage: config.ETCDStorage{
					ClassName: pointer.StringPtr("gardener.cloud-fast"),
					Capacity:  resource.NewQuantity(85899345920, resource.BinarySI),
				},
			},
			HealthCheckConfig: &healthcheckconfig.HealthCheckConfig{
				SyncPeriod: v1.Duration{Duration: time.Second * 30},
			},
			ShootStorageClassConfig: &config.StorageClass{
				Encrypted: pointer.BoolPtr(true),
			},
		}
	})

	It("succeeds", func() {
		c, err := loader.LoadFromFile(filepath.Join("testdata", "config.yaml"))

		Expect(err).ToNot(HaveOccurred())
		Expect(c).ToNot(BeNil())
		Expect(c).To(Equal(expected))
	})

	It("succeeds and sets defaults", func() {
		expected.ShootStorageClassConfig.Encrypted = pointer.BoolPtr(false)

		c, err := loader.LoadFromFile(filepath.Join("testdata", "config_no_encryption.yaml"))

		Expect(err).ToNot(HaveOccurred())
		Expect(c).ToNot(BeNil())
		Expect(c).To(Equal(expected))
		Expect(c.ShootStorageClassConfig).NotTo(BeNil())
	})

	It("example is correct", func() {
		expected.ClientConnection.QPS = 100
		expected.ClientConnection.Burst = 130
		expected.ClientConnection.Kubeconfig = ""
		expected.HealthCheckConfig = nil

		c, err := loader.LoadFromFile(filepath.Join("../", "../", "../", "../", "example", "00-componentconfig.yaml"))

		Expect(err).ToNot(HaveOccurred())
		Expect(c).ToNot(BeNil())
		Expect(c).To(Equal(expected))
	})

	It("fails when using wrong version", func() {
		c, err := loader.LoadFromFile(filepath.Join("testdata", "config_wrong_version.yaml"))

		Expect(err).To(HaveOccurred())
		Expect(c).To(BeNil())
	})
})
