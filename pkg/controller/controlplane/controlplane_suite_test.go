// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-provider-aws/pkg/features"
)

var (
	featureGates = map[string]bool{
		string(features.EnableIPAMController): false,
	}
)

func TestControlplane(t *testing.T) {
	RegisterFailHandler(Fail)
	features.RegisterExtensionFeatureGate()

	err := features.ExtensionFeatureGate.SetFromMap(featureGates)
	if err != nil {
		Fail(fmt.Sprintf("failed to register feature gates: %v", err))
	}
	RunSpecs(t, "Controlplane Suite")
}
