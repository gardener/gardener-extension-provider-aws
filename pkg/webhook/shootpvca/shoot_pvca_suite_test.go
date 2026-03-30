// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootpvca_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestShootPVCA(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Shoot PVCA Webhook Suite")
}
