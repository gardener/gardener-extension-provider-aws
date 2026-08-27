// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package pvca_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPVCA(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Seed PVCA Webhook Suite")
}
