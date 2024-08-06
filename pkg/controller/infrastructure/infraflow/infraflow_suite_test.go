package infraflow_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestInfraflow(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Infraflow Suite")
}
