package features

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/featuregate"
)

const (
	// EnableIPAMController controls whether the aws provider will enable the ipam-controller. Technically it will still be deployed, but scaled down to zero.
	// alpha: v1.29.0
	EnableIPAMController featuregate.Feature = "EnableIPAMController"
)

// ExtensionFeatureGate is the feature gate for the extension controllers.
var ExtensionFeatureGate = featuregate.NewFeatureGate()

func init() {
	RegisterExtensionFeatureGate()
}

// RegisterExtensionFeatureGate registers features to the extension feature gate.
func RegisterExtensionFeatureGate() {
	runtime.Must(ExtensionFeatureGate.Add(map[featuregate.Feature]featuregate.FeatureSpec{
		EnableIPAMController: {Default: false, PreRelease: featuregate.Alpha},
	}))
}
