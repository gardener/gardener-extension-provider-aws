// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package features

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/featuregate"
)

const (
	// MTUCustomizer enables the deployment of the mtu-customizer DaemonSet on AWS seed
	// nodes to set network interface MTU to 1460.
	// This feature gate is used to phase out MTU customization. It will be switched to
	// default false in a future version and eventually removed along with all related code.
	// alpha: v1.69 (default=true)
	MTUCustomizer featuregate.Feature = "MTUCustomizer"
)

var FeatureGate featuregate.MutableFeatureGate = featuregate.NewFeatureGate()

var featureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	MTUCustomizer: {Default: true, PreRelease: featuregate.Alpha},
}

// RegisterFeatureGates registers the feature gates of the provider-aws extension.
func RegisterFeatureGates() {
	runtime.Must(FeatureGate.Add(featureGates))
}
