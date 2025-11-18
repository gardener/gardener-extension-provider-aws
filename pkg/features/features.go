// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package features

const (
	// VolumeAttributesClass is the feature gate for VolumeAttributesClass support.
	// alpha: v1.29
	// beta: v1.31
	// GA: v1.34
	VolumeAttributesClass = "VolumeAttributesClass"

	// RecoverVolumeExpansionFailure is the feature gate for recovering from volume expansion failures.
	// alpha: v1.23
	// beta: v1.32
	//
	RecoverVolumeExpansionFailure = "RecoverVolumeExpansionFailure"
)
