// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import "k8s.io/apimachinery/pkg/runtime"

// rawExtensionToString converts a runtime.RawExtension to its string representation, useful for error messages.
func rawExtensionToString(raw *runtime.RawExtension) string {
	if raw == nil {
		return "<nil>"
	}

	return string(raw.Raw)
}
