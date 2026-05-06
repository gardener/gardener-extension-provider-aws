// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"testing"
)

func TestIsAttachmentTerminal(t *testing.T) {
	tests := []struct {
		state    string
		expected bool
	}{
		// Terminal states
		{"deleting", true},
		{"deleted", true},
		{"failed", true},
		{"rejected", true},
		{"rejecting", true},
		{"failing", true},
		// Case insensitive
		{"Deleting", true},
		{"DELETED", true},
		{"Failed", true},
		// Non-terminal states
		{"available", false},
		{"pending", false},
		{"initiating", false},
		{"pendingAcceptance", false},
		{"modifying", false},
		{"rollingBack", false},
		// Edge cases
		{"", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			result := isAttachmentTerminal(tt.state)
			if result != tt.expected {
				t.Errorf("isAttachmentTerminal(%q) = %v, want %v", tt.state, result, tt.expected)
			}
		})
	}
}
