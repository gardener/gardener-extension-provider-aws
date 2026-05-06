// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"github.com/go-logr/logr"
)

// clearStaleAttachmentState clears the state key for a TGW attachment that
// no longer exists. Called when AWS returns NotFound for an attachment ID
// that was stored in state from a previous reconcile.
func (c *FlowContext) clearStaleAttachmentState(log logr.Logger, stateKey, staleID string) {
	log.Info("clearing stale attachment from state (attachment was deleted externally)",
		"stateKey", stateKey, "staleAttachmentId", staleID)
	c.state.Delete(stateKey)
}
