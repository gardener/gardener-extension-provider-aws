// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
//

package charts

import (
	"embed"
)

// InternalChart embeds the internal charts in embed.FS
//
//go:embed internal
var InternalChart embed.FS

const (
	// InternalChartsPath is the path to the internal charts.
	InternalChartsPath = "internal"
)
