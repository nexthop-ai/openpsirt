// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package scansapi holds the operations a build sends its inventory through,
// and the receipts, documents and scanner runs it reads back.
package scansapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Register adds the operations a build sends its inventory through, and the receipts,
// documents and runs it can read back.
func Register(api huma.API, in core.Deps) {
	registerScans(api, in)
	registerReceipts(api, in)
	// Reading back a document a build sent.
	registerRetained(api, in)
	// One run of the scanner.
	registerRun(api, in)
}
