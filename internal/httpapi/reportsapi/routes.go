// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package reportsapi holds the operations that report across builds and
// products, and the exports that hand the same lists over as files.
package reportsapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Register adds the operations that report across builds and products, and the
// exports that hand the same lists over as files.
func Register(api huma.API, in core.Deps) {
	registerInventoryChanges(api, in)
	// Which names two builds differ on, and the same as a file.
	registerInventoryComparison(api, in)
	registerInventoryComparisonExport(api, in)
	// One product's own page.
	registerOverview(api, in)
	registerCoverage(api, in)
	registerCoverageExport(api, in)
	registerOutOfSupport(api, in)
	registerPublished(api, in)
	registerAudit(api, in)
	registerRemediation(api, in)
	registerNotes(api, in)
	registerReleaseTrend(api, in)
	registerCarrying(api, in)
	registerDue(api, in)
	registerExport(api, in)
	registerAnywhereExport(api, in)
	// The three lists that could be read and not taken away.
	registerMoreExports(api, in)
	registerRegister(api, in)
	registerCompliance(api, in)
	registerReports(api, in)
	registerMeasures(api, in)
	registerEffort(api, in)
	registerCarry(api, in)
	registerIssueDocument(api, in)
}
