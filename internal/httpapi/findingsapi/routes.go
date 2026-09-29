// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package findingsapi holds the operations over findings and issues: the
// lists, one finding, entered findings, disclosure, notes, the component
// graph, collaborators, and reports from outside.
package findingsapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Register adds the operations over findings and issues: the lists, one finding,
// what was entered by hand, disclosure, notes, and the component graph.
func Register(api huma.API, in core.Deps) {
	registerFindings(api, in)
	registerComponentFindings(api, in)
	// The findings list across every product somebody may see.
	registerAnywhere(api, in)
	// The kinds of package open findings sit at, for the list's filter.
	registerKinds(api, in)
	registerHolders(api, in)
	registerFindingDetail(api, in)
	registerEntry(api, in)
	registerDisclosure(api, in)
	registerResolution(api, in)
	registerAttachments(api, in)
	registerScoring(api, in)
	// What a weakness is called, and a search over both lists of names.
	registerWeaknesses(api)
	registerAffects(api, in)
	registerMovements(api, in)
	registerGraph(api, in)
	registerMatchCoverage(api, in)
	registerMatchCoverageExport(api, in)
	// Components with no upstream answer, and the reason for each.
	registerUpstream(api, in)
	registerPatchBranches(api, in)
	registerMentions(api, in)
	registerCarried(api, in)
	registerIssueNotes(api, in)
	// The record of who told us, and the names an issue goes by.
	registerWhoTold(api, in)
	registerIntake(api, in)
	// One issue, everywhere it sits, across products.
	registerIssue(api, in)
	// The tree seen upward, for somebody narrowed to their own work.
	registerUpward(api, in)
	// The people on one undisclosed case. It takes both: the grant is managed
	// by whoever reads the case rather than by an administrator, and it lands
	// in the administration trail like every other access change.
	registerCollaborators(api, in, core.Administering{
		DB: in.DB, Access: in.Rights, Catalog: in.Catalog, Logger: in.Logger,
	})
}
