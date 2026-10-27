// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package assignapi holds the operations that hand work out: assignment of
// findings and code findings, assignment rules, teams, tags, bulk acts, planned upgrades and planned upgrades.
package assignapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Register adds the operations that hand work to people and teams: assignment,
// assignment rules, teams, tags, bulk acts, planned upgrades and upgrades.
func Register(api huma.API, in core.Deps) {
	registerComponent(api, in)
	registerPlanUpgrade(api, in)
	registerAssignment(api, in)
	registerAssignMatching(api, in)
	registerCodeFindingAssigning(api, in)
	registerReportAssignment(api, in)
	registerPlannedUpgrades(api, in)
	registerBuildPlannedUpgrades(api, in)
	registerAssignmentRules(api, in)
	registerBulk(api, in)
	// A change to a team's membership hands back what no remaining member
	// reads.
	registerTeams(api, core.Administering{
		DB: in.DB, Access: in.Rights, Catalog: in.Catalog, Logger: in.Logger,
		Findings: func() *finding.Store {
			return finding.NewStore(in.DB.DB)
		},
	})
	// The words people put on findings.
	registerTags(api, in)
}
