// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package assignapi holds the operations that hand work out: assignment,
// routing rules, teams, tags, bulk acts, fix bundles and planned upgrades.
package assignapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Register adds the operations that hand work to people and teams: assignment,
// routing rules, teams, tags, bulk acts, fix bundles and upgrades.
func Register(api huma.API, in core.Deps) {
	registerComponent(api, in)
	registerPlanUpgrade(api, in)
	registerAssignment(api, in)
	registerAssignMatching(api, in)
	registerBundles(api, in)
	registerPendingUpgrades(api, in)
	registerRouting(api, in)
	registerBulk(api, in)
	registerTeams(api, core.Administering{
		DB: in.DB, Access: in.Rights, Catalog: in.Catalog, Logger: in.Logger,
	})
	// The words people put on findings.
	registerTags(api, in)
}
