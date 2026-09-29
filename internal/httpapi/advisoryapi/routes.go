// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package advisoryapi holds the operations over advisories and VEX: issuing
// them, importing a supplier's, and the suppliers read on a schedule.
package advisoryapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// Register adds the operations over advisories and VEX: issuing them, importing a
// supplier's, and the suppliers read on a schedule.
func Register(api huma.API, in core.Deps) {
	registerAdvisory(api, in)
	// What an advisory states about each release, and marking one affected.
	registerReleases(api, in)
	registerVexImport(api, in)
	registerAdvisoryImport(api, in)
	// The suppliers whose published advisories are read on a schedule, which
	// is the same evidence arriving without anybody choosing each document.
	registerAdvisorySources(api, in)
	// Standing claims about the third-party components a build ships.
	registerVEX(api, in)
	// The destinations this deployment posts to.
	registerOutbound(api, in, core.Administering{
		DB: in.DB, Access: in.Rights, Catalog: in.Catalog, Logger: in.Logger,
	})
}
