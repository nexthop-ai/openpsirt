// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package adminapi holds the operations that administer the deployment: the
// catalog, people and their roles, keys and tokens, settings, and the trail.
package adminapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// Register adds the operations that administer the deployment: the catalog,
// people and their roles, keys and tokens, settings, and the trail.
func Register(api huma.API, in core.Deps) {
	registerNotifications(api, in)
	registerDigest(api, in)
	registerChatChoices(api, in)
	registerTokens(api, in)
	registerSettings(api, in)
	// Work the queue set aside, and putting it back.
	registerWork(api, in)
	registerTrail(api, in)
	registerSaved(api, in)
	registerWhoAmI(api, in)
	registerBindings(api, core.Administering{
		DB: in.DB, Access: in.Rights, Catalog: in.Catalog, Logger: in.Logger,
	}, in.Settings)
	registerCatalog(api, core.Declaring{
		DB: in.DB, Store: in.Catalog, Logger: in.Logger,
		Findings: func() *finding.Store {
			if in.DB == nil {
				return nil
			}
			return finding.NewStore(in.DB.DB)
		},
		Scans: func() *ingest.Store {
			if in.DB == nil {
				return nil
			}
			return ingest.NewStore(in.DB.DB)
		},
		RewriteDeadlines: deadlinesRewritten(in),
	})
	registerAdministration(api, core.Administering{
		DB: in.DB, Access: in.Rights, Catalog: in.Catalog, Logger: in.Logger,
		Findings: func() *finding.Store {
			if in.DB == nil {
				return nil
			}
			return finding.NewStore(in.DB.DB)
		},
		Settings: in.Settings,
	})
	// One person, whole: the grants in force, the grants withdrawn, their part
	// in the record, and what they were told.
	registerPerson(api, in, core.Administering{
		DB: in.DB, Access: in.Rights, Catalog: in.Catalog, Logger: in.Logger,
		// Deactivating somebody hands back what they were dealing with.
		Findings: func() *finding.Store {
			if in.DB == nil {
				return nil
			}
			return finding.NewStore(in.DB.DB)
		},
	})
	registerRevocation(api, core.Administering{
		DB: in.DB, Access: in.Rights, Catalog: in.Catalog, Logger: in.Logger,
	})
}
