// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

// A v0.12.0 database upgrades to v0.13.0's declarations, from the start and
// from a start on MySQL or MariaDB that stopped after the withdrawer's column
// committed and before its key. The declarations are the whole check.
func withdrawerPartV0130() partV0130 {
	return partV0130{
		name: "TheWithdrawerIsDeclared",
		stops: []stopV0130{
			{"after the withdrawer's column", func(t *testing.T, db *database.DB) error {
				return migrations.StopV0130AfterEndedByColumn(t.Context(), db)
			}},
		},
	}
}
