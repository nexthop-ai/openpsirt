// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// An upgrade to v0.11.0 stopped between adding the issue kind and dropping the
// default that filled it is carried through v0.12.0 to the issue kind as
// declared, with no default. MySQL and MariaDB keep the column through the
// stop, and the resumed v0.11.0 upgrade steps over it.
func TestTheIssueKindHoldsNoDefaultAfterAStoppedUpgrade(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if engine := db.Server.Engine; engine == database.Postgres || engine == database.SQLite {
			t.Skip("the v0.11.0 upgrade changes the table in one transaction here, so a stop keeps no column")
		}
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		if err := migrations.StopV0110AfterAddingIssueKind(ctx, db); err != nil {
			t.Fatalf("make what a stopped upgrade left: %v", err)
		}
		stopped := ""
		for _, line := range describe(t, ctx, db) {
			if strings.HasPrefix(line, "column vulnerability.kind ") {
				stopped = line
			}
		}
		if stopped == "" || strings.Contains(stopped, " default=- ") {
			t.Fatalf("the stopped upgrade left the issue kind as %q, not filled by a default, so this checked nothing", stopped)
		}
		dbtest.MigrateTo(t, db, v0120)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0120(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}
