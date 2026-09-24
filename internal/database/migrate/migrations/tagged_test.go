// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/released"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// Each tagged release's migrations still build, on every engine, the schema
// they built when the release was tagged.
func TestEachReleaseBuildsTheSchemaItTagged(t *testing.T) {
	tagged, err := released.All(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(tagged) == 0 {
		t.Fatal("no release is recorded, so nothing was checked")
	}
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		for _, r := range tagged {
			dbtest.MigrateTo(t, db, r.Last)
			taggedSchema(t, r.Version, db.Server.Engine, describe(t, ctx, db))
		}
		leaveAtLatest(t, ctx, db)
	})
}

// leaveAtLatest empties the database and migrates it to the latest, which is
// where every other test in the package expects it.
func leaveAtLatest(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	dbtest.Reset(t, db)
	if err := schema.Up(ctx, db, quiet()); err != nil {
		t.Fatalf("migrate to the latest: %v", err)
	}
	dbtest.Reset(t, db)
}
