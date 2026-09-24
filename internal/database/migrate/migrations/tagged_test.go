// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// The schema a release builds, written into its record on every engine. make
// release-freeze runs it on the commit to be tagged; it is skipped otherwise,
// because it writes into the tree.
func TestWriteTheSchemaAReleaseTags(t *testing.T) {
	tag := os.Getenv("OPENPSIRT_RELEASE_FREEZE")
	if tag == "" {
		t.Skip("writes a release's record: make release-freeze runs it")
	}
	version, err := released.Base(tag)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(records, version)
	if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // G703: a record directory named by a release tag Base checked
		t.Fatal(err)
	}
	var mu sync.Mutex
	wrote := map[string]bool{}
	t.Run("engines", func(t *testing.T) {
		dbtest.Each(t, func(t *testing.T, db *database.DB) {
			ctx := t.Context()
			rollBack(t, ctx, db)
			if err := schema.Up(ctx, db, quiet()); err != nil {
				t.Fatalf("migrate to the latest: %v", err)
			}
			lines := describe(t, ctx, db)
			engine := string(db.Server.Engine)
			if err := os.WriteFile(filepath.Join(dir, released.Schema(engine)), //nolint:gosec // G703: the record directory above and an engine name
				[]byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			wrote[engine] = true
			mu.Unlock()
			dbtest.Reset(t, db)
		})
	})
	for _, engine := range released.Engines {
		if !wrote[engine] {
			t.Errorf("nothing was written for %s: a release is recorded on every engine, so run make engines-up first",
				engine)
		}
	}
}
