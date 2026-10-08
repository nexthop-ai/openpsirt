// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
		dbtest.Empty(t, db)
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
	// Up before emptying, because emptying asks every table the latest
	// migration makes.
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
			dbtest.Empty(t, db)
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

// taggedSchema holds what a release's migrations build to what they built
// when it was tagged, which the files alone do not: the column spellings and
// widths they use are read from helpers a later change is free to edit.
//
// The expected schema was captured from the tag's migrations on each engine.
func taggedSchema(t *testing.T, version string, engine database.Engine, got []string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join(records, version, released.Schema(string(engine)))) //nolint:gosec // G304: a record in this repository, named by a release and an engine
	if err != nil {
		t.Fatalf("read what %s built on %s: %v", version, engine, err)
	}
	lines := strings.Split(strings.TrimRight(string(want), "\n"), "\n")
	if diff := setDiff(lines, got); diff != "" {
		t.Errorf("the migrations no longer build what %s built on %s:\n%s", version, engine, diff)
	}
}

func setDiff(want, got []string) string {
	var b strings.Builder
	for _, line := range want {
		if !slices.Contains(got, line) {
			fmt.Fprintf(&b, "  missing: %s\n", line)
		}
	}
	for _, line := range got {
		if !slices.Contains(want, line) {
			fmt.Fprintf(&b, "  extra:   %s\n", line)
		}
	}
	return b.String()
}
