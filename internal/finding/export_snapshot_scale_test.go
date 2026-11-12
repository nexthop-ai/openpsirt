// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package finding_test

import (
	"context"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// exportPage is the page a findings file is read in.
const exportPage = 200

// A product's findings file, read the way the export reads it: every page of
// the list's groups at the file's page size, inside one read-only snapshot,
// and the same pages read one statement each outside one. A file is cut at the
// export ceiling, so the whole read has to sit well inside it.
func TestMeasureAFindingsFileReadInOneSnapshot(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		other := seedAcross(t, w)
		dbtest.SettleStatistics(t, db)
		reader := access.NewPerson(1_000_000, "a reader", false, map[int64][]access.Role{
			w.Product.ID: {access.PublicRead, access.PrivateRead},
			other.ID:     {access.PublicRead, access.PrivateRead},
		}, 0)
		scope := finding.Scope{ProductID: &w.Product.ID}

		read := func(q bun.IDB) (rows, pages int, slowest time.Duration) {
			t.Helper()
			store := finding.NewStore(q)
			for offset := 0; ; offset += exportPage {
				at := time.Now()
				groups, _, err := store.Groups(ctx, reader, scope, exportPage, offset, finding.Filter{})
				if err != nil {
					t.Fatal(err)
				}
				slowest = max(slowest, time.Since(at))
				rows += len(groups)
				pages++
				if len(groups) < exportPage {
					return rows, pages, slowest
				}
			}
		}

		at := time.Now()
		var rows, pages int
		var slowest time.Duration
		if err := database.Snapshot(ctx, db, func(_ context.Context, view bun.IDB) error {
			rows, pages, slowest = read(view)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		inside := time.Since(at)
		at = time.Now()
		_, _, slowestOutside := read(db)
		t.Logf("%d rows in %d pages: %s in one snapshot (slowest page %s), %s a statement each (slowest %s)",
			rows, pages, inside.Round(time.Millisecond), slowest.Round(time.Millisecond),
			time.Since(at).Round(time.Millisecond), slowestOutside.Round(time.Millisecond))
	})
}
