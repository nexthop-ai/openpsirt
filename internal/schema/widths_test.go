// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

func TestProducerSuppliedTextIsNotBoundedByAColumn(t *testing.T) {
	// A component's name and version are whatever a producer put in a scan
	// file. Nothing in any format bounds them, and a column that does turns a
	// merely unusual value into a failure of the whole scan that carried it —
	// which is indistinguishable from a product that stopped having problems.
	//
	// Two of the four engines gave this class a 64 KB type while giving the
	// operator-typed class beside it 16 MB, which is the inversion of what the
	// two are declared to mean: typed text is at least bounded at submission,
	// and this is not bounded anywhere.
	//
	// A hundred kilobytes because it is past the smaller type and nowhere near
	// the larger, so this fails on exactly the engines that get it wrong.
	const size = 100 * 1024
	oversized := strings.Repeat("v", size)

	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		// A hex digest, because identity and fold_key are digest columns and
		// are 64 characters wide on every engine. What is under test is the
		// class beside them.
		identity := fmt.Sprintf("%064x", probeCounter.Add(1)+time.Now().UnixNano())
		if _, err := db.ExecContext(ctx,
			`INSERT INTO "component" ("identity", "name", "version", "fold_key", "first_seen_at")
			 VALUES (?, ?, ?, ?, ?)`,
			identity, oversized, oversized, identity, time.Now().UTC()); err != nil {
			t.Fatalf("a %d-byte value a producer supplied was refused: %v", size, err)
		}
		// Not the test's own context: it is canceled by the time a cleanup
		// runs, so two 100 KiB values would be left behind on every engine.
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.WithoutCancel(ctx),
				`DELETE FROM "component" WHERE "identity" = ?`, identity)
		})

		var name, version string
		if err := db.QueryRowContext(ctx,
			`SELECT "name", "version" FROM "component" WHERE "identity" = ?`, identity).
			Scan(&name, &version); err != nil {
			t.Fatalf("read back: %v", err)
		}
		for what, got := range map[string]string{"name": name, "version": version} {
			if got != oversized {
				t.Errorf("%s came back %d bytes, wrote %d", what, len(got), size)
			}
		}
	})
}

func TestWhatAScannerCallsItselfIsNotBoundedByAColumn(t *testing.T) {
	// The other half of the same class, and the one strictness turns from a
	// truncation into a failure: what the scanner calls itself, its version
	// and the version of the data it read are taken verbatim from its output
	// and bounded by nothing on the way in. Left in the indexed-name slot they
	// are 191 characters on three engines, so one scan file fails the whole
	// run there and succeeds on SQLite.
	//
	// Long rather than enormous, because the point is that nothing bounds
	// these rather than that they are ever large.
	oversized := strings.Repeat("s", 4096)

	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx, db, target := t.Context(), w.DB, w.Target.ID
		if _, err := db.ExecContext(ctx,
			`INSERT INTO "scan_run" ("target_id", "scanner", "scanner_version",
				"database_version", "ran_here", "started_at")
			 VALUES (?, ?, ?, ?, ?, ?)`,
			target, oversized, oversized, oversized, true, time.Now().UTC()); err != nil {
			t.Fatalf("a scanner's own words were refused at %d bytes: %v", len(oversized), err)
		}
		// Read back by the build rather than by an inserted identifier, which
		// one of the four drivers does not report. The database is this
		// test's alone, so the build names exactly the row just written.

		var scanner, version, data string
		if err := db.QueryRowContext(ctx,
			`SELECT "scanner", "scanner_version", "database_version"
			 FROM "scan_run" WHERE "target_id" = ?`, target).Scan(&scanner, &version, &data); err != nil {
			t.Fatalf("read back: %v", err)
		}
		for what, got := range map[string]string{
			"scanner": scanner, "scanner_version": version, "database_version": data,
		} {
			if got != oversized {
				t.Errorf("%s came back %d bytes, wrote %d", what, len(got), len(oversized))
			}
		}
	})
}
