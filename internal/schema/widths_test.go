package schema_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
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
	// The other half of the same class, and the one strictness turned from a
	// truncation into a failure: what the scanner calls itself, its version
	// and the version of the data it read are taken verbatim from its output
	// and bounded by nothing on the way in. Left in the indexed-name slot,
	// they were 191 characters on three engines — so one scan file would fail
	// the whole run there and succeed on SQLite.
	//
	// Long rather than enormous, because the point is that nothing bounds
	// these rather than that they are ever large.
	oversized := strings.Repeat("s", 4096)

	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		target := aTarget(t, db)
		if _, err := db.ExecContext(ctx,
			`INSERT INTO "scan_run" ("target_id", "scanner", "scanner_version",
				"database_version", "ran_here", "started_at")
			 VALUES (?, ?, ?, ?, ?, ?)`,
			target, oversized, oversized, oversized, true, time.Now().UTC()); err != nil {
			t.Fatalf("a scanner's own words were refused at %d bytes: %v", len(oversized), err)
		}
		// Read back by the build rather than by an inserted identifier, which
		// one of the four drivers does not report — and the build is this
		// test's own, so it names exactly the row just written.
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.WithoutCancel(ctx),
				`DELETE FROM "scan_run" WHERE "target_id" = ?`, target)
		})

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

// aTarget makes the build a scan run has to point at, and returns its
// identifier.
//
// Hand-rolled, because internal/dbtest exports lifecycle and no fixtures — the
// reason thirty-five files do the same thing beside this one.
func aTarget(t *testing.T, db *database.DB) int64 {
	t.Helper()
	ctx := t.Context()
	name := uniqueName(t)
	now := time.Now().UTC()

	insert := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	read := func(statement string, args ...any) int64 {
		t.Helper()
		var id int64
		if err := db.QueryRowContext(ctx, statement, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
		return id
	}

	insert(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`,
		name, name, now)
	productID := read(`SELECT "id" FROM "product" WHERE "name" = ?`, name)

	insert(`INSERT INTO "stream" ("product_id", "name", "display_name", "kind", "created_at")
		VALUES (?, ?, ?, ?, ?)`, productID, name, name, "branch", now)
	streamID := read(`SELECT "id" FROM "stream" WHERE "product_id" = ? AND "name" = ?`, productID, name)

	insert(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
		VALUES (?, ?, ?, ?, ?)`, productID, name, name, true, now)
	variantID := read(`SELECT "id" FROM "variant" WHERE "product_id" = ? AND "name" = ?`, productID, name)

	insert(`INSERT INTO "target" ("stream_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
		streamID, variantID, now)
	targetID := read(`SELECT "id" FROM "target" WHERE "stream_id" = ? AND "variant_id" = ?`,
		streamID, variantID)

	// Removed in the order the foreign keys allow, and on a context the test's
	// own is not, because a cleanup runs after that one is canceled.
	t.Cleanup(func() {
		clean := context.WithoutCancel(ctx)
		for _, step := range []struct {
			statement string
			id        int64
		}{
			{`DELETE FROM "target" WHERE "id" = ?`, targetID},
			{`DELETE FROM "variant" WHERE "id" = ?`, variantID},
			{`DELETE FROM "stream" WHERE "id" = ?`, streamID},
			{`DELETE FROM "product" WHERE "id" = ?`, productID},
		} {
			_, _ = db.ExecContext(clean, step.statement, step.id)
		}
	})
	return targetID
}
