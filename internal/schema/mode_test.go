package schema_test

import (
	"context"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

func TestAnOversizedValueIsRefusedRatherThanTruncated(t *testing.T) {
	// Asking two of the engines for standard identifier quoting nearly cost
	// this the strictness that makes an oversized value an error. Setting a
	// mode replaces it rather than adding to it, and what it replaced included
	// the rule that refuses a value too long for its column — so a nine
	// character string went into a four character column and came back four
	// characters long, with no error, on two engines and not on the other two.
	//
	// Silent truncation is the worst shape a portability difference can take:
	// nothing fails, and the data is wrong. This is here so that the quoting
	// setting can never be written in a way that turns it off again.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := context.Background()
		if _, err := db.ExecContext(ctx, `CREATE TABLE "strict_probe" ("c" VARCHAR(4))`); err != nil {
			t.Fatalf("create: %v", err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DROP TABLE "strict_probe"`) })

		const written = "123456789"
		if _, err := db.ExecContext(ctx,
			`INSERT INTO "strict_probe" ("c") VALUES (?)`, written); err != nil {
			return // Refused outright, which is one correct answer.
		}

		// The other correct answer is to store it whole — one engine does not
		// constrain a text column's width at all, which is documented
		// behavior and loses nothing. What must never happen is the third
		// outcome: accepted, changed, and no error.
		var stored string
		if err := db.QueryRowContext(ctx, `SELECT "c" FROM "strict_probe"`).Scan(&stored); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if stored != written {
			t.Errorf("a value was accepted and silently changed: wrote %q, read %q", written, stored)
		}
	})
}

func TestStandardQuotingSurvivesAlongsideStrictness(t *testing.T) {
	// Both at once, because the fix for one is what broke the other: the
	// quoting is asked for by appending to the mode, and appending is only
	// correct if what was already there is still in force.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := context.Background()
		if _, err := db.ExecContext(ctx, `CREATE TABLE "both_probe" ("rank" BIGINT, "order" INT)`); err != nil {
			t.Fatalf("standard quoting is not in force: %v", err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DROP TABLE "both_probe"`) })

		if _, err := db.ExecContext(ctx, `INSERT INTO "both_probe" ("rank", "order") VALUES (1, 2)`); err != nil {
			t.Fatalf("insert: %v", err)
		}
		var rank int
		if err := db.QueryRowContext(ctx, `SELECT "rank" FROM "both_probe"`).Scan(&rank); err != nil {
			t.Fatalf("select: %v", err)
		}
		if rank != 1 {
			t.Errorf("read %d", rank)
		}
	})
}
