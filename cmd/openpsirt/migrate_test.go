package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestServingIsRefusedWhenTheSchemaIsBehindThisBuild(t *testing.T) {
	// Applying migrations separately is supported and is the whole reason the
	// setting exists. What it leaves is a binary and a schema that move
	// independently, and nothing compared them: a build carrying a new
	// migration started, granted administrators, answered the readiness probe
	// — which is a bare ping — and failed every request that touched the new
	// table. In a rolling deployment, the probe passing is what retires the
	// last replica that still worked.
	//
	// Two engines, because nothing here varies by engine and the version is
	// read through the same portable path on all four.
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if err := schema.Up(ctx, db, silent()); err != nil {
			t.Fatalf("migrate up: %v", err)
		}
		// Current, so serving is allowed.
		if err := schemaIsCurrent(ctx, db, silent()); err != nil {
			t.Fatalf("a current schema was refused: %v", err)
		}

		// One migration short, which is what a build deployed ahead of its
		// migration step is looking at.
		if err := schema.Down(ctx, db, silent()); err != nil {
			t.Fatalf("roll back one: %v", err)
		}
		// Not the test's own context: it is canceled by the time a cleanup
		// runs, so the repair would be issued against a dead context and the
		// database would stay one migration short for every test after this.
		t.Cleanup(func() { _ = schema.Up(context.WithoutCancel(ctx), db, silent()) })

		err := schemaIsCurrent(ctx, db, silent())
		if err == nil {
			t.Fatal("serving against a schema this build is ahead of was allowed")
		}
		// The refusal has to say both numbers and what to do, or it is a
		// startup failure an operator has to guess at.
		applied, readErr := schema.Version(ctx, db)
		if readErr != nil {
			t.Fatalf("version: %v", readErr)
		}
		wanted, readErr := schema.Expected()
		if readErr != nil {
			t.Fatalf("expected: %v", readErr)
		}
		for _, want := range []string{
			"migrate up", "AUTO_MIGRATE",
			itoa(applied), itoa(wanted),
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not say %q: %v", want, err)
			}
		}
	})
}

func TestASchemaAheadOfThisBuildStillServes(t *testing.T) {
	// A rollback has to keep working. The migrations a newer binary applied
	// are additive, so the older one's queries still run — and refusing here
	// would leave a bad deployment with no way back, which is the opposite of
	// what a startup check is for.
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if err := schema.Up(ctx, db, silent()); err != nil {
			t.Fatalf("migrate up: %v", err)
		}
		wanted, err := schema.Expected()
		if err != nil {
			t.Fatalf("expected: %v", err)
		}
		// Standing in for a newer binary's migration, recorded the way the
		// library records one. The tables it would have made are beside the
		// point: what is being pinned is that a higher applied version is not
		// a refusal.
		if _, err := db.ExecContext(ctx,
			`INSERT INTO "goose_db_version" ("version_id", "is_applied") VALUES (?, ?)`,
			wanted+1, true); err != nil {
			t.Fatalf("record a later migration: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.WithoutCancel(ctx),
				`DELETE FROM "goose_db_version" WHERE "version_id" = ?`, wanted+1)
		})

		if err := schemaIsCurrent(ctx, db, silent()); err != nil {
			t.Errorf("a rollback was refused its own schema: %v", err)
		}
	})
}

// itoa keeps the assertion above readable without pulling in a formatter for
// one number.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
