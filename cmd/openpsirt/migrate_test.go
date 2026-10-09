// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
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
		// migration step is looking at. Emptied and built up to it, and
		// brought back to the latest when the test ends.
		short, readErr := schema.Expected()
		if readErr != nil {
			t.Fatal(readErr)
		}
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, short-1)

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

// TestStartingWithoutMigratingChecksTheSchemaFirst pins the call rather than
// the check: the server started with migration off, against a schema one
// migration short, stops before anything else and says why. The check above
// is only a control where serving reaches it.
func TestStartingWithoutMigratingChecksTheSchemaFirst(t *testing.T) {
	url := "sqlite://" + filepath.Join(t.TempDir(), "behind.db")
	target, err := database.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := schema.Expected()
	if err != nil {
		t.Fatal(err)
	}
	dbtest.MigrateTo(t, db, wanted-1)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("OPENPSIRT_DATABASE_URL", url)
	t.Setenv("OPENPSIRT_AUTO_MIGRATE", "false")
	discard, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = discard.Close() }()

	err = run(nil, discard, discard)
	if err == nil {
		t.Fatal("the server started against a schema this build is ahead of")
	}
	// The refusal the check writes, which nothing later in startup does.
	for _, want := range []string{"schema", "AUTO_MIGRATE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("starting did not stop at the schema check: %v", err)
			break
		}
	}
}

// A database is only ever upgraded, so a schema a later release applied is one
// this build refuses, whether it is asked to serve it or to migrate it, and the
// refusal says both versions and the way back.
func TestASchemaAheadOfThisBuildIsRefused(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if err := schema.Up(ctx, db, silent()); err != nil {
			t.Fatalf("migrate up: %v", err)
		}
		wanted, err := schema.Expected()
		if err != nil {
			t.Fatalf("expected: %v", err)
		}
		// Standing in for a later release's migration, recorded the way the
		// library records one. The tables it would have made are beside the
		// point: what is pinned is that a higher applied version is refused.
		if _, err := db.ExecContext(ctx,
			`INSERT INTO "goose_db_version" ("version_id", "is_applied") VALUES (?, ?)`,
			wanted+1, true); err != nil {
			t.Fatalf("record a later migration: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.WithoutCancel(ctx),
				`DELETE FROM "goose_db_version" WHERE "version_id" = ?`, wanted+1)
		})

		for what, err := range map[string]error{
			"serving":   schemaIsCurrent(ctx, db, silent()),
			"migrating": schema.Up(ctx, db, silent()),
		} {
			if err == nil {
				t.Errorf("%s a schema ahead of this build was allowed", what)
				continue
			}
			for _, want := range []string{itoa(wanted + 1), itoa(wanted), "restore the backup"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: the refusal does not say %q: %v", what, want, err)
				}
			}
		}
	})
}

// A database a release before v0.5.0 built records a version below the
// migration that makes v0.5.0's schema at once. Serving or migrating it is
// refused before anything runs, naming the version and the release that
// upgrades it.
func TestASchemaFromBeforeTheBaselineIsRefused(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, migrations.Baseline)
		// Standing in for v0.4.0's last migration, recorded the way the
		// library records one, in place of the baseline's.
		const v040 = 38
		record := func(ctx context.Context, from, to int64) error {
			if _, err := db.ExecContext(ctx,
				`DELETE FROM "goose_db_version" WHERE "version_id" = ?`, from); err != nil {
				return err
			}
			_, err := db.ExecContext(ctx,
				`INSERT INTO "goose_db_version" ("version_id", "is_applied") VALUES (?, ?)`, to, true)
			return err
		}
		if err := record(ctx, migrations.Baseline, v040); err != nil {
			t.Fatalf("record v0.4.0's last migration: %v", err)
		}
		t.Cleanup(func() {
			if err := record(context.WithoutCancel(ctx), v040, migrations.Baseline); err != nil {
				t.Errorf("record the baseline again: %v", err)
			}
		})

		for what, err := range map[string]error{
			"serving":   schemaIsCurrent(ctx, db, silent()),
			"migrating": schema.Up(ctx, db, silent()),
		} {
			if err == nil {
				t.Errorf("%s a schema a release before v0.5.0 built was allowed", what)
				continue
			}
			for _, want := range []string{itoa(v040), "v0.6.0"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: the refusal does not say %q: %v", what, want, err)
				}
			}
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
