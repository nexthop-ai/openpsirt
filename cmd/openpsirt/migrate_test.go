// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
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
			strconv.FormatInt(applied, 10), strconv.FormatInt(wanted, 10),
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
			`INSERT INTO "`+migrate.VersionTable+`" ("version_id", "is_applied") VALUES (?, ?)`,
			wanted+1, true); err != nil {
			t.Fatalf("record a later migration: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.WithoutCancel(ctx),
				`DELETE FROM "`+migrate.VersionTable+`" WHERE "version_id" = ?`, wanted+1)
		})

		for what, err := range map[string]error{
			"serving":   schemaIsCurrent(ctx, db, silent()),
			"migrating": schema.Up(ctx, db, silent()),
		} {
			if err == nil {
				t.Errorf("%s a schema ahead of this build was allowed", what)
				continue
			}
			for _, want := range []string{strconv.FormatInt(wanted+1, 10), strconv.FormatInt(wanted, 10), "restore the backup"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: the refusal does not say %q: %v", what, want, err)
				}
			}
		}
	})
}

// A database a release before v0.7.0 built records a version from 1 to 40,
// below the migration that makes v0.7.0's schema at once. Serving or
// migrating it is refused before anything runs, naming the version and the
// releases that upgrade it. The baseline's own version is not refused.
func TestASchemaFromBeforeTheBaselineIsRefused(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, migrations.Baseline)
		// An earlier release's last migration, recorded the way the library
		// records one, in place of the baseline's.
		record := func(ctx context.Context, from, to int64) error {
			if _, err := db.ExecContext(ctx,
				`DELETE FROM "`+migrate.VersionTable+`" WHERE "version_id" = ?`, from); err != nil {
				return err
			}
			_, err := db.ExecContext(ctx,
				`INSERT INTO "`+migrate.VersionTable+`" ("version_id", "is_applied") VALUES (?, ?)`, to, true)
			return err
		}
		// v0.8.0 upgrades a database from its own baseline, 39, on, and
		// refuses one below it, which v0.6.0 upgrades first.
		for _, c := range []struct {
			earlier int64
			with    string
		}{
			{1, "with v0.6.0 and then v0.8.0,"},
			{38, "with v0.6.0 and then v0.8.0,"},
			{39, "with v0.8.0,"},
			{migrations.Baseline - 1, "with v0.8.0,"},
		} {
			earlier := c.earlier
			if err := record(ctx, migrations.Baseline, earlier); err != nil {
				t.Fatalf("record version %d: %v", earlier, err)
			}
			for what, err := range map[string]error{
				"serving":   schemaIsCurrent(ctx, db, silent()),
				"migrating": schema.Up(ctx, db, silent()),
			} {
				if err == nil {
					t.Errorf("%s a schema at version %d was allowed", what, earlier)
					continue
				}
				for _, want := range []string{"version " + strconv.FormatInt(earlier, 10) + ",", "v0.7.0", c.with} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s: the refusal does not say %q: %v", what, want, err)
					}
				}
			}
			if err := record(context.WithoutCancel(ctx), earlier, migrations.Baseline); err != nil {
				t.Fatalf("record the baseline again: %v", err)
			}
		}
		if err := schema.NotBeforeTheBaseline(ctx, db); err != nil {
			t.Errorf("the baseline's own version was refused: %v", err)
		}
	})
}

// migrate status names a version before the baseline as one, with the
// releases that upgrade it, and says how every other version stands against this
// build's.
func TestMigrateStatusSaysWhereASchemaStands(t *testing.T) {
	wanted, err := schema.Expected()
	if err != nil {
		t.Fatal(err)
	}
	twice := "before the baseline: upgrade it with v0.6.0 and then v0.8.0 first"
	once := "before the baseline: upgrade it with v0.8.0 first"
	for _, c := range []struct {
		applied int64
		want    string
	}{
		{0, "behind by " + strconv.FormatInt(wanted, 10)},
		{1, twice},
		{38, twice},
		{39, once},
		{migrations.Baseline - 1, once},
		{migrations.Baseline, "behind by " + strconv.FormatInt(wanted-migrations.Baseline, 10)},
		{wanted, "the version this build expects"},
		{wanted + 1, "ahead of this build"},
	} {
		if got := schemaState(c.applied, wanted); got != c.want {
			t.Errorf("version %d of %d reads %q, want %q", c.applied, wanted, got, c.want)
		}
	}
}
