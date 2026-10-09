// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package schema applies this application's schema to a database.
//
// It exists so that using the migration machinery necessarily registers the
// migrations. Importing the runner directly would compile and run against an
// empty migration set, leaving a database that looks migrated and has no
// tables — a failure with no error message.
package schema

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"

	// Registering every migration is what this import is for, and what this
	// package exists for. It was blank until Expected gave it something to
	// name; importing the runner without it still compiles and runs against an
	// empty migration set.
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

// Up brings the database up to the schema this build expects.
//
// A database a later release has upgraded is refused. A database is only ever
// upgraded, so this build has nothing it could do to one, and the way back to
// an earlier release is the backup taken before the upgrade.
func Up(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	if err := NotBeforeTheBaseline(ctx, db); err != nil {
		return err
	}
	if err := NotAhead(ctx, db); err != nil {
		return err
	}
	if err := migrate.Up(ctx, db, logger); err != nil {
		return err
	}
	// Asked again once the lock is released: a later release may have
	// migrated while this one waited on it, which leaves this one nothing to
	// apply and a schema it cannot read.
	return NotAhead(ctx, db)
}

// NotAhead refuses a database whose schema is newer than this build's.
func NotAhead(ctx context.Context, db *database.DB) error {
	applied, err := Version(ctx, db)
	if err != nil {
		return err
	}
	wanted, err := Expected()
	if err != nil {
		return err
	}
	if applied > wanted {
		return fmt.Errorf("the database is at schema version %d, which a later release applied, and "+
			"this build carries %d: a database is only ever upgraded, so deploy the release that "+
			"upgraded it, or restore the backup taken before that upgrade", applied, wanted)
	}
	return nil
}

// NotBeforeTheBaseline refuses a database a release before v0.5.0 built.
//
// This build makes v0.5.0's schema in one migration and carries none of the
// ones before it, so it has no way to upgrade an earlier schema. v0.6.0
// carries every one of them, and a database it has upgraded is one this build
// upgrades in turn.
func NotBeforeTheBaseline(ctx context.Context, db *database.DB) error {
	applied, err := Version(ctx, db)
	if err != nil {
		return err
	}
	if BeforeTheBaseline(applied) {
		return fmt.Errorf("the database is at schema version %d, which a release before v0.5.0 "+
			"built, and this build upgrades a database v0.5.0 or a later release built: take a "+
			"backup, run openpsirt migrate up with v0.6.0, and then deploy this build", applied)
	}
	return nil
}

// BeforeTheBaseline reports whether a schema version is one a release before
// v0.5.0 built. Zero is an empty database, which the baseline makes from
// nothing.
func BeforeTheBaseline(applied int64) bool {
	return applied > 0 && applied < migrations.Baseline
}

// Version reports the schema version currently applied.
func Version(ctx context.Context, db *database.DB) (int64, error) {
	return migrate.Version(ctx, db)
}

// Expected reports the schema version this build was written against.
//
// The other half of Version. A deployment that applies migrations separately
// runs a binary and a schema that move independently, and until there was a
// number for what the binary expects there was no way to say whether they had
// moved together.
func Expected() (int64, error) {
	return migrations.Expected()
}
