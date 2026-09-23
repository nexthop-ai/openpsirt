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
func Up(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	return migrate.Up(ctx, db, logger)
}

// Down rolls back the most recent migration.
func Down(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	return migrate.Down(ctx, db, logger)
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
