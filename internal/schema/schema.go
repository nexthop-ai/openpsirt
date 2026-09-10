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

	// Registers every migration. This blank import is the reason this package
	// exists; do not remove it.
	_ "github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
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
