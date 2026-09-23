// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"io"
	"log/slog"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// MigrateTo applies the migrations up to and including a version, which is
// how a test builds the schema a release shipped.
//
// Through a provider of its own rather than the migration library's shared
// state, which the migration runner serializes behind a lock of its own: a
// provider reads the registered migrations and holds its dialect itself, so it
// races with nothing.
func MigrateTo(t *testing.T, db *database.DB, version int64) {
	t.Helper()
	dialects := map[database.Engine]goose.Dialect{
		database.Postgres: goose.DialectPostgres,
		database.MySQL:    goose.DialectMySQL,
		database.MariaDB:  goose.DialectMySQL,
		database.SQLite:   goose.DialectSQLite3,
	}
	dialect, ok := dialects[db.Server.Engine]
	if !ok {
		t.Fatalf("no migration dialect for %s", db.Server.Engine)
	}
	provider, err := goose.NewProvider(dialect, db.DB.DB, nil)
	if err != nil {
		t.Fatalf("prepare the migrations: %v", err)
	}
	ctx := migrate.WithEngine(t.Context(), db.Server.Engine, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := provider.UpTo(ctx, version); err != nil {
		t.Fatalf("apply the migrations up to %d: %v", version, err)
	}
}
