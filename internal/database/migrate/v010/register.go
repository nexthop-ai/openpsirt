// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package v010 is the schema the v0.1.0 release built, frozen.
//
// Every numbered file here is that release's migration as it was tagged. Four
// things differ, and nothing else: the package clause; a license header where
// the file had none; the call each file registers itself with; and the two
// column widths, which are constants here rather than read from the database
// package, so that widening a name there cannot move what this package builds.
//
// It builds a database that looks exactly like one a v0.1.0 deployment holds,
// migration bookkeeping included, so that the upgrade from it is tested against
// the real thing rather than a description of it. Nothing outside the tests
// builds one: a deployment that holds a v0.1.0 database already has it.
package v010

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// The widths the v0.1.0 schema was declared with.
const (
	nameWidth     = 191
	composedWidth = 3*nameWidth + 20
)

// registered is this package's migrations, kept apart from the library's
// global registry. The current migrations register there under the same
// version numbers, and the two sets have to coexist in one test binary.
var registered []*goose.Migration

func register(up, down func(context.Context, *sql.Tx) error) {
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		panic("v010: cannot name the file registering a migration")
	}
	version, err := goose.NumericComponent(filepath.Base(file))
	if err != nil {
		panic(fmt.Sprintf("v010: %s: %v", file, err))
	}
	registered = append(registered, goose.NewGoMigration(version,
		&goose.GoFunc{RunTx: up}, &goose.GoFunc{RunTx: down}))
}

// Up builds the v0.1.0 schema on an empty database, recording each migration
// in the same bookkeeping table the release recorded it in.
func Up(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	dialect, err := migrate.Dialect(db.Server.Engine)
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(dialect, db.DB.DB, nil,
		goose.WithDisableGlobalRegistry(true),
		goose.WithGoMigrations(registered...))
	if err != nil {
		return fmt.Errorf("v0.1.0 migrations: %w", err)
	}
	if _, err := provider.Up(migrate.WithEngine(ctx, db.Server.Engine, logger)); err != nil {
		return fmt.Errorf("v0.1.0 migrations: %w", err)
	}
	return nil
}
