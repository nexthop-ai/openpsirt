// Package migrate applies schema changes.
//
// Migrations are embedded in the binary, so a deployment is one artifact and
// there is no separate step or script to run. They apply at startup by default
// and can also be run on their own, under different credentials, by an operator
// who wants to see what will change first.
package migrate

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// running serializes migration work within this process.
//
// It exists because the migration library keeps its dialect and logger in
// package-level state. Two goroutines migrating at once would race on those
// regardless of any database lock — a real race, and one the race detector
// finds immediately. Migrations are rare and brief, so serializing them
// process-wide costs nothing and removes the whole class of problem.
//
// This is separate from the database lock, which excludes *other processes*.
// Both are needed: this one for goroutines here, that one for instances
// elsewhere.
var running sync.Mutex

// engineKey carries the engine to the migrations, which need it because the
// data-definition language genuinely differs between engines even where the
// queries above it do not.
type engineKey struct{}

// EngineFrom returns the engine a migration is running against.
func EngineFrom(ctx context.Context) database.Engine {
	e, _ := ctx.Value(engineKey{}).(database.Engine)
	return e
}

func gooseDialect(e database.Engine) (goose.Dialect, error) {
	switch e {
	case database.Postgres:
		return goose.DialectPostgres, nil
	case database.MySQL, database.MariaDB:
		return goose.DialectMySQL, nil
	case database.SQLite:
		return goose.DialectSQLite3, nil
	}
	return "", fmt.Errorf("no migration dialect for %s", e)
}

// Up applies every outstanding migration, holding the lock while it does.
func Up(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	return withLock(ctx, db, logger, func(ctx context.Context) error {
		before, err := goose.GetDBVersionContext(ctx, db.DB.DB)
		if err != nil {
			return fmt.Errorf("read schema version: %w", err)
		}
		if err := goose.UpContext(ctx, db.DB.DB, "."); err != nil {
			return fmt.Errorf("apply migrations: %w", err)
		}
		after, err := goose.GetDBVersionContext(ctx, db.DB.DB)
		if err != nil {
			return fmt.Errorf("read schema version: %w", err)
		}
		if before == after {
			logger.Info("schema is current", "version", after)
		} else {
			logger.Info("schema migrated", "from", before, "to", after)
		}
		return nil
	})
}

// Down rolls back the most recent migration.
func Down(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	return withLock(ctx, db, logger, func(ctx context.Context) error {
		if err := goose.DownContext(ctx, db.DB.DB, "."); err != nil {
			return fmt.Errorf("roll back migration: %w", err)
		}
		version, err := goose.GetDBVersionContext(ctx, db.DB.DB)
		if err != nil {
			return fmt.Errorf("read schema version: %w", err)
		}
		logger.Info("schema rolled back", "version", version)
		return nil
	})
}

// Version reports the schema version currently applied.
//
// It performs no schema changes. Asking whether the bookkeeping table exists
// before reading it keeps this from creating it — the library's version query
// creates it when missing, which would make a read-only inspection command
// need schema-change rights on a fresh database, against no schema rights
// while running.
func Version(ctx context.Context, db *database.DB) (int64, error) {
	running.Lock()
	defer running.Unlock()

	if err := prepare(db); err != nil {
		return 0, err
	}
	if !versionTableExists(ctx, db) {
		return 0, nil
	}
	return goose.GetDBVersionContext(ctx, db.DB.DB)
}

func withLock(ctx context.Context, db *database.DB, logger *slog.Logger, fn func(context.Context) error) error {
	running.Lock()
	defer running.Unlock()

	if err := prepare(db); err != nil {
		return err
	}
	ctx = context.WithValue(ctx, engineKey{}, db.Server.Engine)

	release, err := acquire(ctx, db)
	if err != nil {
		return err
	}
	defer func() {
		if err := release(context.WithoutCancel(ctx)); err != nil {
			logger.Warn("could not release the migration lock", "error", err)
		}
	}()

	return fn(ctx)
}

func prepare(db *database.DB) error {
	dialect, err := gooseDialect(db.Server.Engine)
	if err != nil {
		return err
	}
	if err := goose.SetDialect(string(dialect)); err != nil {
		return fmt.Errorf("set migration dialect: %w", err)
	}
	goose.SetLogger(goose.NopLogger())
	return nil
}
