// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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

// lastOfV010 is the last migration the v0.1.0 release shipped. A database at
// it or later is one a release built.
const lastOfV010 = 36

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

// loggerKey carries the caller's logger to the migrations, the same way the
// engine reaches them.
//
// A migration that resumes past something it had already created has to say
// so, and the migration library's own logger is package-level state this does
// not otherwise write to. Carried rather than passed, because a migration's
// signature belongs to the library.
type loggerKey struct{}

// WithEngine carries the engine and the logger a migration runs under.
//
// The readers below are exported and this is what establishes what they read,
// so the pair is complete rather than settable only from inside this package.
func WithEngine(ctx context.Context, engine database.Engine, logger *slog.Logger) context.Context {
	ctx = context.WithValue(ctx, engineKey{}, engine)
	return context.WithValue(ctx, loggerKey{}, logger)
}

// LoggerFrom returns the logger a migration should report through.
//
// Never nil: a migration that wrote nothing because it had nowhere to write it
// is worse than one that wrote somewhere nobody reads.
func LoggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
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
			// A database a release built is upgraded by the migrations after
			// the ones it shipped. On MySQL and MariaDB one that fails part
			// way leaves the schema part changed and the version where it
			// was, so the backup is what recovers it.
			if before >= lastOfV010 {
				return fmt.Errorf("upgrade the schema from version %d: %w — on MySQL and "+
					"MariaDB an upgrade that fails part way leaves the schema part "+
					"changed; restore the backup taken before it and start again", before, err)
			}
			// Named, because the commonest way this fails says a migration is
			// missing and then prints the path of a file that is sitting right
			// there. Below 1.0 a schema change edits what declares the thing
			// rather than adding a migration beside it, so a database an
			// unreleased build made can hold a version this set no longer
			// issues, and recreating it is the answer rather than migrating.
			return fmt.Errorf("apply migrations: %w — before 1.0 a schema change "+
				"edits what declares the thing rather than adding a migration, so "+
				"a database built by an unreleased build is recreated rather than "+
				"migrated", err)
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

// UpTo applies the outstanding migrations up to and including a version,
// holding the lock while it does. A test builds the schema a release shipped
// with it.
func UpTo(ctx context.Context, db *database.DB, logger *slog.Logger, version int64) error {
	return withLock(ctx, db, logger, func(ctx context.Context) error {
		if err := goose.UpToContext(ctx, db.DB.DB, ".", version); err != nil {
			return fmt.Errorf("apply migrations up to %d: %w", version, err)
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
//
// Zero means nothing is applied and nothing else. A database that could not be
// read is an error, because the two were the same answer and the reasonable
// thing to do about "nothing is applied" is to migrate.
func Version(ctx context.Context, db *database.DB) (int64, error) {
	running.Lock()
	defer running.Unlock()

	if err := prepare(db); err != nil {
		return 0, err
	}
	there, err := versionTableExists(ctx, db)
	if err != nil {
		return 0, err
	}
	if !there {
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
	ctx = WithEngine(ctx, db.Server.Engine, logger)

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
