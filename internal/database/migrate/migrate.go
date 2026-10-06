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
	"embed"
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
			return upFailed(db.Server.Engine, before, err)
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

// upFailed says what a failed upgrade leaves behind, and what recovers it.
//
// An empty database has nothing to recover, so its failure is reported alone.
// Otherwise the version number cannot say whether a release or an unreleased
// build made the database, so both recoveries are named: below 1.0 a schema
// change edits what declares the thing rather than adding a migration beside
// it, so a database an unreleased build made can hold a version this build no
// longer issues, and is recreated. MySQL and MariaDB apply a schema change
// outside any transaction, so on those two an upgrade that fails part way
// leaves the schema part changed and the version where it was.
func upFailed(engine database.Engine, before int64, err error) error {
	if before == 0 {
		return fmt.Errorf("apply migrations to an empty database: %w", err)
	}
	const unreleased = "a database an unreleased build made can hold a version this " +
		"build no longer issues, and is recreated rather than migrated"
	if engine == database.MySQL || engine == database.MariaDB {
		return fmt.Errorf("upgrade the schema from version %d: %w — on %s an upgrade that "+
			"fails part way leaves the schema part changed, so restore the backup taken "+
			"before it and start again; %s", before, err, engine, unreleased)
	}
	return fmt.Errorf("upgrade the schema from version %d: %w — %s", before, err, unreleased)
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

// dbMaxOpen names the setting a pool too small to migrate through is refused
// in terms of.
const dbMaxOpen = "OPENPSIRT_DB_MAX_OPEN"

func withLock(ctx context.Context, db *database.DB, logger *slog.Logger, fn func(context.Context) error) (failed error) {
	running.Lock()
	defer running.Unlock()

	if err := prepare(db); err != nil {
		return err
	}
	// The lock holds one pooled connection for the whole migration and the
	// migration runs on another. A pool of one would have the migration wait
	// for the lock's connection, with no deadline, for ever. SQLite is exempt:
	// its lock is on a file rather than a connection.
	if db.Server.Engine != database.SQLite && db.Stats().MaxOpenConnections == 1 {
		return fmt.Errorf("the migration lock holds one connection and the migrations "+
			"need another: raise %s to at least 2", dbMaxOpen)
	}
	ctx = WithEngine(ctx, db.Server.Engine, logger)

	// SQLite migrates on one connection. A migration that changes a table's
	// shape turns foreign keys off on a connection and then opens its
	// transaction, and on a wider pool the transaction can land on a
	// connection where they are still on — and the one it turned off goes back
	// into the pool that way. The pool is put back as it was afterwards.
	//
	// Both limits, because narrowing the open limit lowers the idle limit to
	// match and widening it again does not raise it: left at one, the pool
	// closes all but one connection after every burst.
	if db.Server.Engine == database.SQLite {
		width := db.Stats().MaxOpenConnections
		db.SetMaxOpenConns(1)
		defer func() {
			db.SetMaxOpenConns(width)
			if db.Pool.MaxIdle > 0 {
				db.SetMaxIdleConns(db.Pool.MaxIdle)
			}
		}()
	}

	release, err := acquire(ctx, db)
	if err != nil {
		return err
	}
	defer func() {
		err := release(context.WithoutCancel(ctx))
		switch {
		case err == nil:
		case failed == nil:
			// A lock this session no longer holds when the work is done is
			// one it may have lost part way, and another instance may have
			// migrated alongside it. The work finished; what it ran under is
			// not certain, and that is reported rather than logged.
			failed = fmt.Errorf("the migration finished and its lock could not be released "+
				"as held, so another instance may have migrated at the same time: %w", err)
		default:
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
	// The migrations are Go functions registered with the library, and no
	// directory is read. Left at its default, the library globs the process's
	// working directory for migration files: a stray `*.sql` there fails every
	// start, a numbered one is applied, and a numbered `.go` file narrows the
	// registered set to the ones with a file beside it.
	goose.SetBaseFS(embed.FS{})
	goose.SetLogger(goose.NopLogger())
	return nil
}
