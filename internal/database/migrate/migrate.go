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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/bound"
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
//
// Where a migration is outstanding it also holds the schema change lock, from
// before the first statement until after the last, which tells an instance
// serving the database to stop. On a database holding a schema it then waits
// notice before the first statement, for those instances to see the lock and
// stop. A start with nothing to apply never takes the change lock, so a
// replica starting beside others pauses none of them.
func Up(ctx context.Context, db *database.DB, logger *slog.Logger, notice time.Duration) error {
	return withLock(ctx, db, logger, func(ctx context.Context, lock *held) (failed error) {
		before, err := goose.GetDBVersionContext(ctx, db.DB.DB)
		if err != nil {
			return fmt.Errorf("read schema version: %w", err)
		}
		stopChanging, err := changeSchema(ctx, db, lock, logger, before, goose.MaxVersion, notice)
		if err != nil {
			return err
		}
		defer func() { stopChanging(failed) }()
		if err := goose.UpContext(ctx, db.DB.DB, "."); err != nil {
			return upEnded(ctx, db.Server.Engine, before, err)
		}
		after, err := goose.GetDBVersionContext(ctx, db.DB.DB)
		if err != nil {
			return fmt.Errorf("read schema version: %w", err)
		}
		if before == after {
			logger.Info("schema is current", "version", after)
			return nil
		}
		logger.Info("schema migrated", "from", before, "to", after)
		// An empty database has nothing for statistics to describe.
		if before != 0 {
			refreshStatistics(ctx, db, logger)
		}
		return nil
	})
}

// changeSchema takes the schema change lock where a migration after before
// and up to target is outstanding, waits notice on a database holding a
// schema, records the change where the database keeps that record, and answers
// what ends the change given how the upgrade ended. Where nothing is
// outstanding it takes nothing, and removes any record the version applied
// has reached.
//
// The record is written on MySQL and MariaDB alone, and removed when the
// upgrade succeeds. An upgrade ending any other way leaves the schema part
// changed, so the record stays, and every serving instance stays paused,
// until an upgrade reaches the version it names or the backup is restored.
//
// A release of the lock that fails is logged: the migration lock's release
// follows on the same session, and reports a session lost part way.
func changeSchema(ctx context.Context, db *database.DB, lock *held, logger *slog.Logger, before, target int64,
	notice time.Duration) (func(error), error) {
	nothing := func(error) {}
	var outstanding goose.Migrations
	if target > before {
		// The library answers ErrNoMigrationFiles where none is outstanding.
		var err error
		outstanding, err = goose.CollectMigrations(".", before, target)
		if err != nil && !errors.Is(err, goose.ErrNoMigrationFiles) {
			return nil, fmt.Errorf("list the outstanding migrations: %w", err)
		}
	}
	if len(outstanding) == 0 {
		clearReached(ctx, db, before, logger)
		return nothing, nil
	}
	return beginChange(ctx, db, lock, logger, before, outstanding[len(outstanding)-1].Version, notice)
}

// beginChange takes the schema change lock, waits notice on a database
// holding a schema, and records the change, as changeSchema says.
func beginChange(ctx context.Context, db *database.DB, lock *held, logger *slog.Logger, before, target int64,
	notice time.Duration) (func(error), error) {
	release, err := lock.change(ctx)
	if err != nil {
		return nil, err
	}
	let := func() {
		if err := releaseWithin(ctx, release); err != nil {
			logger.Warn("could not release the schema change lock", "error", err)
		}
	}
	if before != 0 && notice > 0 {
		logger.Info("waiting for serving instances to stop before changing the schema", "wait", notice)
		select {
		case <-ctx.Done():
			let()
			return nil, fmt.Errorf("stopped before changing the schema: %w", ctx.Err())
		case <-time.After(notice):
		}
	}
	// Written once the notice has passed, just before the first statement:
	// the lock alone covers the notice, and a record written earlier would
	// outlive a process killed during it with nothing changed.
	if err := recordChange(ctx, db, target); err != nil {
		let()
		return nil, err
	}
	stop := func(failed error) {
		applied, err := appliedNow(ctx, db)
		if err != nil {
			logger.Warn("could not read the schema version after changing it, so every record of the "+
				"change stands", "error", err)
		} else {
			clearReached(ctx, db, applied, logger)
		}
		if failed != nil && partChanges(db.Server.Engine) {
			logger.Warn("the schema is left part changed, so every serving instance stays paused " +
				"until an upgrade succeeds or the backup taken before it is restored")
		}
		let()
	}
	return stop, nil
}

// partChanges reports whether an upgrade on engine that fails part way leaves
// the schema part changed: MySQL and MariaDB commit each data-definition
// statement alone, so the record is written before the first. Elsewhere a
// release's migration writes its record in its own transaction, which
// commits with the schema and rolls back with it, a killed process included.
func partChanges(engine database.Engine) bool {
	return engine == database.MySQL || engine == database.MariaDB
}

// ChangeTable is the record an upgrade keeps while it changes the schema,
// which a release's migration makes and this reads and writes.
const ChangeTable = "schema_change"

// recordChange writes the record of an upgrade changing the schema to target,
// on an engine where a failed upgrade leaves the schema part changed and
// where the database has the table for it: a database the release that made
// the table has not yet upgraded has none.
//
// A record names the version its upgrade was reaching, so one left by a
// process ended after its last migration, or by a removal that failed, stops
// counting once the version applied reaches it.
func recordChange(ctx context.Context, db *database.DB, target int64) error {
	if !partChanges(db.Server.Engine) {
		return nil
	}
	there, err := tableExists(ctx, db, ChangeTable)
	if err != nil || !there {
		return err
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "an unnamed host"
	}
	by := fmt.Sprintf("process %d on %s", os.Getpid(), host)
	by = bound.HeadRunes(by, database.NameWidth)
	if _, err := db.ExecContext(ctx, `INSERT INTO "`+ChangeTable+`" ("started_at", "started_by", "target_version")
		VALUES (?, ?, ?)`, time.Now().UTC(), by, target); err != nil {
		return fmt.Errorf("record the schema change: %w", err)
	}
	return nil
}

// appliedNow reads the schema version an upgrade reached, bounded as a
// release is, whatever happened to ctx.
func appliedNow(ctx context.Context, db *database.DB) (int64, error) {
	reading, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetWait)
	defer cancel()
	return goose.GetDBVersionContext(reading, db.DB.DB)
}

// clearReached removes every record of an upgrade changing the schema to a
// version no later than reached, which nothing reads as changing any more.
// Bounded as a release is, whatever happened to ctx; a failure is logged,
// since a record the version applied has reached pauses nobody.
func clearReached(ctx context.Context, db *database.DB, reached int64, logger *slog.Logger) {
	clearing, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetWait)
	defer cancel()
	there, err := tableExists(clearing, db, ChangeTable)
	if err == nil && there {
		_, err = db.ExecContext(clearing, `DELETE FROM "`+ChangeTable+`" WHERE "target_version" <= ?`, reached)
	}
	if err != nil {
		logger.Warn("could not clear the record of the schema change", "error", err)
	}
}

// refreshStatistics analyzes every table once migrations have changed the
// schema, under the lock and with no deadline, as the migration has none.
//
// An upgrade leaves the planner's statistics describing a schema that is
// gone. On SQLite an index the upgrade adds has none beside indexes that keep
// theirs, and SQLite prefers the index it knows nothing about. A v0.9.0 demo
// of 414,681 findings upgraded to v0.11.0 kept statistics for five of the
// finding table's ten indexes and none for the decision occurrences, and
// planned the audit export, the findings export and the upstream offers
// through the index on a finding's kind, which nearly every finding shares:
// each ran past five minutes, and analyzed they take 0.6 s, 0.55 s a page and
// 1.7 s. The start's own refresh is bounded by the startup deadline, so it
// cannot be what repairs this.
//
// A failed refresh is logged and the upgrade stands: stale estimates make a
// statement slow, never wrong, and the next start asks again.
func refreshStatistics(ctx context.Context, db *database.DB, logger *slog.Logger) {
	database.AnalyzeAndLog(ctx, db, logger, "after the upgrade")
}

// upEnded says why an upgrade ended part way: stopped by its caller, or
// failed.
//
// A stop is not a failure, and says nothing about recovering. On PostgreSQL
// and SQLite the migration's transaction rolls back, and on MySQL and MariaDB
// the next start steps over what the stopped migration made, so in both cases
// the next start applies the schema again.
func upEnded(ctx context.Context, engine database.Engine, before int64, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("stopped part way through the migrations: %w", err)
	}
	return upFailed(engine, before, err)
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
	return withLock(ctx, db, logger, func(ctx context.Context, lock *held) (failed error) {
		before, err := goose.GetDBVersionContext(ctx, db.DB.DB)
		if err != nil {
			return fmt.Errorf("read schema version: %w", err)
		}
		stopChanging, err := changeSchema(ctx, db, lock, logger, before, version, 0)
		if err != nil {
			return err
		}
		defer func() { stopChanging(failed) }()
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
// Zero means nothing is applied and nothing else. A database that cannot be
// read is an error, because the reasonable thing to do about "nothing is
// applied" is to migrate, and reading it as zero would migrate a populated
// database.
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

func withLock(ctx context.Context, db *database.DB, logger *slog.Logger,
	fn func(context.Context, *held) error) (failed error) {
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
			db.RestoreIdle()
		}()
	}

	lock, err := acquire(ctx, db)
	if err != nil {
		return err
	}
	defer func() {
		err := releaseWithin(ctx, lock.release)
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

	return fn(ctx, lock)
}

// releaseWithin releases the migration lock within resetWait, whatever
// happened to ctx, and a release answering past it is reported. An unlock
// that fails has its connection closed, never pooled, which ends the session
// and frees the lock on the server. A keep-alive use still running leaves the
// connection to be closed once that use ends.
func releaseWithin(ctx context.Context, release unlock) error {
	releasing, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetWait)
	defer cancel()
	return release(releasing)
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
