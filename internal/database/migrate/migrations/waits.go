// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// This file holds how a migration waits for a table another session holds:
// another session's statement on the table queues behind a waiting one, so a
// wait is cut into short attempts and the migration tries again until the
// holder lets go or the migration is stopped.

// lockWaits is how long one attempt at a lock waits and how long a migration
// pauses between attempts.
type lockWaits struct {
	// attemptSeconds bounds one wait a statement makes for a lock. MySQL and
	// MariaDB count it in whole seconds.
	attemptSeconds int
	// pause follows the first attempt that waits out its bound, and doubles
	// after each one until it reaches most.
	pause, most time.Duration
}

// everyMigration is the waits every migration runs with.
//
// Three seconds an attempt: a statement on the table waits at most that long
// behind the migration's, and a short transaction, which holds a lock
// for milliseconds, ends well inside one attempt.
//
// The pause is when statements queued on the table go through, so a holder
// that stays leaves the table queued for a smaller share of the time each
// round: three seconds in four after the first attempt, three in
// thirty-three from the sixth. Half a minute is also the longest a migration
// starts late once the holder lets go.
var everyMigration = lockWaits{attemptSeconds: 3, pause: time.Second, most: 30 * time.Second}

// waitsKey carries other waits on the context, which only a test does: a
// package variable changed by one test is read by the migrations its
// neighbors run at the same time.
type waitsKey struct{}

// waitsFrom is the waits a migration runs with.
func waitsFrom(ctx context.Context) lockWaits {
	if w, ok := ctx.Value(waitsKey{}).(lockWaits); ok {
		return w
	}
	return everyMigration
}

// pauseAfter is the pause after an attempt, counted from one.
func (w lockWaits) pauseAfter(attempt int) time.Duration {
	pause := w.pause
	for i := 1; i < attempt && pause < w.most; i++ {
		pause *= 2
	}
	return min(pause, w.most)
}

// retriesInPlace reports whether a statement that waited out its bound is
// tried again where it stands: on MySQL and MariaDB, which commit before and
// after every data-definition statement, so the statements before it are
// kept and nothing they locked is held. On PostgreSQL and SQLite the
// transaction holds every lock it took until it ends, so the whole
// transaction is rolled back and run again, which lets those go between
// attempts.
func retriesInPlace(engine database.Engine) bool {
	return engine == database.MySQL || engine == database.MariaDB
}

// waitOut reports an attempt that waited out its bound, with every other
// session on the database holding a transaction open, and pauses before the
// next. It returns the context's error where the migration is stopped
// meanwhile.
func waitOut(ctx context.Context, q database.Querier, attempt int, since time.Time, err error) error {
	migrate.LoggerFrom(ctx).Warn("a migration is waiting for a table something else holds",
		"attempt", attempt, "waited", time.Since(since).Round(time.Second), "error", err,
		"held_by", database.Holders(ctx, q, migrate.EngineFrom(ctx)))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(waitsFrom(ctx).pauseAfter(attempt)):
		return nil
	}
}

// execWaiting runs one statement of a migration with its wait for a lock
// bounded, and on MySQL and MariaDB runs it again after each wait that ends.
//
// The bound is set for each statement: the v0.11.0 renames put PostgreSQL's
// back to the server's default part way through their migration. On
// PostgreSQL it lasts the rest of the transaction, so a data step after a
// bounded statement is bounded too, and a wait it ends runs the whole
// upgrade again. On MySQL and MariaDB it belongs to the session and is
// lifted once the statement ends, so a data step the migration runs beside
// it waits as the server says, and the connection goes back to the pool as
// it came.
func execWaiting(ctx context.Context, tx *sql.Tx, stmt string) (err error) {
	engine := migrate.EngineFrom(ctx)
	since := time.Now()
	if err := database.BoundLockWait(ctx, tx, engine, waitsFrom(ctx).attemptSeconds); err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, database.LiftLockWait(context.WithoutCancel(ctx), tx, engine))
	}()
	for attempt := 1; ; attempt++ {
		_, err := tx.ExecContext(ctx, stmt)
		if err == nil || !retriesInPlace(engine) || !database.LockWaitEnded(err) {
			return err
		}
		if stopped := waitOut(ctx, tx, attempt, since, fmt.Errorf("%s: %w", firstLine(stmt), err)); stopped != nil {
			return fmt.Errorf("%w: %w", err, stopped)
		}
	}
}
