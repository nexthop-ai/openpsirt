// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// LeaseTable holds the migration lease: one row while an instance migrates,
// naming it, what it holds, and when the lease lapses unless renewed.
//
// It is the migrator's own bookkeeping, made before any migration runs, as
// the migration library makes its version table: a lease taken to apply the
// first migration cannot live in a table a migration makes. No migration
// declares it.
//
// The lease is a committed row on every engine, never a lock held by a
// session. A session lock lives on one server, so on a cluster taking writes
// on every node two instances on two nodes both hold it. A row is certified
// at commit like every other write (`design-docs/database-transactions.md`).
const LeaseTable = "schema_lease"

// leaseName keys the one lease row.
const leaseName = "schema"

// What a lease holds. An instance holds it to migrate from before it reads
// the version; it holds it to change the schema from before its first
// migration's statements to after its last, and a serving instance pauses
// for that alone, so a start with nothing to apply pauses nobody.
const (
	holdingMigrate = "migrate"
	holdingChange  = "change"
)

// The lease's timing. Variables only so tests can shorten them; nothing in
// the application changes them.
//
// A lease lapses leaseFor after it was last written, by the database's clock.
// Its holder writes it again every renewEvery. On the server engines a holder
// whose renewals have gone unanswered for stopAfter stops, leaseFor less
// stopAfter before the lapse it last wrote, which is the room left for the
// clocks of a cluster's nodes to differ. A waiter tries again every
// claimEvery, and names the holder about once every waitLogEvery.
var (
	leaseFor     = 30 * time.Second
	renewEvery   = 5 * time.Second
	stopAfter    = 20 * time.Second
	claimEvery   = time.Second
	waitLogEvery = time.Minute
)

// leaseClock reads the database's clock, which every lapse is written and
// read by. A variable only so tests can move it; nothing in the application
// changes it.
var leaseClock = database.ServerTimeOn

// cleanupWait bounds what an upgrade does after its work, whatever happened
// to its context: letting the lease go, and reading and clearing the record of
// a change. A variable only so tests can shorten it.
var cleanupWait = 5 * time.Second

// errLeaseLost is a holder finding its lease gone, taken, or unrenewed past
// the point it stops.
var errLeaseLost = errors.New("the migration lease was lost")

// errReleased ends a lease's context once it is let go.
var errReleased = errors.New("the migration lease was let go")

// unlock lets go of what a lease holds.
type unlock func(context.Context) error

// held is the migration lease, once taken.
type held struct {
	// ctx ends when the lease is lost or let go. Everything done under the
	// lease runs under it, so a holder that lost its lease sends no further
	// statement.
	ctx context.Context
	// release lets the lease go.
	release unlock
	// change holds the lease to change the schema, and answers the unlock
	// that goes back to holding it to migrate.
	change func(context.Context) (unlock, error)
}

// leaseRow is what a lease row holds.
type leaseRow struct {
	token   string
	holding string
	holder  string
	// expires is when the lease lapses, in microseconds since the epoch by
	// the database's clock.
	expires int64
}

// lease is one instance's hold on the lease row.
type lease struct {
	db     *database.DB
	token  string
	holder string
	// fences is whether the holder stops once its renewals have gone
	// unanswered for stopAfter, which it does on the server engines.
	fences bool
	ctx    context.Context
	lose   context.CancelCauseFunc
	// stop ends the renewals, and stopped closes once they have ended.
	stop    context.CancelFunc
	stopped chan struct{}
}

// acquire takes the migration lease, waiting for as long as another instance
// holds it, so that instances starting at once do not migrate at the same
// time.
//
// A claim is one transaction, read and written on the database's clock: it
// writes the row where none stands or where the one standing has lapsed, and
// otherwise writes nothing. Two claimants each find what the other committed,
// or, on a cluster, the second to commit is refused and tries again, so
// exactly one wins.
func acquire(ctx context.Context, db *database.DB) (*held, error) {
	if err := leaseTable(ctx, db); err != nil {
		return nil, err
	}
	l := &lease{db: db, token: newToken(), holder: holderName(), fences: db.Server.Engine != database.SQLite}
	waits := waiting{logger: LoggerFrom(ctx), since: time.Now()}
	for {
		began := time.Now()
		won, seen, now, err := l.claim(ctx)
		switch {
		case err != nil && ctx.Err() != nil:
			return nil, fmt.Errorf("stopped waiting for the migration lease: %w", ctx.Err())
		case err != nil && !database.WorthRetrying(err):
			return nil, fmt.Errorf("take the migration lease: %w", err)
		case err == nil && won:
			if seen.token != "" {
				waits.logger.Warn("took over the migration lease from a holder that let it lapse",
					"holder", seen.holder, "holding", seen.holding)
			}
			return l.start(ctx, began), nil
		case err == nil:
			waits.still(seen, now)
		default:
			waits.refused(err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("stopped waiting for the migration lease: %w", ctx.Err())
		case <-time.After(claimEvery):
		}
	}
}

// leaseTable makes the lease table where it is absent. Asked first, so a
// credential without the right to make tables passes where it is there.
// Two instances making it at once on PostgreSQL may see the loser refused,
// as a duplicate or as a table that already exists, so a refusal is followed
// by asking again, and a table there is the table made.
func leaseTable(ctx context.Context, db *database.DB) error {
	there, err := tableExists(ctx, db, LeaseTable)
	if err != nil || there {
		return err
	}
	return makeLeaseTable(ctx, db)
}

// makeLeaseTable makes the lease table, and answers a refusal only where the
// table is still not there once it is refused. MySQL answers one of two
// creates racing on it as a deadlock, which is asked again, as any write is.
func makeLeaseTable(ctx context.Context, db *database.DB) error {
	err := database.Retry(ctx, func() error {
		return leaseCreate(ctx, db, `CREATE TABLE IF NOT EXISTS "`+LeaseTable+`" (
			"name"       VARCHAR(32) NOT NULL,
			"token"      VARCHAR(64) NOT NULL,
			"holding"    VARCHAR(16) NOT NULL,
			"holder"     VARCHAR(191) NOT NULL,
			"expires_at" BIGINT NOT NULL,
			PRIMARY KEY ("name")
		)`)
	})
	if err != nil {
		if there, again := tableExists(ctx, db, LeaseTable); again == nil && there {
			return nil
		}
		return fmt.Errorf("make the migration lease table: %w", err)
	}
	return nil
}

// leaseCreate runs the statement making the lease table.
var leaseCreate = func(ctx context.Context, db *database.DB, statement string) error {
	_, err := db.ExecContext(ctx, statement)
	return err
}

// newToken is a value no other holder has.
func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// holderName names this process for a waiter's log.
func holderName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "an unnamed host"
	}
	return bound.HeadRunes(fmt.Sprintf("process %d on %s", os.Getpid(), host), database.NameWidth)
}

// claim tries once to take the lease. It answers whether it won, the row it
// found standing, and the database's clock as it looked.
func (l *lease) claim(ctx context.Context) (won bool, seen leaseRow, now time.Time, err error) {
	err = database.InTransaction(ctx, l.db.DB, func(ctx context.Context, tx bun.Tx) error {
		won, seen = false, leaseRow{}
		var err error
		if now, err = leaseClock(ctx, tx, l.db.Server.Engine); err != nil {
			return err
		}
		expires := now.Add(leaseFor).UnixMicro()
		switch err := tx.QueryRowContext(ctx, `SELECT "token", "holding", "holder", "expires_at"
			FROM "`+LeaseTable+`" WHERE "name" = ?`, leaseName).
			Scan(&seen.token, &seen.holding, &seen.holder, &seen.expires); {
		case database.IsNoRows(err):
			if _, err := tx.ExecContext(ctx, `INSERT INTO "`+LeaseTable+`"
				("name", "token", "holding", "holder", "expires_at") VALUES (?, ?, ?, ?, ?)`,
				leaseName, l.token, holdingMigrate, l.holder, expires); err != nil {
				if database.IsDuplicate(err) {
					return fmt.Errorf("take the migration lease: %w", database.ErrGoAgain)
				}
				return fmt.Errorf("take the migration lease: %w", err)
			}
			won = true
			return nil
		case err != nil:
			return fmt.Errorf("read the migration lease: %w", err)
		}
		if seen.expires > now.UnixMicro() {
			return nil
		}
		// Matched on the token read, so a claimant that took the lapsed
		// lease in between leaves this one matching nothing.
		res, err := tx.ExecContext(ctx, `UPDATE "`+LeaseTable+`"
			SET "token" = ?, "holding" = ?, "holder" = ?, "expires_at" = ?
			WHERE "name" = ? AND "token" = ?`,
			l.token, holdingMigrate, l.holder, expires, leaseName, seen.token)
		if err != nil {
			return fmt.Errorf("take the migration lease: %w", err)
		}
		if err := database.MovedAll(res, 1, "take the migration lease"); err != nil {
			return err
		}
		won = true
		return nil
	})
	return won, seen, now, err
}

// write writes the lease again, holding what holding names, or what it holds
// where holding is empty, lapsing leaseFor from the database's clock now. It
// matches on the token, so a lease another instance took, or none, answers
// errLeaseLost. The lapse is always a later value, so the row is written,
// and a cluster certifies it.
func (l *lease) write(ctx context.Context, holding string) error {
	return database.InTransaction(ctx, l.db.DB, func(ctx context.Context, tx bun.Tx) error {
		now, err := leaseClock(ctx, tx, l.db.Server.Engine)
		if err != nil {
			return err
		}
		expires := now.Add(leaseFor).UnixMicro()
		q := tx.NewUpdate().Table(LeaseTable).Set(`"expires_at" = ?`, expires)
		if holding != "" {
			q = q.Set(`"holding" = ?`, holding)
		}
		res, err := q.Where(`"name" = ?`, leaseName).Where(`"token" = ?`, l.token).Exec(ctx)
		if err != nil {
			return fmt.Errorf("renew the migration lease: %w", err)
		}
		if renewed, err := database.Changed(res, "renew the migration lease"); err != nil || !renewed {
			if err == nil {
				err = fmt.Errorf("%w: another instance holds it, or nobody does", errLeaseLost)
			}
			return err
		}
		return nil
	})
}

// start begins renewing a lease claimed at began, and answers it held.
func (l *lease) start(ctx context.Context, began time.Time) *held {
	l.ctx, l.lose = context.WithCancelCause(ctx)
	renewing, stop := context.WithCancel(context.WithoutCancel(ctx))
	l.stop, l.stopped = stop, make(chan struct{})
	go l.renewing(renewing, began)
	return &held{ctx: l.ctx, release: l.release, change: l.change}
}

// renewing writes the lease every renewEvery until stopped. On the server
// engines it renews on a pooled connection, never the one a migration holds:
// a data-definition statement runs for minutes, and on MySQL and MariaDB
// commits alone.
//
// A renewal finding the lease gone or taken ends the lease's context, and the
// holder sends no further statement. On the server engines so does stopAfter
// passing with no renewal answered, each bounded by renewEvery. On SQLite a
// renewal waits as long as it takes: a migration's transaction holds the one
// write the file admits, so the renewal waits for it, and so does any
// claimant's; the migration runs on the pool's one connection, and a renewal
// waiting for it takes it before the migration's next statement does.
func (l *lease) renewing(ctx context.Context, confirmed time.Time) {
	defer close(l.stopped)
	tick := time.NewTicker(renewEvery)
	defer tick.Stop()
	for {
		// On the server engines the holder stops stopAfter past the last
		// renewal answered, whether a renewal is under way or not.
		deadline := confirmed.Add(stopAfter)
		var unanswered <-chan time.Time
		if l.fences {
			unanswered = time.After(time.Until(deadline))
		}
		select {
		case <-ctx.Done():
			return
		case <-unanswered:
			l.lose(fmt.Errorf("%w: no renewal answered for %s", errLeaseLost, stopAfter))
			return
		case <-tick.C:
		}
		began := time.Now()
		attempt, cancel := ctx, context.CancelFunc(func() {})
		if l.fences {
			attempt, cancel = context.WithDeadline(ctx, began.Add(min(renewEvery, deadline.Sub(began))))
		}
		err := l.write(attempt, "")
		cancel()
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, errLeaseLost):
			l.lose(err)
			return
		case err == nil:
			confirmed = began
		case l.fences && !time.Now().Before(deadline):
			l.lose(fmt.Errorf("%w: no renewal answered for %s: %w", errLeaseLost, stopAfter, err))
			return
		}
	}
}

// change holds the lease to change the schema, and answers the unlock that
// goes back to holding it to migrate. Either write that finds the lease lost
// ends the lease's context.
func (l *lease) change(ctx context.Context) (unlock, error) {
	if err := l.hold(ctx, holdingChange); err != nil {
		return nil, err
	}
	return func(ctx context.Context) error { return l.hold(ctx, holdingMigrate) }, nil
}

// hold writes what the lease holds.
func (l *lease) hold(ctx context.Context, holding string) error {
	err := l.write(ctx, holding)
	if errors.Is(err, errLeaseLost) {
		l.lose(err)
	}
	if err != nil {
		return fmt.Errorf("hold the migration lease to %s: %w", holding, err)
	}
	return nil
}

// release stops the renewals and deletes the lease row, matched on the
// token. A row not there to delete is a lease lost part way: another
// instance may have migrated alongside.
func (l *lease) release(ctx context.Context) error {
	l.stop()
	select {
	case <-l.stopped:
	case <-ctx.Done():
		l.lose(errReleased)
		return fmt.Errorf("the migration lease's renewal did not stop: %w", ctx.Err())
	}
	defer l.lose(errReleased)
	var held bool
	err := database.InTransaction(ctx, l.db.DB, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewDelete().Table(LeaseTable).
			Where(`"name" = ?`, leaseName).Where(`"token" = ?`, l.token).Exec(ctx)
		if err != nil {
			return fmt.Errorf("let the migration lease go: %w", err)
		}
		held, err = database.Changed(res, "let the migration lease go")
		return err
	})
	// A lease already lost stays lost, though a row still standing as this
	// holder's is deleted rather than left to lapse.
	if lost := context.Cause(l.ctx); errors.Is(lost, errLeaseLost) {
		return lost
	}
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("%w: it was not held when let go", errLeaseLost)
	}
	return nil
}

// waiting reports a wait on the migration lease: at the first claim that
// finds it held, and then about once every waitLogEvery, naming the holder and
// when its lease lapses unless renewed.
type waiting struct {
	logger *slog.Logger
	since  time.Time
	said   time.Time
}

// refused says a claim was refused for a reason a later one may not meet,
// such as a SQLite file another process is writing, where a line is due.
func (w *waiting) refused(err error) {
	at := time.Now()
	if !w.said.IsZero() && at.Sub(w.said) < waitLogEvery {
		return
	}
	w.said = at
	w.logger.Info("waiting for the migration lease", "refused", err, "waited", at.Sub(w.since).Round(time.Second))
}

// still says the lease is held as seen, by the database's clock now, where a
// line is due.
func (w *waiting) still(seen leaseRow, now time.Time) {
	at := time.Now()
	if !w.said.IsZero() && at.Sub(w.said) < waitLogEvery {
		return
	}
	w.said = at
	lapses := time.UnixMicro(seen.expires).Sub(now).Round(time.Second)
	w.logger.Info("waiting for the migration lease", "holder", seen.holder, "holding", seen.holding,
		"lapses_unless_renewed_in", lapses, "waited", at.Sub(w.since).Round(time.Second))
}
