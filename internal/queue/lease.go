// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Lease says which replica is doing a named piece of recurring work.
//
// Every replica runs the same binary with no leader and no process-local state
// that decides anything, so a pass that runs on a timer runs on all of them
// unless something in the database says otherwise. A job answers that for
// discrete work — there is a row to claim. A recurring pass has no work item,
// so what it takes is the name of the work.
type Lease struct {
	bun.BaseModel `bun:"table:lease,alias:le"`

	Name      string     `bun:"name,pk"`
	HeldBy    *string    `bun:"held_by"`
	HeldUntil *time.Time `bun:"held_until"`
}

// Leases hands out the names of recurring work.
//
// No engine of its own to ask about, unlike claiming a job: nothing here needs
// row locking, because a lease is one row and there is no queue of them to
// skip past.
type Leases struct {
	// db is the handle rather than any transaction-or-handle, because taking
	// a lease is its own transaction: a cluster certifies at commit, so a
	// take whose statements all succeeded can still be rolled back under it,
	// and a replica told it lost a race it never ran stops sweeping with
	// nothing logged.
	db  *bun.DB
	now func() time.Time
}

// NewLeases returns the leases held in db.
func NewLeases(db *bun.DB) *Leases {
	return &Leases{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Take tries once to take a lease, reporting whether this holder now has it.
//
// Taking is a conditional update repeating what made the lease available, so
// two replicas asking together cannot both get it — the same guarantee, and
// the same reasoning, as claiming a job. Nothing about it is engine-specific.
//
// A holder that already has the lease takes it again and extends it, so a pass
// that runs on a timer renews simply by asking each cycle. It is not renewed
// while the work runs, which is why `until` has to cover a cycle of the work
// rather than an instant of it.
func (l *Leases) Take(ctx context.Context, name, holder string, until time.Duration) (bool, error) {
	var mine bool
	err := database.InTransaction(ctx, l.db, func(ctx context.Context, tx bun.Tx) error {
		// Every attempt starts from nothing: an attempt that was rolled back
		// took no lease, whatever it decided, and a retry runs after a pause
		// the moment has to include.
		mine = false
		now := l.now().Truncate(time.Microsecond)
		// The row is made on first use rather than seeded by the migration:
		// what work exists is decided in code, and a migration listing the
		// names would be a second place to change whenever a pass is added or
		// retired. Written so that a row another replica made first is left
		// alone rather than refused, because on PostgreSQL a refused
		// statement aborts the transaction it is in.
		if err := database.InBatchesKeeping(ctx, tx, []Lease{{Name: name}}); err != nil {
			return fmt.Errorf("record the lease on %s: %w", name, err)
		}
		taken, err := l.takeIn(ctx, tx, name, holder, now, until)
		if err != nil {
			return err
		}
		mine = taken
		return nil
	})
	return mine, err
}

func (l *Leases) takeIn(ctx context.Context, tx bun.Tx,
	name, holder string, now time.Time, until time.Duration) (bool, error) {

	res, err := tx.NewUpdate().Model((*Lease)(nil)).
		Set(`"held_by" = ?`, holder).
		Set(`"held_until" = ?`, now.Add(until)).
		Where(`"name" = ?`, name).
		WhereGroup(" AND ", func(u *bun.UpdateQuery) *bun.UpdateQuery {
			return u.
				WhereOr(`"held_by" IS NULL`).
				WhereOr(`"held_by" = ?`, holder).
				WhereOr(`"held_until" < ?`, now)
		}).
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("take the lease on %s: %w", name, err)
	}
	// Read as "somebody else holds it", a count that cannot be read stops
	// every recurring sweep on every replica — notifications, digests and the
	// lapse sweep never run again — with nothing logged, because each replica
	// is simply told it lost a race it never ran.
	n, err := database.Affected(res)
	if err != nil {
		return false, fmt.Errorf("take the lease on %s: %w", name, err)
	}
	return n > 0, nil
}

// Await takes a lease as soon as it is free, or gives up when ctx ends.
//
// For work that has to happen rather than work that may be skipped: a policy
// somebody just changed has to be applied, so a replica that loses the race
// waits and applies it after — which is also what makes the last rewrite the
// one holding the newest policy.
//
// A take that fails is a turn missed, and asked again at the next poll: one
// connection reset would otherwise drop work that has to happen. What it
// failed with is returned beside the context's own error when ctx ends.
func (l *Leases) Await(ctx context.Context, name, holder string, until, poll time.Duration) error {
	var last error
	for {
		held, err := l.Take(ctx, name, holder, until)
		if err == nil && held {
			return nil
		}
		if err != nil {
			last = err
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), last)
		case <-timer.C:
		}
	}
}

// Release hands a lease back, by the holder that has it.
//
// Only the holder, for the reason only the holder finishes a job: a replica
// whose lease has lapsed and been taken by another is still running, and
// releasing then would hand away what somebody else is holding.
//
// A lease that is never released still lapses, so this shortens a handover
// rather than making one possible. That is what it is for — a replica shutting
// down cleanly should not leave the work stopped for the length of a lease.
func (l *Leases) Release(ctx context.Context, name, holder string) error {
	return database.InTransaction(ctx, l.db, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.NewUpdate().Model((*Lease)(nil)).
			Set(`"held_by" = NULL`).
			Set(`"held_until" = NULL`).
			Where(`"name" = ?`, name).
			Where(`"held_by" = ?`, holder).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("hand back the lease on %s: %w", name, err)
		}
		return nil
	})
}

// handbackWait bounds handing a lease back on the way out. It is one write
// against a server that was answering a moment ago.
const handbackWait = 10 * time.Second

// Handback releases a lease on shutdown, for a pass whose context has ended.
//
// The release runs on a context of its own, because the pass's has already
// ended by the time it is called, and is bounded so a database that has gone
// away does not hold the process up. A failure is logged and not returned: the
// lease lapses on its own, and a shutdown has nobody to return it to.
func (l *Leases) Handback(ctx context.Context, name, holder string, logger *slog.Logger) {
	if l == nil {
		return
	}
	releasing, cancel := context.WithTimeout(context.WithoutCancel(ctx), handbackWait)
	defer cancel()
	if err := l.Release(releasing, name, holder); err != nil && logger != nil {
		logger.WarnContext(releasing, "handing back a lease on the way out", "lease", name, "error", err)
	}
}
