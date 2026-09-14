package queue

import (
	"context"
	"fmt"
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
	now := l.now().Truncate(time.Microsecond)
	// The row is made on first use rather than seeded by the migration: what
	// work exists is decided in code, and a migration listing the names would
	// be a second place to change whenever a pass is added or retired. A
	// second replica's insert is refused by the primary key, which is the
	// answer rather than an error — both then go on to the update, and that is
	// what decides between them.
	// Outside the transaction below, and deliberately. A second replica's
	// insert is refused by the primary key, which is the answer rather than an
	// error — but on PostgreSQL a statement that fails inside a transaction
	// aborts the whole of it, so the refusal that is the ordinary case would
	// take the update with it. Nothing here depends on the two being atomic:
	// the row's existence is not what decides, the update is.
	made := &Lease{Name: name}
	if _, err := l.db.NewInsert().Model(made).Exec(ctx); err != nil && !database.IsDuplicate(err) {
		return false, fmt.Errorf("record the lease on %s: %w", name, err)
	}

	var mine bool
	err := database.InTransaction(ctx, l.db, func(ctx context.Context, tx bun.Tx) error {
		// Every attempt starts from nothing: an attempt that was rolled back
		// took no lease, whatever it decided.
		mine = false
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
		Set("held_by = ?", holder).
		Set("held_until = ?", now.Add(until)).
		Where("name = ?", name).
		WhereGroup(" AND ", func(u *bun.UpdateQuery) *bun.UpdateQuery {
			return u.
				WhereOr("held_by IS NULL").
				WhereOr("held_by = ?", holder).
				WhereOr("held_until < ?", now)
		}).
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("take the lease on %s: %w", name, err)
	}
	// A count that cannot be read is a fault, not "somebody else holds it".
	// Read as the second, a driver or proxy that cannot report one stops every
	// recurring sweep on every replica — notifications, digests and the lapse
	// sweep never run again — with nothing logged, because each replica is
	// simply told it lost a race it never ran.
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("cannot tell whether the lease on %s was taken: %w", name, err)
	}
	return n > 0, nil
}

// Await takes a lease as soon as it is free, or gives up when ctx ends.
//
// For work that has to happen rather than work that may be skipped: a policy
// somebody just changed has to be applied, so a replica that loses the race
// waits and applies it after — which is also what makes the last rewrite the
// one holding the newest policy.
func (l *Leases) Await(ctx context.Context, name, holder string, until, poll time.Duration) error {
	for {
		held, err := l.Take(ctx, name, holder, until)
		if err != nil {
			return err
		}
		if held {
			return nil
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
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
			Set("held_by = NULL").
			Set("held_until = NULL").
			Where("name = ?", name).
			Where("held_by = ?", holder).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("hand back the lease on %s: %w", name, err)
		}
		return nil
	})
}
