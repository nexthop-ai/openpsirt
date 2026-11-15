// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Observer is what an instance serving a database asks about its schema:
// whether another instance is changing it, and which version is applied.
//
// An instance is changing the schema while its migration lease, not lapsed,
// holds it to change the schema, and an upgrade that left the schema part
// changed is still changing it while its record stands.
//
// Asking reads rows, and takes nothing an instance migrating waits for.
type Observer struct {
	db *database.DB
	// recorded is whether the database keeps a record of schema changes. A
	// serving instance's database does, being at its build's version.
	recorded bool
	// leased is whether the lease table has been seen. A migrator makes it
	// before it migrates, so once seen it stays.
	leased atomic.Bool
}

// NewObserver is an Observer of db.
func NewObserver(ctx context.Context, db *database.DB) (*Observer, error) {
	recorded, err := tableExists(ctx, db, ChangeTable)
	if err != nil {
		return nil, err
	}
	return &Observer{db: db, recorded: recorded}, nil
}

// Change is what a look found of a schema change.
type Change int

const (
	// Unchanged is no lease held to change the schema and no record standing.
	Unchanged Change = iota
	// Held is a lease, not lapsed, held by an instance changing the schema.
	Held
	// Recorded is a record standing of an upgrade to a later version than the
	// one applied, with no lease held to change the schema: one that left the
	// schema part changed, or committed a migration before its version was
	// recorded.
	Recorded
)

// Look reports whether another instance is changing the schema, and the
// highest schema version applied, on one connection of its own. Taking the
// connection is bounded by acquireWithin and the questions by lookWithin.
//
// The version is read first and answered even where asking about a change
// then fails, since a version ahead settles what a serving instance does
// whatever else is true. It is read again after, and the later answer kept.
func (o *Observer) Look(ctx context.Context, acquireWithin, lookWithin time.Duration) (Change, int64, error) {
	acquiring, cancel := context.WithTimeout(ctx, acquireWithin)
	conn, err := o.db.Conn(acquiring)
	cancel()
	if err != nil {
		return Unchanged, 0, fmt.Errorf("take a connection to ask about the schema: %w", err)
	}
	defer func() { _ = conn.Close() }()
	asking, cancel := context.WithTimeout(ctx, lookWithin)
	defer cancel()
	applied, err := o.applied(asking, conn)
	if err != nil {
		return Unchanged, 0, err
	}
	changing, err := o.changing(asking, conn, applied)
	if err != nil {
		return Unchanged, applied, err
	}
	// Read again, since an upgrade may have finished and let go of the lease
	// between the two reads: no lease with the first version would read as
	// this build's schema when it is already the next one's.
	later, err := o.applied(asking, conn)
	return changing, max(applied, later), err
}

// changing reports whether an instance holds the lease to change the schema,
// which it does from before its first migration's statements to after its
// last, or else whether a record stands of an upgrade reaching a version
// later than applied.
func (o *Observer) changing(ctx context.Context, q database.RowQuerier, applied int64) (Change, error) {
	held, err := o.leasedToChange(ctx, q)
	if err != nil {
		return Unchanged, err
	}
	if held {
		return Held, nil
	}
	if !o.recorded {
		return Unchanged, nil
	}
	var records int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM "`+ChangeTable+`" WHERE "target_version" > ?`,
		applied).Scan(&records); err != nil {
		return Unchanged, fmt.Errorf("read the record of schema changes: %w", err)
	}
	if records > 0 {
		return Recorded, nil
	}
	return Unchanged, nil
}

// leasedToChange reports whether the lease is held to change the schema and
// has not lapsed. The database's clock is read only where a lease is held to
// change it, which is only during an upgrade.
func (o *Observer) leasedToChange(ctx context.Context, q database.RowQuerier) (bool, error) {
	if !o.leased.Load() {
		there, err := tableExistsOn(ctx, q, o.db.Server.Engine, LeaseTable)
		if err != nil || !there {
			return false, err
		}
		o.leased.Store(true)
	}
	var holding string
	var expires int64
	switch err := q.QueryRowContext(ctx, `SELECT "holding", "expires_at" FROM "`+LeaseTable+`" WHERE "name" = ?`,
		leaseName).Scan(&holding, &expires); {
	case database.IsNoRows(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ask whether the schema is changing: %w", err)
	}
	if holding != holdingChange {
		return false, nil
	}
	now, err := database.ServerTimeOn(ctx, q, o.db.Server.Engine)
	if err != nil {
		return false, fmt.Errorf("ask whether the schema is changing: %w", err)
	}
	return expires > now.UnixMicro(), nil
}

// applied reports the highest schema version applied, in one query on the
// migration library's bookkeeping table.
func (o *Observer) applied(ctx context.Context, q database.RowQuerier) (int64, error) {
	var applied sql.NullInt64
	if err := q.QueryRowContext(ctx,
		`SELECT MAX("version_id") FROM "`+VersionTable+`" WHERE "is_applied"`).Scan(&applied); err != nil {
		return 0, fmt.Errorf("read the schema version: %w", err)
	}
	return applied.Int64, nil
}
