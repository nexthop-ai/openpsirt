// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Observer is what an instance serving a database asks about its schema:
// whether another instance is changing it, and which version is applied.
//
// An instance is changing the schema while it holds the schema change lock,
// and an upgrade that left the schema part changed is still changing it while
// its record stands.
//
// Asking takes nothing an instance migrating waits for. On PostgreSQL the lock
// table is read; on MySQL and MariaDB the server is asked who holds the named
// lock; on SQLite a shared lock is taken on the file for the moment of asking,
// and the instance taking the change lock tries again past it.
type Observer struct {
	db *database.DB
	// name is the schema change lock's name on MySQL and MariaDB.
	name string
	// file is the schema change lock's file on SQLite, and empty for a
	// database in memory, which no other process reaches.
	file string
	// recorded is whether the database keeps a record of schema changes. A
	// serving instance's database does, being at its build's version.
	recorded bool
}

// NewObserver is an Observer of db.
func NewObserver(ctx context.Context, db *database.DB) (*Observer, error) {
	o := &Observer{db: db}
	recorded, err := tableExists(ctx, db, ChangeTable)
	if err != nil {
		return nil, err
	}
	o.recorded = recorded
	switch db.Server.Engine {
	case database.MySQL, database.MariaDB:
		name, err := namedLock(ctx, db, changeName)
		if err != nil {
			return nil, err
		}
		o.name = name
	case database.SQLite:
		path, err := sqliteFile(ctx, db)
		if err != nil {
			return nil, err
		}
		if path != "" {
			o.file = path + changeSuffix
		}
	}
	return o, nil
}

// Change is what a look found of a schema change.
type Change int

const (
	// Unchanged is no lock held and no record standing.
	Unchanged Change = iota
	// Held is the schema change lock held by an instance changing the schema.
	Held
	// Recorded is a record standing of an upgrade to a later version than the
	// one applied, with the lock free: one that left the schema part changed,
	// or committed a migration before its version was recorded.
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
	// Read again, since an upgrade may have finished and let go of the lock
	// between the two reads: an absent lock with the first version would
	// read as this build's schema when it is already the next one's.
	later, err := o.applied(asking, conn)
	return changing, max(applied, later), err
}

// changing reports whether an instance holds the schema change lock, which it
// holds from before its first migration's statements to after its last, or
// else whether a record stands of an upgrade reaching a version later than
// applied.
func (o *Observer) changing(ctx context.Context, q rowQuerier, applied int64) (Change, error) {
	held, err := o.locked(ctx, q)
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

// locked reports whether an instance holds the schema change lock.
func (o *Observer) locked(ctx context.Context, q rowQuerier) (bool, error) {
	switch o.db.Server.Engine {
	case database.Postgres:
		var held int
		if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM "pg_catalog"."pg_locks"
			WHERE "locktype" = 'advisory' AND "granted"
			AND "database" = (SELECT "oid" FROM "pg_catalog"."pg_database" WHERE "datname" = current_database())
			AND "classid"::bigint = ? AND "objid"::bigint = ? AND "objsubid" = 1`,
			int64(changeID>>32), int64(changeID&0xffffffff)).Scan(&held); err != nil {
			return false, fmt.Errorf("ask whether the schema is changing: %w", err)
		}
		return held > 0, nil
	case database.MySQL, database.MariaDB:
		var holder sql.NullInt64
		if err := q.QueryRowContext(ctx, "SELECT IS_USED_LOCK(?)", o.name).Scan(&holder); err != nil {
			return false, fmt.Errorf("ask whether the schema is changing: %w", err)
		}
		return holder.Valid, nil
	case database.SQLite:
		if o.file == "" {
			return false, nil
		}
		return fileLocked(o.file)
	}
	return false, fmt.Errorf("no schema change lock for %s", o.db.Server.Engine)
}

// applied reports the highest schema version applied, in one query on the
// migration library's bookkeeping table.
func (o *Observer) applied(ctx context.Context, q rowQuerier) (int64, error) {
	var applied sql.NullInt64
	if err := q.QueryRowContext(ctx,
		`SELECT MAX("version_id") FROM "`+VersionTable+`" WHERE "is_applied"`).Scan(&applied); err != nil {
		return 0, fmt.Errorf("read the schema version: %w", err)
	}
	return applied.Int64, nil
}
