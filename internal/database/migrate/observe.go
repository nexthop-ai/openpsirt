// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"fmt"

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

// Changing reports whether an instance holds the schema change lock, which it
// holds from before its first migration's statements to after its last, or a
// record of an upgrade that left the schema part changed stands.
func (o *Observer) Changing(ctx context.Context) (bool, error) {
	held, err := o.locked(ctx)
	if err != nil || held || !o.recorded {
		return held, err
	}
	var records int
	if err := o.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "`+ChangeTable+`"`).Scan(&records); err != nil {
		return false, fmt.Errorf("read the record of schema changes: %w", err)
	}
	return records > 0, nil
}

// locked reports whether an instance holds the schema change lock.
func (o *Observer) locked(ctx context.Context) (bool, error) {
	switch o.db.Server.Engine {
	case database.Postgres:
		var held int
		if err := o.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "pg_catalog"."pg_locks"
			WHERE "locktype" = 'advisory' AND "granted"
			AND "database" = (SELECT "oid" FROM "pg_catalog"."pg_database" WHERE "datname" = current_database())
			AND "classid"::bigint = ? AND "objid"::bigint = ? AND "objsubid" = 1`,
			int64(changeID>>32), int64(changeID&0xffffffff)).Scan(&held); err != nil {
			return false, fmt.Errorf("ask whether the schema is changing: %w", err)
		}
		return held > 0, nil
	case database.MySQL, database.MariaDB:
		var holder sql.NullInt64
		if err := o.db.QueryRowContext(ctx, "SELECT IS_USED_LOCK(?)", o.name).Scan(&holder); err != nil {
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

// Applied reports the highest schema version applied, in one query on the
// migration library's bookkeeping table.
func (o *Observer) Applied(ctx context.Context) (int64, error) {
	var applied sql.NullInt64
	if err := o.db.QueryRowContext(ctx,
		`SELECT MAX("version_id") FROM "`+VersionTable+`" WHERE "is_applied"`).Scan(&applied); err != nil {
		return 0, fmt.Errorf("read the schema version: %w", err)
	}
	return applied.Int64, nil
}
