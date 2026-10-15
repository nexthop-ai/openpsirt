// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: a name, not a signature; the choice is the length of the hex, and the input is a database name
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// lockName identifies the migration lock. The numeric form is for engines that
// take an integer; the text form is for those that take a name.
//
// A PostgreSQL advisory lock belongs to the database it is taken in. A MySQL
// or MariaDB named lock belongs to the server, so the name there carries the
// database: the lock is about one schema, and two databases on one server
// migrating at once are not in each other's way. Named locks are capped at
// 64 characters, so a long database name is hashed rather than cut.
const (
	lockName = "openpsirt_migrate"
	lockID   = 8_147_263_001
)

func namedLock(ctx context.Context, conn *sql.Conn) (string, error) {
	var current sql.NullString
	if err := conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&current); err != nil {
		return "", fmt.Errorf("read the current database: %w", err)
	}
	name := lockName + ":" + current.String
	if len(name) > 64 {
		sum := sha1.Sum([]byte(current.String)) //nolint:gosec // G401: see the import
		name = lockName + ":" + hex.EncodeToString(sum[:])
	}
	return name, nil
}

// lockWaitSeconds bounds how long we wait for another instance to finish. A
// variable rather than a constant only so tests can shorten it; nothing in the
// application changes it.
// Long enough for a real migration, short enough that a stuck one is noticed
// rather than blocking every replacement pod indefinitely.
var lockWaitSeconds = 300

// resetWait bounds unwinding the session before the connection goes back to
// the pool. It is one round trip against a server that has just answered.
const resetWait = 5 * time.Second

// keepAliveEvery is how often the connection holding the lock is used while
// the migration runs on another. A variable only so tests can shorten it.
//
// The lock is a session lock, so it lasts as long as the session. The pool's
// idle timeout closes an idle connection before anything in the path kills it,
// and it only reaches connections in the pool: this one is checked out for the
// whole migration and issues nothing between taking the lock and releasing
// it. A server's own idle timeout, or an intermediary's, would end the session
// part way through, the server would release the lock, and a replica waiting
// on it would migrate the half-migrated schema. Half a minute sits under the
// common idle timeouts by the margin the pool's minute does.
var keepAliveEvery = 30 * time.Second

// keepAlive uses a pinned connection on a timer until stopped. The stop waits
// for the last use to finish, because a connection is not safe to use from
// two goroutines and the release comes next.
func keepAlive(ctx context.Context, conn *sql.Conn) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		tick := time.NewTicker(keepAliveEvery)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				// No deadline: both drivers close a connection whose query
				// outlived its context, and the server releases the lock with
				// the session. A use that fails says the session may be gone,
				// which the release reports when it finds the lock no longer
				// held.
				_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT 1")
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// unlock releases a migration lock and returns the pinned connection.
type unlock func(context.Context) error

// acquire takes the migration lock, so that instances starting at once do not
// migrate at the same time.
//
// This is one of the few places the portable-SQL rule does not hold: every
// engine spells advisory locking differently, and placeholders here are the
// driver's native form rather than the query builder's, because the lock must
// be taken on a pinned connection rather than on the pool.
//
// The connection is pinned deliberately. These are session locks. Taking
// one on the pool and releasing it on the pool means the release can land on a
// different connection — and neither engine reports that as an error, it just
// silently fails to release. The lock would then be held for the life of the
// process and every other instance would block on it.
func acquire(ctx context.Context, db *database.DB) (unlock, error) {
	if db.Server.Engine == database.SQLite {
		// SQLite has no advisory lock and cannot take one on this handle: it
		// migrates on a single connection, which the migration itself needs.
		// The exclusion is a lock on a file beside the database — see
		// filelock.go, which has the whole of why.
		return sqliteLock(ctx, db)
	}

	conn, err := db.DB.DB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("pin a connection for the migration lock: %w", err)
	}
	// The session settings this function makes are unwound before the
	// connection goes back. Close returns it to the pool rather than closing
	// it — which is the whole reason the connection is pinned above — so a
	// setting left behind travels on one pooled connection and not the others,
	// and the same query afterwards behaves differently depending on which
	// connection it is handed.
	closeConn := func() {
		if db.Server.Engine == database.Postgres {
			// Without a context of its own this would be skipped on exactly
			// the path that most needs it: a migration abandoned because its
			// context ended.
			reset, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetWait)
			defer cancel()
			// A reset that fails leaves the connection carrying the bound,
			// which is the state this arrived in and is stricter rather than
			// looser. There is nothing further to do about it from a cleanup
			// that runs on every path including the failing ones.
			_, _ = conn.ExecContext(reset, "RESET lock_timeout")
		}
		if err := conn.Close(); err != nil {
			_ = err // returning the connection to the pool; nothing to do
		}
	}

	switch db.Server.Engine {
	case database.Postgres:
		// Bound the wait. Without this, pg_advisory_lock waits forever: an
		// instance wedged mid-migration blocks every replacement silently,
		// and the startup probe kills each one in turn.
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf("SET lock_timeout = '%ds'", lockWaitSeconds)); err != nil {
			closeConn()
			return nil, fmt.Errorf("bound the migration lock wait: %w", err)
		}
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
			holder := holderOf(ctx, conn, db.Server.Engine, "")
			closeConn()
			return nil, fmt.Errorf("take migration lock%s: %w", holder, err)
		}
		stop := keepAlive(ctx, conn)
		return func(ctx context.Context) error {
			stop()
			defer closeConn()
			// pg_advisory_unlock answers false when this session did not hold
			// the lock. Executing it without reading the result would report
			// success while leaking the lock.
			var released *int
			if err := conn.QueryRowContext(ctx,
				"SELECT CAST(pg_advisory_unlock($1) AS INTEGER)", lockID).Scan(&released); err != nil {
				return fmt.Errorf("release migration lock: %w", err)
			}
			return heldWhenReleased(released)
		}, nil

	case database.MySQL, database.MariaDB:
		// GET_LOCK returns 1 when granted, 0 on timeout, NULL on error. A
		// timeout means another instance is migrating, which is not our
		// failure but does mean we must not proceed.
		name, err := namedLock(ctx, conn)
		if err != nil {
			closeConn()
			return nil, err
		}
		var granted *int
		row := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", name, lockWaitSeconds)
		if err := row.Scan(&granted); err != nil {
			closeConn()
			return nil, fmt.Errorf("take migration lock: %w", err)
		}
		if granted == nil || *granted != 1 {
			holder := holderOf(ctx, conn, db.Server.Engine, name)
			closeConn()
			return nil, fmt.Errorf("the migration lock %q is held%s", name, holder)
		}
		stop := keepAlive(ctx, conn)
		return func(ctx context.Context) error {
			stop()
			defer closeConn()
			// RELEASE_LOCK answers 0 when held by another session and NULL
			// when no such lock exists. Neither is an error to the driver.
			var released *int
			if err := conn.QueryRowContext(ctx,
				"SELECT RELEASE_LOCK(?)", name).Scan(&released); err != nil {
				return fmt.Errorf("release migration lock: %w", err)
			}
			return heldWhenReleased(released)
		}, nil
	}

	closeConn()
	return nil, fmt.Errorf("no migration lock for %s", db.Server.Engine)
}

// heldWhenReleased reads what a release answered: one where this session held
// the lock, and zero or nothing where it did not.
//
// A lock this session no longer holds is one it lost part way, and the server
// may have handed it to another instance in between.
func heldWhenReleased(released *int) error {
	if released == nil || *released != 1 {
		return fmt.Errorf("migration lock was not held by this session when released")
	}
	return nil
}

// holderOf names the session holding the migration lock, for a refusal to
// wait any longer, or says nothing where the server will not tell.
//
// Any account that can connect may take the lock: a named lock on MySQL and
// MariaDB needs no privilege and is shared by every database on the server,
// and an advisory lock on PostgreSQL has no permissions at all. A refusal that
// blames another instance sends an operator looking for a replica that may not
// exist, so it names the connection instead.
//
// On PostgreSQL every role sees each session's user and application; a role
// without the right to see other sessions sees neither their state nor their
// query. Where the server leaves a name empty the answer omits it.
func holderOf(ctx context.Context, conn *sql.Conn, engine database.Engine, name string) string {
	asking, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetWait)
	defer cancel()
	switch engine {
	case database.Postgres:
		var pid int64
		var user, application sql.NullString
		err := conn.QueryRowContext(asking, `SELECT "a"."pid", "a"."usename", "a"."application_name"
			FROM "pg_catalog"."pg_locks" AS "l"
			JOIN "pg_catalog"."pg_stat_activity" AS "a" ON "a"."pid" = "l"."pid"
			WHERE "l"."locktype" = 'advisory' AND "l"."granted"
			AND "l"."database" = (SELECT "oid" FROM "pg_catalog"."pg_database" WHERE "datname" = current_database())
			AND "l"."classid"::bigint = $1 AND "l"."objid"::bigint = $2 AND "l"."objsubid" = 1`,
			int64(lockID>>32), int64(lockID&0xffffffff)).Scan(&pid, &user, &application)
		if err != nil {
			return ""
		}
		held := fmt.Sprintf(" by server process %d", pid)
		if user.String != "" {
			held += fmt.Sprintf(", user %q", user.String)
		}
		if application.String != "" {
			held += fmt.Sprintf(", application %q", application.String)
		}
		return held
	case database.MySQL, database.MariaDB:
		var id sql.NullInt64
		if err := conn.QueryRowContext(asking, "SELECT IS_USED_LOCK(?)", name).Scan(&id); err != nil || !id.Valid {
			return ""
		}
		return fmt.Sprintf(" by connection %d", id.Int64)
	}
	return ""
}

// versionTableExists reports whether the migration bookkeeping table is there.
//
// Asking before reading the version keeps "migrate status" from creating it.
// The library's version query creates the table when it is missing, which
// makes a read-only inspection command perform schema changes — and no schema
// rights while running says the running application may hold read and write
// rights only.
//
// The catalog is asked, rather than the table. Selecting from the table
// answers three questions at once and cannot tell them apart: it is not there,
// this credential may not read it, or the database is unreachable. Read as the
// first, a fully populated database whose credentials omit this one table
// reports "schema version 0" — and the reasonable thing to do about "nothing
// is applied" is to migrate. Running migrations under a credential of their
// own is the documented reason automatic migration can be turned off, so that
// credential is the ordinary arrangement rather than an exotic one.
//
// PostgreSQL is asked through pg_class rather than the information schema,
// because the information schema is filtered by privilege on all three
// servers: a role with no rights on a table does not see the table there, so
// it gives back the same conflation this exists to remove. `pg_class` is
// readable by any role, so on that engine the two are genuinely told apart.
//
// On MySQL and MariaDB they are not. Every catalog those engines offer is
// privilege-filtered and there is no unfiltered one, so a credential that may
// not read the table is indistinguishable from an absent table. What that
// costs is bounded: the next thing to run is the version query or a migration,
// both of which fail with the engine's own permission message rather than
// silently.
func versionTableExists(ctx context.Context, db *database.DB) (bool, error) {
	return tableExists(ctx, db, versionTable)
}

// tableExists reports whether the catalog holds a table of a given name, by
// the name an unqualified reference to it resolves.
func tableExists(ctx context.Context, db *database.DB, name string) (bool, error) {
	query, err := catalogQuery(db.Server.Engine)
	if err != nil {
		return false, err
	}
	var probe int
	switch err := db.QueryRowContext(ctx, query, name).Scan(&probe); {
	case database.IsNoRows(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ask whether this database has been migrated: %w", err)
	}
	return true, nil
}

// catalogQuery asks one engine whether it holds a table of a given name.
//
// A catalog is engine-specific by nature: three of the four have an
// information schema, SQLite has a table of its own, and PostgreSQL is asked
// somewhere else again for the reason above.
//
// On PostgreSQL the name is resolved through the session's whole search path,
// the way the migration library's own unqualified reference resolves it. A
// runtime role with a schema of its own has that schema as its current one,
// and the table the migrations made sits in a schema further along the path.
// Resolving a name needs only the right to use the schema it is found in, so
// the answer is still not filtered by privilege on the table.
func catalogQuery(engine database.Engine) (string, error) {
	switch engine {
	case database.Postgres:
		return `SELECT 1 FROM "pg_catalog"."pg_class"
			WHERE "oid" = to_regclass(?::text) AND "relkind" = 'r'`, nil
	case database.MySQL, database.MariaDB:
		return `SELECT 1 FROM "information_schema"."TABLES"
			WHERE "TABLE_SCHEMA" = DATABASE() AND "TABLE_NAME" = ?`, nil
	case database.SQLite:
		return `SELECT 1 FROM "sqlite_master" WHERE "type" = 'table' AND "name" = ?`, nil
	}
	return "", fmt.Errorf("no way to read the catalog of %s", engine)
}

// versionTable is the migration library's bookkeeping table, which it names
// and this only reads.
const versionTable = "goose_db_version"
