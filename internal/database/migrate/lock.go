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
// **The connection is pinned deliberately.** These are session locks. Taking
// one on the pool and releasing it on the pool means the release can land on a
// different connection — and neither engine reports that as an error, it just
// silently fails to release. The lock would then be held for the life of the
// process and every other instance would block on it.
func acquire(ctx context.Context, db *database.DB) (unlock, error) {
	if db.Server.Engine == database.SQLite {
		// SQLite has no advisory lock and cannot take one on this handle: it
		// is capped at a single connection, which the migration itself needs.
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
			closeConn()
			return nil, fmt.Errorf("take migration lock: %w", err)
		}
		return func(ctx context.Context) error {
			defer closeConn()
			// pg_advisory_unlock returns false when this session did not hold
			// the lock. Executing it without reading the result would report
			// success while leaking the lock.
			var released bool
			if err := conn.QueryRowContext(ctx,
				"SELECT pg_advisory_unlock($1)", lockID).Scan(&released); err != nil {
				return fmt.Errorf("release migration lock: %w", err)
			}
			if !released {
				return fmt.Errorf("migration lock was not held by this session when released")
			}
			return nil
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
			closeConn()
			return nil, fmt.Errorf("another instance holds the migration lock")
		}
		return func(ctx context.Context) error {
			defer closeConn()
			// RELEASE_LOCK returns 0 when held by another session and NULL
			// when no such lock exists. Neither is an error to the driver.
			var released *int
			if err := conn.QueryRowContext(ctx,
				"SELECT RELEASE_LOCK(?)", name).Scan(&released); err != nil {
				return fmt.Errorf("release migration lock: %w", err)
			}
			if released == nil || *released != 1 {
				return fmt.Errorf("migration lock was not held by this session when released")
			}
			return nil
		}, nil
	}

	closeConn()
	return nil, fmt.Errorf("no migration lock for %s", db.Server.Engine)
}

// versionTableExists reports whether the migration bookkeeping table is there.
//
// Asking before reading the version keeps "migrate status" from creating it.
// The library's version query creates the table when it is missing, which
// makes a read-only inspection command perform schema changes — and no schema
// rights while running says the running application may hold read and write
// rights only.
//
// **"The table is not there" and "I could not look" arrive the same way.** An
// absent table is an error rather than an empty result, so every other failure
// — a credential without SELECT on the version table, a reset connection, a
// deadline — reads as an empty database unless something tells them apart. It
// read as one, and "schema version 0" against a fully populated database
// invites an operator to migrate it again.
//
// So a failed probe is followed by a trivial one. A database that answers the
// second was reachable, and the first failure was about the table; a database
// that answers neither could not be read, and says so. Two probes rather than
// matching each engine's code for an absent relation, which is four spellings
// of a question that has a portable answer.
func versionTableExists(ctx context.Context, db *database.DB) (bool, error) {
	var probe int
	err := db.QueryRowContext(ctx, "SELECT 1 FROM goose_db_version LIMIT 1").Scan(&probe)
	if err == nil || database.IsNoRows(err) {
		return true, nil
	}
	var alive int
	if reachable := db.QueryRowContext(ctx, "SELECT 1").Scan(&alive); reachable != nil {
		return false, fmt.Errorf("read the schema version: %w", err)
	}
	return false, nil
}
