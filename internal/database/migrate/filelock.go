package migrate

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// sqliteLock excludes another process migrating the same SQLite file.
//
// The other three engines take a lock in the database and this one cannot.
// A SQLite handle is capped at one connection, because the file has one writer
// and more connections add contention rather than concurrency — so a lock held
// on a pinned connection would be holding the only connection the migration
// itself needs. Every in-database spelling of this deadlocks against that.
//
// So the lock is on a file beside the database, taken with the operating
// system's own advisory locking. That is released by the kernel when the
// process ends, however it ends, which is the property a lock file written and
// deleted by hand does not have: a crash there leaves a file nothing will ever
// remove, and every start afterwards refuses for a reason that is no longer
// true.
//
// What this buys is not integrity. Four processes migrating one file with
// no lock were run: one applied the schema and three failed, with "no such
// table: goose_db_version; table goose_db_version already exists". Nothing was
// corrupted and the schema ended correct. What the lock changes is that the
// three wait their turn and find the work already done, rather than crashing
// on a message about the migration library's bookkeeping.
func sqliteLock(ctx context.Context, db *database.DB) (unlock, error) {
	path, err := sqliteFile(ctx, db)
	if err != nil {
		return nil, err
	}
	if path == "" {
		// An in-memory database, which belongs to this process alone. There
		// is no file to lock and no second process that could reach it.
		return func(context.Context) error { return nil }, nil
	}
	return lockFile(ctx, path+lockSuffix, time.Duration(lockWaitSeconds)*time.Second)
}

// lockSuffix names the lock beside the database rather than locking the
// database file itself, so nothing here competes with SQLite's own locking of
// that file.
const lockSuffix = ".migrate-lock"

// sqliteFile asks the connection which file it is working on.
//
// Asked rather than carried down from the URL, which would mean threading a
// path through the handle for one engine's benefit. The answer is empty for an
// in-memory database.
func sqliteFile(ctx context.Context, db *database.DB) (string, error) {
	var seq int
	var name, file string
	// One row per attached database; the main one is always first.
	if err := db.QueryRowContext(ctx,
		"PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		return "", fmt.Errorf("ask which file this database is: %w", err)
	}
	return file, nil
}
