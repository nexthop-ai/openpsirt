package migrate

import (
	"context"
	"os"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
)

// This package cannot use dbtest: dbtest builds the schema, the schema is
// applied through this package, and Go allows no such cycle in a test. So
// the two helpers it needs are here, in the smallest form that works.
//
// What is *not* copied here is which engines a run may touch. That rule lives
// in dbtest/engines, which imports neither this package nor dbtest, precisely
// so the copy in this file does not have to exist — it is the rule the quick
// loop and the race run set, and this test used to ignore it and open three
// servers regardless.
const (
	postgresURLEnv = "OPENPSIRT_TEST_POSTGRES_URL"
	mysqlURLEnv    = "OPENPSIRT_TEST_MYSQL_URL"
	mariadbURLEnv  = "OPENPSIRT_TEST_MARIADB_URL"
)

func open(t *testing.T, url string) *database.DB {
	t.Helper()
	target, err := database.ParseURL(url)
	if err != nil {
		t.Fatalf("parse %q: %v", url, err)
	}
	db, err := database.Open(context.Background(), target)
	if err != nil {
		t.Fatalf("open %s: %v", target.Redacted, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestLockExcludesAnotherConnection is the only test that exercises the
// advisory lock.
//
// It cannot be written through schema.Up: every caller there serializes on the
// in-process mutex before reaching acquire, so a test driving goroutines
// through Up passes with the entire advisory lock deleted. It proves the mutex
// and nothing else. This drives acquire directly, from two separate pools.
func TestLockExcludesAnotherConnection(t *testing.T) {
	// Otherwise the second attempt waits five minutes.
	restore := lockWaitSeconds
	lockWaitSeconds = 2
	t.Cleanup(func() { lockWaitSeconds = restore })

	for name, env := range map[database.Engine]string{
		database.Postgres: postgresURLEnv,
		database.MySQL:    mysqlURLEnv,
		database.MariaDB:  mariadbURLEnv,
	} {
		t.Run(string(name), func(t *testing.T) {
			// This is an internal test of the migrate package and dbtest
			// depends on migrate, so the narrowing comes from the package
			// below both rather than from a second copy of the parsing here.
			engines.SkipUnless(t, name)
			url := os.Getenv(env)
			if url == "" {
				t.Skipf("%s is not set, so the migration lock is untested here", env)
			}
			ctx := t.Context()

			// Two pools, as two instances would be.
			first := open(t, url)
			second := open(t, url)

			release, err := acquire(ctx, first)
			if err != nil {
				t.Fatalf("first instance could not take the lock: %v", err)
			}

			// The whole point: while one holds it, another must not get it.
			if release2, err := acquire(ctx, second); err == nil {
				_ = release2(ctx)
				_ = release(ctx)
				t.Fatal("a second instance took the migration lock while it was held")
			}

			if err := release(ctx); err != nil {
				t.Fatalf("release: %v", err)
			}

			// And once released, the next instance must get it — a lock that
			// is never released is as broken as one that never excludes.
			release2, err := acquire(ctx, second)
			if err != nil {
				t.Fatalf("lock was not released: %v", err)
			}
			if err := release2(ctx); err != nil {
				t.Errorf("release by the second instance: %v", err)
			}
		})
	}
}

func TestSQLiteNeedsNoAdvisoryLock(t *testing.T) {
	db := open(t, "sqlite://"+t.TempDir()+"/lock.db")
	release, err := acquire(context.Background(), db)
	if err != nil {
		t.Fatalf("acquire on sqlite: %v", err)
	}
	if err := release(context.Background()); err != nil {
		t.Errorf("release on sqlite: %v", err)
	}
	_ = database.SQLite
}

func TestTheLockLeavesNoSettingOnAConnectionItHandsBack(t *testing.T) {
	// The bound on the lock wait is a session setting, and Close returns the
	// connection to the pool rather than closing it — which is why the
	// connection is pinned in the first place. Left set, one pooled connection
	// carries a 300-second bound and the others carry the server's default, so
	// the same query afterwards either waits indefinitely or is cancelled,
	// decided by which connection the pool happens to hand out.
	engines.SkipUnless(t, database.Postgres)
	url := os.Getenv(postgresURLEnv)
	if url == "" {
		t.Skipf("%s is not set", postgresURLEnv)
	}
	db := open(t, url)
	ctx := context.Background()

	var before string
	if err := db.QueryRowContext(ctx, "SHOW lock_timeout").Scan(&before); err != nil {
		t.Fatalf("read the bound before: %v", err)
	}

	release, err := acquire(ctx, db)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}

	// The pool holds one connection under the default settings, so the
	// checkout after the release is the connection the lock was taken on.
	var after string
	if err := db.QueryRowContext(ctx, "SHOW lock_timeout").Scan(&after); err != nil {
		t.Fatalf("read the bound after: %v", err)
	}
	if after != before {
		t.Errorf("the connection went back to the pool carrying lock_timeout = %q, not %q", after, before)
	}
}

func TestAnUnreadableVersionIsNotAnEmptyDatabase(t *testing.T) {
	// "The table is not there" and "I could not look" arrived the same way, so
	// a database whose credentials cannot read the version table reported
	// version 0 — and the reasonable thing to do about "nothing is applied" is
	// to migrate a database that may be fully populated.
	engines.SkipUnless(t, database.Postgres)
	url := os.Getenv(postgresURLEnv)
	if url == "" {
		t.Skipf("%s is not set", postgresURLEnv)
	}
	db := open(t, url)
	ctx := context.Background()

	// A database with no version table reads as version 0, which is the
	// answer that has to keep working.
	there, err := versionTableExists(ctx, db)
	if err != nil {
		t.Fatalf("probing a reachable database reported a failure: %v", err)
	}
	t.Logf("the version table is there: %v", there)

	// And one that cannot be reached at all reports that, rather than zero.
	closed := open(t, url)
	if err := closed.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := versionTableExists(ctx, closed); err == nil {
		t.Error("a database that could not be read reported that the version table is simply absent")
	}
}
