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
