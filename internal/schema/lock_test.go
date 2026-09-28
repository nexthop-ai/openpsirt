// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

func TestConcurrentMigrationsInOneProcessDoNotCollide(t *testing.T) {
	// This covers goroutines in a single process, and nothing more.
	//
	// Two things serialize the callers: the in-process mutex, and the lock
	// that excludes other instances — on SQLite a lock on a file beside the
	// database. Either alone is enough, so this pins the pair; the lock that
	// excludes other instances is tested on its own in
	// internal/database/migrate, driving acquire directly from two pools.
	//
	// The database starts empty, so every migration is applied while the
	// four callers race for it; on one already migrated each Up has nothing
	// to do and no collision is possible. A new empty database is a file on
	// SQLite and a server-side database elsewhere, so this runs on SQLite.
	// Verified by deleting the mutex's Lock and Unlock and making the file
	// lock a no-op: every caller but one fails creating the version table.
	dbtest.Only(t, database.SQLite, func(t *testing.T, _ *database.DB) {
		db := dbtest.Open(t, "sqlite://"+filepath.Join(t.TempDir(), "fresh.db"))
		const instances = 4

		var wg sync.WaitGroup
		errs := make([]error, instances)
		start := make(chan struct{})

		for i := range instances {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // let them all try at the same moment
				errs[i] = schema.Up(t.Context(), db, quiet())
			}()
		}
		close(start)
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Errorf("instance %d failed to migrate: %v", i, err)
			}
		}
		version, err := schema.Version(t.Context(), db)
		if err != nil {
			t.Fatalf("read version: %v", err)
		}
		wanted, err := schema.Expected()
		if err != nil {
			t.Fatalf("read what this build expects: %v", err)
		}
		if version != wanted {
			t.Errorf("four instances migrating at once left version %d, and this build expects %d",
				version, wanted)
		}
	})
}
