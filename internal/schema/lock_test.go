// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

func TestConcurrentMigrationsInOneProcessDoNotCollide(t *testing.T) {
	// This covers goroutines in a single process, and nothing more.
	//
	// It cannot test the advisory lock: every caller serializes on the
	// in-process mutex before reaching it, so this passes with the entire
	// advisory lock deleted — verified. The lock that excludes *other
	// instances* is tested in internal/database/migrate, driving acquire
	// directly from two pools.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
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
