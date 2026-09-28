// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

// A slot is leased through a lock on the server, so these run against the
// servers only. Each names a package no real test binary has, so the slots it
// takes and the databases it makes are its own.

// slotPath is a package path of this test's own on engine: nothing else leases
// its slots or makes its databases.
func slotPath(t *testing.T, engine database.Engine) string {
	t.Helper()
	return fmt.Sprintf("example.com/slots%s%d.test", suffixFor(t, engine), time.Now().UnixNano())
}

// leaseFor takes a slot of path for the test, and gives it back when the test
// ends unless the test gave it back first.
func leaseFor(t *testing.T, engine database.Engine, base, path string) *lease {
	t.Helper()
	held, err := takeSlot(t.Context(), engine, base, path)
	if err != nil {
		t.Fatalf("lease a slot: %v", err)
	}
	t.Cleanup(func() { _ = held.release(context.Background()) })
	return held
}

// dropAfter drops the databases named when the test ends.
func dropAfter(t *testing.T, admin *database.DB, names ...string) {
	t.Helper()
	t.Cleanup(func() {
		for _, name := range names {
			if _, err := admin.ExecContext(context.Background(),
				`DROP DATABASE IF EXISTS "`+name+`"`); err != nil {
				t.Errorf("clean up %s: %v", name, err)
			}
		}
	})
}

// Two test binaries of one package starting at once, from two checkouts, each
// come away with a slot of their own. A shared slot is a shared database, and
// each empties it before every test, so each would delete the other's rows.
//
// Verified by making tryLock answer true without asking: every lessee then
// takes the first slot.
func TestTwoLesseesOfOnePackageNeverShareASlot(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		path := slotPath(t, engine)
		const lessees = 6
		var (
			wg    sync.WaitGroup
			mu    sync.Mutex
			slots []int
		)
		start := make(chan struct{})
		for range lessees {
			wg.Go(func() {
				<-start
				held, err := takeSlot(context.Background(), engine, base, path)
				if err != nil {
					t.Errorf("lease a slot: %v", err)
					return
				}
				t.Cleanup(func() { _ = held.release(context.Background()) })
				mu.Lock()
				slots = append(slots, held.slot)
				mu.Unlock()
			})
		}
		close(start)
		wg.Wait()
		if len(slots) != lessees {
			t.Fatalf("%d of %d lessees got a slot", len(slots), lessees)
		}
		slices.Sort(slots)
		if len(slices.Compact(slices.Clone(slots))) != lessees {
			t.Errorf("lessees running at once shared a slot: %v", slots)
		}

		// Another package's slots are its own: while every slot above is held,
		// it still takes the first of its own.
		other := leaseFor(t, engine, base, slotPath(t, engine)+"other")
		if other.slot != 1 {
			t.Errorf("another package took slot %d, want 1: the lock is not keyed on the package", other.slot)
		}
	})
}

// A slot given back is the next one leased, and its database is used as it
// stands where the schema matches, rather than built again: building it is
// most of what a server engine costs a run.
//
// Verified by making prepareServer treat every kept database as half built:
// the slot's database is then dropped and built again, and the mark is gone.
func TestAReleasedSlotIsReusedWithItsDatabase(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		ctx := t.Context()
		admin := Open(t, base)
		path := slotPath(t, engine)
		fingerprint, err := migrations.Fingerprint()
		if err != nil {
			t.Fatal(err)
		}

		first := leaseFor(t, engine, base, path)
		name := databaseName(path, first.slot, fingerprint)
		dropAfter(t, admin, name)
		own, err := prepareServer(ctx, engine, base, name)
		if err != nil {
			t.Fatalf("prepare the slot's database: %v", err)
		}
		// Something the harness would not put there, so a database built
		// again is told apart from one kept.
		mark := openClosed(t, own)
		if _, err := mark.ExecContext(ctx, `CREATE TABLE "dbtest_kept" ("id" INT)`); err != nil {
			t.Fatalf("mark the database: %v", err)
		}
		if err := mark.Close(); err != nil {
			t.Fatal(err)
		}
		if err := first.release(ctx); err != nil {
			t.Fatalf("give the slot back: %v", err)
		}

		second := leaseFor(t, engine, base, path)
		if second.slot != first.slot {
			t.Fatalf("the slot given back was %d and the next lease took %d", first.slot, second.slot)
		}
		again, err := prepareServer(ctx, engine, base, databaseName(path, second.slot, fingerprint))
		if err != nil {
			t.Fatalf("prepare the slot's database again: %v", err)
		}
		db := Open(t, again)
		var kept int
		if err := db.NewSelect().TableExpr(`"dbtest_kept"`).ColumnExpr("COUNT(*)").
			Scan(ctx, &kept); err != nil {
			t.Errorf("the slot's database was built again rather than kept: %v", err)
		}
	})
}

// A test binary never gives its slot back itself. The process ends, the
// connection holding the lock closes with it, and the server releases the
// lock — which is also all a crash does.
//
// Verified by leaving the lease's pool open after its connection closes: the
// connection goes back to the pool with its session, and the slot stays held.
func TestASlotIsFreedWhenItsConnectionCloses(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		path := slotPath(t, engine)
		held := leaseFor(t, engine, base, path)
		// What a process ending does to it: the connection closes and nobody
		// asks for the lock to be released.
		_ = held.conn.Close()
		_ = held.db.Close()

		admin := Open(t, base)
		conn, err := admin.DB.DB.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		// The server ends the session on its own time after the socket
		// closes, so the question is asked until it answers or a few seconds
		// pass.
		deadline := time.Now().Add(10 * time.Second)
		for {
			free, err := tryLock(t.Context(), conn, engine, held.key)
			if err != nil {
				t.Fatal(err)
			}
			if free {
				_ = unlock(t.Context(), conn, engine, held.key)
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the slot %s is still held after its connection closed", held.key)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

// The clean drops a database nobody is using and leaves one a running test
// binary holds, so it can run while other checkouts run their tests. A name
// with no slot in it has a lock nobody takes, and goes with the unheld.
//
// Verified by making dropUnheld drop whatever tryLock answers: the held
// slot's database then goes too.
func TestTheCleanLeavesAHeldSlotAndDropsAnUnheldOne(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		ctx := t.Context()
		admin := Open(t, base)
		path := slotPath(t, engine)
		held := leaseFor(t, engine, base, path)
		freed := leaseFor(t, engine, base, path)
		if err := freed.release(ctx); err != nil {
			t.Fatal(err)
		}

		inUse := databaseName(path, held.slot, schemaOne)
		unused := databaseName(path, freed.slot, schemaOne)
		prefix := strings.TrimSuffix(slotName(path, 1), "01")
		// The shape a database had before slots: the package, a hash and a
		// fingerprint, and nothing a lease locks.
		slotless := prefix + "abcdef"
		dropAfter(t, admin, inUse, unused, slotless)
		for _, name := range []string{inUse, unused, slotless} {
			if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
				t.Fatalf("make %s: %v", name, err)
			}
		}

		dropped, kept, err := dropUnheld(ctx, engine, base, prefix)
		if err != nil {
			t.Fatalf("clean: %v", err)
		}
		left, err := databasesFor(ctx, admin, engine, prefix)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(left, []string{inUse}) || !slices.Equal(kept, []string{inUse}) {
			t.Errorf("the server holds %v and the clean says it left %v, want %s alone: "+
				"the held slot's database is the only one in use", left, kept, inUse)
		}
		slices.Sort(dropped)
		want := []string{unused, slotless}
		slices.Sort(want)
		if !slices.Equal(dropped, want) {
			t.Errorf("the clean dropped %v, want %v", dropped, want)
		}
		// The lock the clean took to drop a database is given back.
		again := leaseFor(t, engine, base, path)
		if again.slot != freed.slot {
			t.Errorf("after the clean the next lease took slot %d, want %d", again.slot, freed.slot)
		}
	})
}
