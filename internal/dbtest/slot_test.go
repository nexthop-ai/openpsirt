// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A slot is leased through a lock on the server, so these run against the
// servers only. Each works in a namespace of its own, which no real test
// binary leases in and whose names no real lease collects, so the slots it
// takes and the databases it makes are its own.

// slotSpace is a namespace of this test's own on engine. Its names are under
// the harness's prefix, so a clean finds what a killed test leaves, and are
// not the shape of a real slot's name, so a real lease never collects them.
func slotSpace(t *testing.T, engine database.Engine) string {
	t.Helper()
	return fmt.Sprintf("%ss%s%d_", harnessPrefix, suffixFor(t, engine), time.Now().UnixNano())
}

// leaseFor takes a slot of the schema fingerprint names, in namespace, for
// the test, and gives it back when the test ends unless the test gave it back
// first.
func leaseFor(t *testing.T, engine database.Engine, base, namespace, fingerprint string) *lease {
	t.Helper()
	held, err := takeSlot(t.Context(), engine, base, namespace, fingerprint)
	if err != nil {
		t.Fatalf("lease a slot: %v", err)
	}
	t.Cleanup(func() { _ = held.release(context.Background()) })
	return held
}

// databaseFor is leaseDatabase for the test: the slot is given back when the
// test ends unless the test gave it back first.
func databaseFor(t *testing.T, engine database.Engine, base, namespace, fingerprint string) (*lease, string) {
	t.Helper()
	held, own, err := leaseDatabase(t.Context(), engine, base, namespace, fingerprint)
	if err != nil {
		t.Fatalf("lease a database: %v", err)
	}
	t.Cleanup(func() { _ = held.release(context.Background()) })
	return held, own
}

// dropAfter drops every database under namespace when the test ends.
func dropAfter(t *testing.T, admin *database.DB, engine database.Engine, namespace string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		names, err := databasesFor(ctx, admin, engine, namespace)
		if err != nil {
			t.Errorf("list what the test made: %v", err)
		}
		for _, name := range names {
			if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+name+`"`); err != nil {
				t.Errorf("clean up %s: %v", name, err)
			}
		}
	})
}

// Two test binaries starting at once, of one package or of two, from one
// checkout or two, each come away with a slot of their own. A shared slot is a
// shared database, and each empties it before every test, so each would delete
// the other's rows. Each lessee here holds a connection of its own, which is
// all a binary is to the server.
//
// Verified by making tryLock answer true without asking: every lessee then
// takes the first slot.
func TestTwoLesseesRunningAtOnceNeverShareASlot(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		namespace := slotSpace(t, engine)
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
				held, err := takeSlot(context.Background(), engine, base, namespace, schemaOne)
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

		// Another schema's slots are its own: while every slot above is held,
		// a binary built from another still takes the first of its own.
		other := leaseFor(t, engine, base, namespace, "abcabcabcabcabca")
		if other.slot != 1 {
			t.Errorf("another schema took slot %d, want 1: the lock is not keyed on the schema", other.slot)
		}
	})
}

// A binary that exits frees its slot, and the next binary to start, of any
// package, takes the slot and uses its database as it stands: building it is
// most of what a server engine costs a run.
//
// Verified by making prepareServer treat every kept database as half built:
// the second lessee then migrates again. And by naming a slot's database for
// something of the lessee's own, as a package was: the second lessee then
// creates a database and migrates it.
func TestTheNextBinaryTakesAFreedSlotWithoutMigrating(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		ctx := t.Context()
		admin := Open(t, base)
		namespace := slotSpace(t, engine)
		dropAfter(t, admin, engine, namespace)

		before := serverBuilds.Load()
		first, own := databaseFor(t, engine, base, namespace, schemaOne)
		if got := serverBuilds.Load() - before; got != 1 {
			t.Fatalf("the first lessee migrated %d databases, want 1", got)
		}
		if err := first.release(ctx); err != nil {
			t.Fatalf("give the slot back: %v", err)
		}

		second, again := databaseFor(t, engine, base, namespace, schemaOne)
		if second.slot != first.slot {
			t.Errorf("the slot given back was %d and the next lease took %d", first.slot, second.slot)
		}
		if again != own {
			t.Errorf("the next lessee was handed %s, want the freed slot's %s", again, own)
		}
		if got := serverBuilds.Load() - before; got != 1 {
			t.Errorf("two lessees in turn migrated %d databases, want 1: the second "+
				"built a database the first left whole", got)
		}
	})
}

// A binary built from an edited migration gets a database built for its own
// schema, and drops the older schema's databases nobody holds. One somebody
// holds is a checkout of the older tree running its tests, and is left.
//
// Verified by leaving the fingerprint out of the name: the edited schema's
// lessee is then handed the older schema's freed database. And by making dropUnheld drop whatever the locks answer: the held
// database then goes too.
func TestAnEditedSchemaGetsAFreshDatabaseAndLeavesAHeldOne(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		ctx := t.Context()
		admin := Open(t, base)
		namespace := slotSpace(t, engine)
		dropAfter(t, admin, engine, namespace)

		// Two slots of the older schema, one held and one given back. Neither
		// needs a schema in it, only a name.
		const older = "aaaaaaaaaaaaaaaa"
		held := leaseFor(t, engine, base, namespace, older)
		freed := leaseFor(t, engine, base, namespace, older)
		for _, slot := range []*lease{held, freed} {
			if _, err := ensureDatabase(ctx, admin, engine, slot.key); err != nil {
				t.Fatal(err)
			}
		}
		if err := freed.release(ctx); err != nil {
			t.Fatal(err)
		}

		before := serverBuilds.Load()
		edited, _ := databaseFor(t, engine, base, namespace, schemaOne)
		if edited.key == held.key || edited.key == freed.key {
			t.Errorf("a lessee of the edited schema was handed %s, which the older schema made", edited.key)
		}
		if got := serverBuilds.Load() - before; got != 1 {
			t.Errorf("a lessee of the edited schema migrated %d databases, want 1", got)
		}
		left, err := databasesFor(ctx, admin, engine, namespace)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{held.key, edited.key}
		slices.Sort(want)
		slices.Sort(left)
		if !slices.Equal(left, want) {
			t.Errorf("the server holds %v, want %v: the older schema's held database "+
				"stays, its unheld one goes, and the edited schema has its own", left, want)
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
		held := leaseFor(t, engine, base, slotSpace(t, engine), schemaOne)
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
// binary holds, so it can run while other checkouts run their tests. A
// database a harness keyed on the package made is held by the lock named for
// it without its last part, and is left while that is held. A name no lock
// guards goes with the unheld.
//
// Verified by making dropUnheld drop whatever the locks answer: the held
// databases then go too. And by asking for the database's own lock alone: the
// package-keyed database then goes while its lock is held.
func TestTheCleanLeavesAHeldSlotAndDropsAnUnheldOne(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		ctx := t.Context()
		admin := Open(t, base)
		namespace := slotSpace(t, engine)
		dropAfter(t, admin, engine, namespace)
		held := leaseFor(t, engine, base, namespace, schemaOne)
		freed := leaseFor(t, engine, base, namespace, schemaOne)
		if err := freed.release(ctx); err != nil {
			t.Fatal(err)
		}
		// A package-keyed harness's database and the slot lock it holds.
		packageSlot := namespace + "httpapi_1a2b3c_01"
		keyed := packageSlot + "_4d5e6f"
		holder := Open(t, base)
		conn, err := holder.DB.DB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if granted, err := tryLock(ctx, conn, engine, packageSlot); err != nil || !granted {
			t.Fatalf("hold the package slot's lock: %v, %v", granted, err)
		}
		// A name nothing locks: one made by hand.
		unguarded := namespace + "byhand"
		for _, name := range []string{held.key, freed.key, keyed, unguarded} {
			if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
				t.Fatalf("make %s: %v", name, err)
			}
		}

		dropped, kept, err := dropUnheld(ctx, engine, base, namespace, nil)
		if err != nil {
			t.Fatalf("clean: %v", err)
		}
		left, err := databasesFor(ctx, admin, engine, namespace)
		if err != nil {
			t.Fatal(err)
		}
		wantLeft := []string{held.key, keyed}
		slices.Sort(wantLeft)
		slices.Sort(left)
		slices.Sort(kept)
		if !slices.Equal(left, wantLeft) || !slices.Equal(kept, wantLeft) {
			t.Errorf("the server holds %v and the clean says it left %v, want %v alone: "+
				"those are the databases in use", left, kept, wantLeft)
		}
		slices.Sort(dropped)
		want := []string{freed.key, unguarded}
		slices.Sort(want)
		if !slices.Equal(dropped, want) {
			t.Errorf("the clean dropped %v, want %v", dropped, want)
		}
		// The locks the clean took to drop a database are given back.
		again := leaseFor(t, engine, base, namespace, schemaOne)
		if again.slot != freed.slot {
			t.Errorf("after the clean the next lease took slot %d, want %d", again.slot, freed.slot)
		}
	})
}
