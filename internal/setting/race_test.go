package setting

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// TestEveryReplicaThatLosesTheMintTakesTheWinnersKey forces the collision
// rather than hoping for it.
//
// Four goroutines with nothing holding them at the line race only if the
// scheduler interleaves them, and nothing could tell a run that never collided
// from one that collided and recovered. So a recovery broken on every server
// engine — the read ran inside the transaction whose insert had just failed,
// which sees nothing on MySQL and MariaDB and is refused outright on
// PostgreSQL — passed locally and failed in CI.
//
// Here every writer is held after its opening read until all of them have
// taken one, so every loser reaches the duplicate arm on every run, and the
// test asserts that it did.
//
// The servers only, because holding four transactions open is the whole
// method: SQLite's pool is one connection, so the second writer would wait for
// a connection the first is holding. It is also where the defect lived — the
// broken version was correct on SQLite and wrong on all three servers.
func TestEveryReplicaThatLosesTheMintTakesTheWinnersKey(t *testing.T) {
	dbtest.Servers(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)
		ctx := t.Context()

		const replicas = 4
		// Released once every writer has read and found nothing, so the row
		// each is about to insert collides with whichever commits first.
		var ready, start sync.WaitGroup
		ready.Add(replicas)
		start.Add(1)

		stores := make([]*Store, replicas)
		for i := range stores {
			// One store each, so a transaction the helper retries cannot
			// signal the barrier twice.
			store := NewStore(db.DB)
			var once sync.Once
			store.beforeInsert = func() {
				once.Do(func() {
					ready.Done()
					start.Wait()
				})
			}
			stores[i] = store
		}

		var wait sync.WaitGroup
		got := make([]string, replicas)
		failures := make([]error, replicas)
		wait.Add(replicas)
		for i := range got {
			go func() {
				defer wait.Done()
				got[i], failures[i] = stores[i].SetIfAbsent(ctx, SignInKey,
					fmt.Sprintf("minted-by-%d", i))
			}()
		}
		// Every writer has now read and found nothing. Let them all insert.
		ready.Wait()
		start.Done()
		wait.Wait()

		for i, err := range failures {
			if err != nil {
				t.Fatalf("replica %d could not mint: %v", i+1, err)
			}
		}
		// They all sign with one key, and it is one somebody minted.
		for i, key := range got {
			if key != got[0] {
				t.Errorf("replica %d signs with %q and replica 1 with %q", i+1, key, got[0])
			}
		}
		if !strings.HasPrefix(got[0], "minted-by-") {
			t.Errorf("the key everybody took is %q, which nobody minted", got[0])
		}
		// And the race actually happened: three of the four took a key that is
		// not the one they minted, which is reachable only through the arm
		// this test exists for. Asserted rather than assumed, because a run
		// that collided with nothing would pass every line above it without
		// entering that arm at all.
		lost := 0
		for i, key := range got {
			if key != fmt.Sprintf("minted-by-%d", i) {
				lost++
			}
		}
		if lost != replicas-1 {
			t.Errorf("%d of %d replicas lost the mint, want %d — the rest never "+
				"collided, so the recovery was not exercised", lost, replicas, replicas-1)
		}

		// And what is stored is what they all took, rather than a fifth value
		// nobody is using.
		stored, found, err := stores[0].Get(ctx, SignInKey)
		if err != nil || !found {
			t.Fatalf("the minted key is not stored: %v found=%v", err, found)
		}
		if stored != got[0] {
			t.Errorf("the stored key is %q and everybody signs with %q", stored, got[0])
		}
	})
}

// TestTheWriterThatLosesTheRowReportsWhatItActuallyReplaced forces the
// interleave rather than hoping for it.
//
// Two goroutines with nothing holding them at the line collide only if the
// scheduler puts both reads before either write, so the unforced version of
// this in setting_test.go passes on most runs whatever the code does — which
// is how a defect that writes a false trail row lived here, failing once in a
// merge queue and nowhere else.
//
// Here both writers are held after the read that answers what the setting
// held, so both have read the original when they are let go. One replaces it;
// the other's condition matches nothing and it goes round again against a row
// that has moved, which is the arm this test exists for and is asserted rather
// than assumed.
//
// The servers only, for the reason the mint race is: holding two transactions
// open is the whole method, and SQLite's pool is one connection, so the second
// writer would wait for a connection the first is holding.
func TestTheWriterThatLosesTheRowReportsWhatItActuallyReplaced(t *testing.T) {
	dbtest.Servers(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)
		ctx := t.Context()

		// Something to replace, written by a store with no seam on it so that
		// seeding does not consume one.
		if err := NewStore(db.DB).Set(ctx, TriageFloor, "critical"); err != nil {
			t.Fatalf("the setting to be moved could not be recorded: %v", err)
		}

		const writers = 2
		// Released once both writers have read "critical", so whichever writes
		// second is writing over a value it never saw.
		var ready, start sync.WaitGroup
		ready.Add(writers)
		start.Add(1)

		stores := make([]*Store, writers)
		attempts := make([]int, writers)
		for i := range stores {
			// One store each, and the barrier is taken on the first attempt
			// only: a writer held again on the attempt it goes round for would
			// wait for a signal nobody is left to give.
			store := NewStore(db.DB)
			var once sync.Once
			store.beforeWrite = func() {
				attempts[i]++
				once.Do(func() {
					ready.Done()
					start.Wait()
				})
			}
			stores[i] = store
		}

		var wait sync.WaitGroup
		held := make([]string, writers)
		failures := make([]error, writers)
		wrote := []string{"medium", "low"}
		wait.Add(writers)
		for i, to := range wrote {
			go func() {
				defer wait.Done()
				held[i], _, failures[i] = stores[i].Change(ctx, TriageFloor, to)
			}()
		}
		// Both have read "critical". Let them both write.
		ready.Wait()
		start.Done()
		wait.Wait()

		for i, err := range failures {
			if err != nil {
				t.Fatalf("writer %d could not move the setting: %v", i+1, err)
			}
		}

		// One of them replaced "critical" and the other replaced what that one
		// wrote. Reporting it twice is the defect: what each writer reports is
		// what the trail records it replaced.
		if held[0] == held[1] {
			t.Fatalf("both writers report replacing %q, so one of them did not", held[0])
		}
		type writer struct {
			held     string
			wrote    string
			attempts int
		}
		won := writer{held[0], wrote[0], attempts[0]}
		lost := writer{held[1], wrote[1], attempts[1]}
		if lost.held == "critical" {
			won, lost = lost, won
		}
		if won.held != "critical" {
			t.Fatalf("neither writer reports replacing \"critical\": %q and %q", held[0], held[1])
		}
		if lost.held != won.wrote {
			t.Errorf("the writer that lost reports replacing %q; the one that won wrote %q",
				lost.held, won.wrote)
		}

		// And it lost by matching no row and going again, rather than by
		// arriving second at a lock. Asserted because a run where the barrier
		// released them in order would satisfy every line above it without
		// entering that arm at all.
		if won.attempts != 1 {
			t.Errorf("the writer that won took %d attempts, want 1", won.attempts)
		}
		if lost.attempts != 2 {
			t.Errorf("the writer that lost took %d attempts, want 2 — it did not go "+
				"round again, so the condition on the write was not what stopped it",
				lost.attempts)
		}

		// The stored value is the loser's: it wrote last, and it wrote
		// knowing what it was replacing.
		stored, found, err := stores[0].Get(ctx, TriageFloor)
		if err != nil || !found {
			t.Fatalf("the setting is not stored: %v found=%v", err, found)
		}
		if stored != lost.wrote {
			t.Errorf("the setting holds %q and the writer that wrote last wrote %q",
				stored, lost.wrote)
		}
	})
}
