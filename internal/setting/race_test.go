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
