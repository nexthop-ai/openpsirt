package queue_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// held is how long these take a lease for. Long against the length of a test,
// so nothing lapses because a server was slow.
const held = time.Hour

func TestOnlyOneReplicaTakesALease(t *testing.T) {
	// The lease is what makes a pass running on every replica happen on one.
	// The currency refresher is the case: the politeness it is built around is
	// a rate per deployment, so three replicas each keeping to it would be
	// three times the traffic at somebody else's free service.
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, _ *queue.Queue) {
		ctx := t.Context()
		leases := queue.NewLeases(db.DB)

		const replicas = 6
		var mu sync.Mutex
		var holders []string
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range replicas {
			wg.Add(1)
			go func() {
				defer wg.Done()
				who := fmt.Sprintf("replica-%d", i)
				<-start
				mine, err := leases.Take(ctx, "asking", who, held)
				if err != nil {
					t.Errorf("%s: %v", who, err)
					return
				}
				if mine {
					mu.Lock()
					holders = append(holders, who)
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()

		if len(holders) != 1 {
			t.Errorf("%d of %d replicas took the lease (%v), want exactly one",
				len(holders), replicas, holders)
		}
	})
}

func TestTheHolderKeepsALeaseByAskingAgain(t *testing.T) {
	// A pass that runs on a timer renews by asking each cycle rather than by
	// doing anything else, so there is one thing to get right instead of two.
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, _ *queue.Queue) {
		ctx := t.Context()
		leases := queue.NewLeases(db.DB)
		moment := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
		queue.SetLeaseClock(leases, func() time.Time { return moment })

		if mine, err := leases.Take(ctx, "asking", "first", time.Minute); err != nil || !mine {
			t.Fatalf("first take: %v %v", mine, err)
		}
		// Well past the length of the first hold, asking again each time.
		for range 5 {
			moment = moment.Add(30 * time.Second)
			if mine, err := leases.Take(ctx, "asking", "first", time.Minute); err != nil || !mine {
				t.Fatalf("renewing at %s: %v %v", moment, mine, err)
			}
			if mine, err := leases.Take(ctx, "asking", "second", time.Minute); err != nil || mine {
				t.Fatalf("another replica took a lease that is still held: %v %v", mine, err)
			}
		}

		// And it lapses once the holder stops asking, so a replica that died
		// does not stop the work happening at all.
		moment = moment.Add(2 * time.Minute)
		if mine, err := leases.Take(ctx, "asking", "second", time.Minute); err != nil || !mine {
			t.Errorf("a lapsed lease was never taken up: %v %v", mine, err)
		}
	})
}

func TestOnlyTheHolderHandsALeaseBack(t *testing.T) {
	// A replica whose lease has lapsed and been taken by another is still
	// running, and handing back then would give away what somebody else holds.
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, _ *queue.Queue) {
		ctx := t.Context()
		leases := queue.NewLeases(db.DB)
		if mine, err := leases.Take(ctx, "asking", "holder", held); err != nil || !mine {
			t.Fatalf("take: %v %v", mine, err)
		}
		if err := leases.Release(ctx, "asking", "somebody-else"); err != nil {
			t.Fatalf("release by another: %v", err)
		}
		if mine, err := leases.Take(ctx, "asking", "opportunist", held); err != nil || mine {
			t.Errorf("a lease was handed away by somebody who did not hold it: %v %v", mine, err)
		}

		// The holder hands it back, and then anybody may have it.
		if err := leases.Release(ctx, "asking", "holder"); err != nil {
			t.Fatal(err)
		}
		if mine, err := leases.Take(ctx, "asking", "next", held); err != nil || !mine {
			t.Errorf("a lease handed back was not free: %v %v", mine, err)
		}
	})
}

func TestWaitingForALeaseTakesItWhenItIsHandedBack(t *testing.T) {
	// For work that has to happen rather than work that may be skipped. A
	// policy somebody just changed has to be applied, so the replica that
	// loses the race applies it afterwards — which is also what makes the last
	// rewrite the one holding the newest policy.
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, _ *queue.Queue) {
		ctx := t.Context()
		leases := queue.NewLeases(db.DB)
		if mine, err := leases.Take(ctx, "rewriting", "first", held); err != nil || !mine {
			t.Fatalf("take: %v %v", mine, err)
		}

		waited := make(chan error, 1)
		go func() {
			waited <- leases.Await(ctx, "rewriting", "second", held, 5*time.Millisecond)
		}()
		select {
		case err := <-waited:
			t.Fatalf("waiting returned %v while the lease was still held", err)
		case <-time.After(50 * time.Millisecond):
		}

		if err := leases.Release(ctx, "rewriting", "first"); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-waited:
			if err != nil {
				t.Errorf("waiting for a lease that was handed back: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("a lease handed back was never taken by the replica waiting for it")
		}
	})
}

func TestWaitingForALeaseGivesUpWhenItsTimeIsUp(t *testing.T) {
	// A rewrite that never gets a turn has to stop rather than sit there for
	// the life of the process. It is reported, because a turn that never came
	// means a policy that was never applied.
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, _ *queue.Queue) {
		leases := queue.NewLeases(db.DB)
		if mine, err := leases.Take(t.Context(), "rewriting", "first", held); err != nil || !mine {
			t.Fatalf("take: %v %v", mine, err)
		}
		ctx, stop := contextWithin(t, 100*time.Millisecond)
		defer stop()
		if err := leases.Await(ctx, "rewriting", "second", held, 5*time.Millisecond); err == nil {
			t.Error("waiting for a lease nobody let go reported success")
		}
	})
}

// contextWithin bounds a wait, so a test that expects one to give up does not
// wait for the whole run.
func contextWithin(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(t.Context(), d)
}
