// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// rewritingWith puts run in place of the rewrite for the length of the test,
// and answers what a handler is handed to ask for one. The database is a key
// the runs are coalesced under and nothing reads it.
func rewritingWith(t *testing.T, run func(ctx context.Context, what string)) (func(context.Context, string, string), *database.DB) {
	t.Helper()
	ordinary := rewrite
	rewrite = func(ctx context.Context, _ *database.DB, _ string, _ *slog.Logger, what, _ string) {
		run(ctx, what)
	}
	t.Cleanup(func() { rewrite = ordinary })
	key := new(database.DB)
	return deadlinesRewritten(core.Deps{DB: key}), key
}

// A burst of policy changes is one rewrite in progress and one more, never one
// each, and never two at once. The rewrite reads the policy once its turn
// comes, so the run after the last change applies every change before it.
func TestABurstOfPolicyChangesIsRewrittenOnceMoreAfterTheRunningOne(t *testing.T) {
	var (
		mu      sync.Mutex
		runs    []string
		running int
		overlap bool
	)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	finished := make(chan struct{}, 10)
	ask, _ := rewritingWith(t, func(_ context.Context, what string) {
		mu.Lock()
		running++
		overlap = overlap || running > 1
		runs = append(runs, what)
		first := len(runs) == 1
		mu.Unlock()
		if first {
			started <- struct{}{}
			<-release
		}
		mu.Lock()
		running--
		mu.Unlock()
		finished <- struct{}{}
	})
	ask(t.Context(), "first", "1")
	<-started
	for _, what := range []string{"second", "third", "fourth"} {
		ask(t.Context(), what, "1")
	}
	close(release)
	for range 2 {
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatal("the rewrites did not finish")
		}
	}
	// Nothing else is coming: a third run would have started by now.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != 2 || runs[1] != "fourth" || overlap {
		t.Errorf("a burst of four changes ran %v, overlapping %v; want the running one and one "+
			"more naming the last change, one at a time", runs, overlap)
	}
}

// Stopping ends the rewrite in progress and waits for it, and a change asked
// for afterwards starts nothing. A process shutting down relies on both: the
// run hands its lease back on the way out, and no run starts that nothing
// waits for.
func TestStoppingEndsTheRunningRewriteAndStartsNoOther(t *testing.T) {
	started := make(chan struct{})
	var (
		mu    sync.Mutex
		runs  int
		ended bool
	)
	ask, key := rewritingWith(t, func(ctx context.Context, _ string) {
		mu.Lock()
		runs++
		mu.Unlock()
		close(started)
		<-ctx.Done()
		mu.Lock()
		ended = true
		mu.Unlock()
	})
	ask(t.Context(), "first", "1")
	<-started
	stopping, give := context.WithTimeout(t.Context(), 10*time.Second)
	defer give()
	// This database's rewriter alone, which is what StopRewrites does to
	// each: the others belong to tests running beside this one.
	rewriterFor(key).stop(stopping)
	if stopping.Err() != nil {
		t.Fatal("stopping waited out its bound: the running rewrite was not ended")
	}
	mu.Lock()
	if !ended {
		t.Error("stopping returned before the running rewrite had finished")
	}
	mu.Unlock()
	ask(t.Context(), "after", "1")
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if runs != 1 {
		t.Errorf("a change asked for after stopping started a rewrite: %d runs, want 1", runs)
	}
}
