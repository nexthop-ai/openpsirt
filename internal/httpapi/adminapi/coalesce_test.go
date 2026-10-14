// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"sync"
	"testing"
	"time"
)

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
	run := func(_ context.Context, what, _ string) {
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
	}
	r := new(rewriter)
	ask := func(ctx context.Context, what, value string) { r.ask(ctx, what, value, run) }
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
