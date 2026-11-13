// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/upstream"
)

// waitingScans is how many scans of each build are queued and not yet claimed.
func waitingScans(t *testing.T, w *world) map[string]int {
	t.Helper()
	var references []string
	if err := w.DB.DB.NewSelect().Model((*queue.Job)(nil)).Column("reference").
		Where(`"kind" = ?`, queue.Scan).Where(`"state" = ?`, queue.Pending).
		Scan(t.Context(), &references); err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, one := range references {
		out[one]++
	}
	return out
}

// A scan waiting to be tried again does not take a change to what an upstream
// closes: it may be on its last attempt, and it waits out its backoff first.
func TestAScanWaitingToBeTriedAgainTakesNoLaterUpstreamChange(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		ctx := t.Context()
		w := newWorld(t, f)
		work := queue.New(w.DB, queue.DefaultOptions())
		if _, err := w.DB.DB.NewDelete().Model((*queue.Job)(nil)).
			Where(`"kind" = ?`, queue.Scan).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := upstream.Again(ctx, w.DB.DB, work, w.fork.ID); err != nil {
			t.Fatal(err)
		}
		build := fmt.Sprint(w.forkBuild.ID)
		if n := waitingScans(t, w)[build]; n != 1 {
			t.Fatalf("the upstream change left %d scans of the build waiting, want one", n)
		}
		if err := upstream.Again(ctx, w.DB.DB, work, w.fork.ID); err != nil {
			t.Fatal(err)
		}
		if n := waitingScans(t, w)[build]; n != 1 {
			t.Fatalf("a second change left %d scans of the build waiting, want the one taking both", n)
		}
		for {
			job, err := work.Claim(ctx, "elsewhere", queue.Scan)
			if err != nil {
				t.Fatal(err)
			}
			if job == nil {
				break
			}
			if err := work.Fail(ctx, job.ID, "elsewhere", errors.New("interrupted")); err != nil {
				t.Fatal(err)
			}
		}
		if n := waitingScans(t, w)[build]; n != 1 {
			t.Fatalf("a failed scan left %d waiting, want it waiting to be tried again", n)
		}
		if err := upstream.Again(ctx, w.DB.DB, work, w.fork.ID); err != nil {
			t.Fatal(err)
		}
		if n := waitingScans(t, w)[build]; n != 2 {
			t.Errorf("a change after a scan failed left %d waiting, want one more", n)
		}
	})
}

// An upstream change taken by a waiting scan holds that scan until it commits,
// so a claim made meanwhile either waits or passes it by: claimed before the
// commit, it would scan under the old upstream with nothing queued after.
func TestAWaitingScanIsNotClaimedBeforeTheUpstreamChangeItTookCommits(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		ctx := t.Context()
		w := newWorld(t, f)
		work := queue.New(w.DB, queue.DefaultOptions())
		if _, err := w.DB.DB.NewDelete().Model((*queue.Job)(nil)).
			Where(`"kind" = ?`, queue.Scan).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := upstream.Again(ctx, w.DB.DB, work, w.fork.ID); err != nil {
			t.Fatal(err)
		}

		tx, err := w.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := upstream.Again(ctx, tx, work, w.fork.ID); err != nil {
			t.Fatal(err)
		}
		type claim struct {
			job *queue.Job
			err error
		}
		answers := make(chan claim, 1)
		go func() {
			job, err := work.Claim(ctx, "elsewhere", queue.Scan)
			answers <- claim{job, err}
		}()
		took := func(c claim) *queue.Job {
			if c.err != nil {
				t.Fatal(c.err)
			}
			return c.job
		}
		// A server engine passes a held job by and finds nothing; SQLite
		// waits for the writer.
		answered := false
		select {
		case c := <-answers:
			answered = true
			if took(c) != nil {
				t.Fatal("a waiting scan was claimed before the upstream change it took had committed")
			}
		case <-time.After(500 * time.Millisecond):
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if !answered {
			select {
			case c := <-answers:
				took(c)
			case <-time.After(30 * time.Second):
				t.Fatal("the claim did not go on once the change committed")
			}
		}
	})
}
