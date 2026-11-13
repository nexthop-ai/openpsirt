// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// waitingRewrites is how many deadline rewrites are queued and not yet claimed.
func waitingRewrites(t *testing.T, f *fixture) int {
	t.Helper()
	n, err := f.db.DB.NewSelect().Table("job").
		Where(`"kind" = ?`, queue.Deadlines).Where(`"state" = ?`, queue.Pending).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

// queueRewrite queues a deadline rewrite the way a policy change does, in a
// transaction of its own.
func queueRewrite(t *testing.T, f *fixture, work *queue.Queue) {
	t.Helper()
	if err := database.Within(t.Context(), f.db.DB, func(ctx context.Context, tx bun.IDB) error {
		return finding.RewriteDeadlines(ctx, tx, work)
	}); err != nil {
		t.Fatal(err)
	}
}

// A burst of policy changes is one waiting rewrite: one not yet started reads
// the policy once its turn comes, so it takes every change queued behind it.
// A rewrite already claimed may have read the policy before, so a change after
// it queues another.
func TestABurstOfPolicyChangesIsOneWaitingRewrite(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		work := queue.New(f.db, queue.DefaultOptions())
		for range 3 {
			queueRewrite(t, f, work)
		}
		if n := waitingRewrites(t, f); n != 1 {
			t.Fatalf("three policy changes left %d rewrites waiting, want one", n)
		}
		job, err := work.Claim(t.Context(), "elsewhere", queue.Deadlines)
		if err != nil || job == nil {
			t.Fatalf("the waiting rewrite could not be claimed: %v", err)
		}
		queueRewrite(t, f, work)
		if n := waitingRewrites(t, f); n != 1 {
			t.Errorf("a change after the rewrite started left %d waiting, want one more", n)
		}
	})
}

// A rewrite waiting to be tried again does not take a later change: it may be
// on its last attempt, and it waits out its backoff first.
func TestARewriteWaitingToBeTriedAgainTakesNoLaterChange(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		work := queue.New(f.db, queue.DefaultOptions())
		queueRewrite(t, f, work)
		job, err := work.Claim(ctx, "elsewhere", queue.Deadlines)
		if err != nil || job == nil {
			t.Fatalf("the waiting rewrite could not be claimed: %v", err)
		}
		if err := work.Fail(ctx, job.ID, "elsewhere", errors.New("interrupted")); err != nil {
			t.Fatal(err)
		}
		if n := waitingRewrites(t, f); n != 1 {
			t.Fatalf("a failed rewrite left %d waiting, want it waiting to be tried again", n)
		}
		queueRewrite(t, f, work)
		if n := waitingRewrites(t, f); n != 2 {
			t.Errorf("a change after a rewrite failed left %d waiting, want one more", n)
		}
	})
}

// A policy change taken by a waiting rewrite holds that rewrite until it
// commits, so a claim made meanwhile either waits or passes it by: claimed
// before the commit, it would read the old policy with nothing queued after.
func TestAWaitingRewriteIsNotClaimedBeforeThePolicyChangeItTookCommits(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		work := queue.New(f.db, queue.DefaultOptions())
		queueRewrite(t, f, work)

		tx, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := finding.RewriteDeadlines(ctx, tx, work); err != nil {
			t.Fatal(err)
		}
		type claim struct {
			job *queue.Job
			err error
		}
		answers := make(chan claim, 1)
		go func() {
			job, err := work.Claim(ctx, "elsewhere", queue.Deadlines)
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
		var early *queue.Job
		answered := false
		select {
		case c := <-answers:
			early = took(c)
			answered = true
			if early != nil {
				t.Fatal("the waiting rewrite was claimed before the change it took had committed")
			}
		case <-time.After(500 * time.Millisecond):
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if !answered {
			select {
			case c := <-answers:
				early = took(c)
			case <-time.After(30 * time.Second):
				t.Fatal("the claim did not go on once the change committed")
			}
		}
		if early == nil {
			if early, err = work.Claim(ctx, "elsewhere", queue.Deadlines); err != nil {
				t.Fatal(err)
			}
		}
		if early == nil {
			t.Error("the waiting rewrite was not claimable once the change committed")
		}
	})
}

// A queued rewrite applies the policy in force when it runs, read after its
// turn is taken, and nothing is left waiting once it has.
func TestAQueuedRewriteAppliesThePolicyInForceWhenItRuns(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		run := f.run(t)
		seen := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond)
		f.seenAt(t, run, seen)
		high := found("CVE-2026-HIGH", swss)
		high.Issue.Severity = "high"
		if _, err := f.store.Apply(ctx, f.build, run, []finding.Reported{high}); err != nil {
			t.Fatal(err)
		}

		work := queue.New(f.db, queue.DefaultOptions())
		queueRewrite(t, f, work)
		// Changed after the rewrite was queued, as a second change arriving
		// while it waits.
		if _, _, err := setting.NewStore(f.db.DB).Change(ctx, setting.DueHigh, "360h"); err != nil {
			t.Fatal(err)
		}

		claimed, rewritten, err := finding.NewRewriter(f.db, work,
			slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !claimed || rewritten == 0 {
			t.Fatalf("the queued rewrite claimed=%v and rewrote %d findings", claimed, rewritten)
		}
		if got, want := f.deadline(t, "CVE-2026-HIGH"), seen.Add(15*24*time.Hour); got.Sub(want).Abs() > time.Second {
			t.Errorf("the deadline is %s after the rewrite, want the first sighting plus fifteen days, %s", got, want)
		}
		if n := waitingRewrites(t, f); n != 0 {
			t.Errorf("%d rewrites are still waiting after the one queued ran", n)
		}
	})
}
