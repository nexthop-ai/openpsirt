// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/issuedate"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
)

// checkOn runs the check of the first inventory through this handle.
func checkOn(t *testing.T, f *checkFixture, handle *bun.DB) *scanner.Checking {
	t.Helper()
	if _, err := f.queue.Add(t.Context(), queue.Check, strconv.FormatInt(f.old, 10)); err != nil {
		t.Fatal(err)
	}
	hooked := *f.db
	hooked.DB = handle
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0011", libnl)}}
	checking, err := scanner.NewRunner(&hooked, f.queue, s, quiet, "test").Check(t.Context())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if checking == nil {
		t.Fatal("nothing was checked")
	}
	return checking
}

// datePass dates every due issue at this moment, on the handle given.
func datePass(ctx context.Context, f *checkFixture, published time.Time) error {
	p := issuedate.NewPass(f.db.DB, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	p.Asker, p.Pause = osvSays{published}, 0
	_, err := p.Once(ctx)
	return err
}

// afterDating runs a rival to its end once the check, holding its build, has
// read the issues' dates, before its next statement.
type afterDating struct {
	rival  func() error
	mu     sync.Mutex
	armed  bool
	fired  bool
	landed error
}

func (h *afterDating) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context { return ctx }

func (h *afterDating) AfterQuery(_ context.Context, e *bun.QueryEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if strings.Contains(e.Query, `"last_run_id" = "last_run_id"`) {
		h.armed = true
		return
	}
	if h.armed && !h.fired && strings.Contains(e.Query, `"dates_asked_at"`) {
		h.fired = true
		h.landed = h.rival()
	}
}

func TestADateLandingWhileACheckReadsIsSeenByTheCheck(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f := undatedBefore(t, w, "CVE-2026-0011")
		if f.db.Stats().MaxOpenConnections == 1 {
			t.Skip("one connection: nothing lands between the check's read and its write")
		}
		when := f.arrived.Add(36 * time.Hour)
		// The date pass commits after the check read the issue as undated.
		hook := &afterDating{rival: func() error { return datePass(context.Background(), f, when) }}
		checkOn(t, f, f.db.WithQueryHook(hook))
		if !hook.fired {
			t.Fatal("the date pass never ran between the check's read and its write")
		}
		if hook.landed != nil {
			t.Fatal(hook.landed)
		}
		got, marked := matchOf(t, f)
		switch {
		case marked:
			t.Error("the match is marked, though the issue was dated before the check wrote it")
		case !got.OpenedAt.Equal(when):
			t.Errorf("opened at %s, want the publication at %s", got.OpenedAt, when)
		}
	})
}

// afterTaking starts a rival once a statement taking the issues' rows has
// run, and holds the check until the rival waits on the lock or lands.
type afterTaking struct {
	db    *database.DB
	rival func() error
	once  sync.Once
	done  chan error
}

func (h *afterTaking) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context { return ctx }

func (h *afterTaking) AfterQuery(ctx context.Context, e *bun.QueryEvent) {
	if !strings.Contains(e.Query, `"published_at" = "published_at"`) {
		return
	}
	h.once.Do(func() {
		landed := make(chan struct{})
		go func() {
			h.done <- h.rival()
			close(landed)
		}()
		dbtest.UntilLockWait(ctx, h.db, landed, 5*time.Second)
	})
}

func TestADatePassWaitingOnACheckRewritesWhatTheCheckWrote(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f := undatedBefore(t, w, "CVE-2026-0011")
		if f.db.Stats().MaxOpenConnections == 1 {
			t.Skip("one connection: the date pass cannot wait on the check")
		}
		when := f.arrived.Add(36 * time.Hour)
		// The date pass starts once the check has taken the issue, and runs
		// to its end only after the check commits.
		hook := &afterTaking{db: f.db, done: make(chan error, 1),
			rival: func() error { return datePass(context.Background(), f, when) }}
		checkOn(t, f, f.db.WithQueryHook(hook))
		select {
		case err := <-hook.done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the date pass never finished")
		}
		got, marked := matchOf(t, f)
		switch {
		case marked:
			t.Error("the match is still marked after the date pass")
		case !got.OpenedAt.Equal(when):
			t.Errorf("opened at %s, want the publication at %s", got.OpenedAt, when)
		}
	})
}
