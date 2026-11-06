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
	return checkOnName(t, f, handle, "CVE-2026-0011")
}

// checkOnName is checkOn with the scanner reporting the issue under this name.
func checkOnName(t *testing.T, f *checkFixture, handle *bun.DB, name string) *scanner.Checking {
	t.Helper()
	if _, err := f.queue.Add(t.Context(), queue.Check, strconv.FormatInt(f.old, 10)); err != nil {
		t.Fatal(err)
	}
	hooked := *f.db
	hooked.DB = handle
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt(name, libnl)}}
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

// takes reports whether a statement takes a row of this table, in either
// quoting style the engines use.
func takes(query, table string) bool {
	q := strings.ReplaceAll(query, "`", `"`)
	return strings.HasPrefix(q, `UPDATE "`+table+`"`) && strings.Contains(q, `"taken_by"`)
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
	if takes(e.Query, "build") {
		h.armed = true
		return
	}
	if h.armed && !h.fired && strings.Contains(strings.ReplaceAll(e.Query, "`", `"`), `"dates_asked_at"`) {
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
	if !takes(e.Query, "vulnerability") {
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

func TestAnIssueMergedAwayWhileACheckReadsIsReadAsTheIssueKept(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f := undatedBefore(t, w, "GHSA-AAAA-BBBB-CCCC")
		if f.db.Stats().MaxOpenConnections == 1 {
			t.Skip("one connection: nothing lands between the check's read and its write")
		}
		when := f.arrived.Add(36 * time.Hour)
		f.published(t, "CVE-2026-0099", when)
		// A report merges the undated issue into a dated one after the check
		// read it as undated.
		hook := &afterDating{rival: func() error {
			_, err := finding.NewVulnerabilities(f.db.DB).Intern(context.Background(), []finding.Named{{
				Identifier: "CVE-2026-0099", Aliases: []string{"GHSA-AAAA-BBBB-CCCC"}, Severity: "high"}})
			return err
		}}
		checkOnName(t, f, f.db.WithQueryHook(hook), "GHSA-AAAA-BBBB-CCCC")
		if !hook.fired {
			t.Fatal("the merge never ran between the check's read and its write")
		}
		if hook.landed != nil {
			t.Fatal(hook.landed)
		}
		if name := issueOfMatch(t, f); name != "CVE-2026-0099" {
			t.Fatalf("the match is read as %s, want the issue kept", name)
		}
		if got, _ := matchOf(t, f); !got.OpenedAt.Equal(when) {
			t.Errorf("opened at %s, want the kept issue's publication at %s", got.OpenedAt, when)
		}
	})
}

// takenBy is the value last written to take this row.
func takenBy(t *testing.T, f *checkFixture, table string, where string, arg any) string {
	t.Helper()
	var by *string
	if err := f.db.NewSelect().Table(table).Column("taken_by").Where(where, arg).
		Scan(t.Context(), &by); err != nil {
		t.Fatal(err)
	}
	if by == nil {
		return ""
	}
	return *by
}

// A take writing the value a row already holds is skipped on MySQL and
// MariaDB, and a cluster never certifies it, so a check and a scan or a date
// pass on two nodes would not conflict.
func TestEveryCheckTakesItsBuildAndUndatedIssuesWithAFreshValue(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		f := undatedBefore(t, w, "CVE-2026-0011")
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0011", libnl)}}
		seen := map[string][]string{}
		for range 2 {
			if checking := f.check(t, s); checking == nil {
				t.Fatal("nothing was checked")
			}
			seen["build"] = append(seen["build"], takenBy(t, f, "build", `"id" = ?`, f.build))
			seen["issue"] = append(seen["issue"], takenBy(t, f, "vulnerability", `"identifier" = ?`, "CVE-2026-0011"))
		}
		for row, values := range seen {
			if values[0] == "" || values[0] == values[1] {
				t.Errorf("the %s was taken with %q then %q, want a fresh value each time", row, values[0], values[1])
			}
		}
	})
}
