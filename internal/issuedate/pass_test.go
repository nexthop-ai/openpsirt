// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package issuedate_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/issuedate"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// osv answers what a test tells it to, so nothing reaches the network.
type osv struct {
	mu    sync.Mutex
	says  map[string]issuedate.Dates
	fails map[string]bool
	asked []string
}

func (o *osv) Dates(_ context.Context, name string) (issuedate.Dates, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.asked = append(o.asked, name)
	if o.fails[name] {
		return issuedate.Dates{}, issuedate.ErrNotAnswering
	}
	dates, known := o.says[name]
	if !known {
		return issuedate.Dates{}, issuedate.ErrUnknown
	}
	return dates, nil
}

var (
	published = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	modified  = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
)

// held is what the table holds about one issue's dates.
type held struct {
	Published *time.Time `bun:"published_at"`
	Modified  *time.Time `bun:"modified_at"`
	Asked     *time.Time `bun:"dates_asked_at"`
}

func datesOf(t *testing.T, db *database.DB, identifier string) held {
	t.Helper()
	var out held
	if err := db.DB.NewSelect().TableExpr(`"vulnerability" AS "v"`).
		ColumnExpr(`"v"."published_at", "v"."modified_at", "v"."dates_asked_at"`).
		Where(`"v"."identifier" = ?`, identifier).Scan(t.Context(), &out); err != nil {
		t.Fatalf("read the dates of %s: %v", identifier, err)
	}
	return out
}

func newPass(db *database.DB, asker issuedate.Asker, now *time.Time) *issuedate.Pass {
	p := issuedate.NewPass(db.DB, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	p.Asker, p.Pause = asker, 0
	p.Now = func() time.Time { return *now }
	return p
}

// An issue OSV knows takes both dates, by an alias where OSV does not know its
// own name; one OSV does not know is recorded as asked with no date, and is
// asked again daily while fresh and monthly after, while a known one waits a
// month.
func TestIssueDatesAreAskedOnceAndAgainWhenStale(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-0001"},
			{Identifier: "CVE-2026-0002", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}},
			{Identifier: "CVE-2026-0003"},
		}); err != nil {
			t.Fatal(err)
		}
		answers := &osv{says: map[string]issuedate.Dates{
			"CVE-2026-0001":       {Published: published, Modified: modified},
			"GHSA-AAAA-BBBB-CCCC": {Published: published},
		}}
		pass := newPass(db, answers, &now)
		asked, err := pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if asked != 3 {
			t.Fatalf("answered %d issues, want 3", asked)
		}
		one := datesOf(t, db, "CVE-2026-0001")
		if one.Published == nil || !one.Published.Equal(published) || one.Modified == nil || !one.Modified.Equal(modified) {
			t.Errorf("a known issue holds %+v, want both dates", one)
		}
		if two := datesOf(t, db, "CVE-2026-0002"); two.Published == nil || !two.Published.Equal(published) {
			t.Errorf("an issue known by its alias holds %+v, want its published date; asked %v", two, answers.asked)
		}
		three := datesOf(t, db, "CVE-2026-0003")
		if three.Published != nil || three.Asked == nil {
			t.Errorf("an unknown issue holds %+v, want asked with no date", three)
		}

		answers.asked = nil
		if asked, err := pass.Once(ctx); err != nil || asked != 0 {
			t.Fatalf("a second pass at once answered %d (%v), want none due", asked, err)
		}
		now = now.Add(25 * time.Hour)
		if asked, err := pass.Once(ctx); err != nil || asked != 1 {
			t.Fatalf("a day later answered %d (%v), want the fresh unknown issue alone", asked, err)
		}
		now = now.Add(20 * 24 * time.Hour)
		answers.asked = nil
		if asked, err := pass.Once(ctx); err != nil || asked != 0 {
			t.Fatalf("past the fortnight a day after asking answered %d (%v), want none: %v", asked, err, answers.asked)
		}
		now = now.Add(11 * 24 * time.Hour)
		if asked, err := pass.Once(ctx); err != nil || asked != 3 {
			t.Fatalf("a month on answered %d (%v), want all three", asked, err)
		}
	})
}

// OSV not answering leaves the issue unasked and ends the pass; turned off,
// the pass asks nothing.
func TestIssueDatesStayDueWhenOSVDoesNotAnswerOrIsTurnedOff(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-0010"}, {Identifier: "CVE-2026-0011"},
		}); err != nil {
			t.Fatal(err)
		}
		answers := &osv{fails: map[string]bool{"CVE-2026-0010": true, "CVE-2026-0011": true}}
		pass := newPass(db, answers, &now)
		if asked, err := pass.Once(ctx); err != nil || asked != 0 {
			t.Fatalf("an unwell OSV answered %d (%v), want none", asked, err)
		}
		if len(answers.asked) != 1 {
			t.Errorf("asked %v, want the pass to stop at the first failure", answers.asked)
		}
		if got := datesOf(t, db, "CVE-2026-0010"); got.Asked != nil {
			t.Errorf("an issue OSV did not answer about is recorded as asked: %+v", got)
		}

		if _, _, err := setting.NewStore(db.DB).Change(ctx, setting.IssueDates, setting.Off); err != nil {
			t.Fatal(err)
		}
		answers.fails, answers.asked = nil, nil
		if asked, err := pass.Once(ctx); err != nil || asked != 0 || len(answers.asked) != 0 {
			t.Fatalf("turned off, the pass answered %d and asked %v (%v), want nothing", asked, answers.asked, err)
		}
	})
}
