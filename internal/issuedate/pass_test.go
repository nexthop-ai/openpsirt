// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package issuedate_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/issuedate"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// osv answers what a test tells it to, so nothing reaches the network.
type osv struct {
	mu        sync.Mutex
	says      map[string]issuedate.Dates
	fails     map[string]bool
	unaskable map[string]bool
	// aliases is the records OSV names for a name it holds only as their
	// alias.
	aliases map[string][]string
	asked   []string
}

func (o *osv) Dates(_ context.Context, name string) (issuedate.Dates, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.asked = append(o.asked, name)
	if o.fails[name] {
		return issuedate.Dates{}, issuedate.ErrNotAnswering
	}
	if o.unaskable[name] {
		return issuedate.Dates{}, issuedate.ErrUnaskable
	}
	if named, ok := o.aliases[name]; ok {
		return issuedate.Dates{}, &issuedate.Aliased{Names: named}
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

func newPass(db *database.DB, asker issuedate.Asker, clock *dbtest.Clock) *issuedate.Pass {
	p := issuedate.NewPass(db.DB, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	p.Asker, p.Pause, p.Now = asker, 0, clock.Now
	return p
}

// An issue OSV knows takes both dates, by an alias where OSV does not know its
// own name; one OSV does not know is recorded as asked with no date, and is
// asked again daily while fresh and monthly after, while a known one waits a
// month.
func TestIssueDatesAreAskedOnceAndAgainWhenStale(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		// Intern stamps first_seen_at from the real clock, and an unknown
		// issue's freshness is measured from it.
		clock := dbtest.NewClock()
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
		pass := newPass(db, answers, clock)
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
		clock.Advance(25 * time.Hour)
		if asked, err := pass.Once(ctx); err != nil || asked != 1 {
			t.Fatalf("a day later answered %d (%v), want the fresh unknown issue alone", asked, err)
		}
		clock.Advance(20 * 24 * time.Hour)
		answers.asked = nil
		if asked, err := pass.Once(ctx); err != nil || asked != 0 {
			t.Fatalf("past the fortnight a day after asking answered %d (%v), want none: %v", asked, err, answers.asked)
		}
		clock.Advance(11 * 24 * time.Hour)
		// OSV no longer serves the first: the dates it gave are kept.
		answers.mu.Lock()
		delete(answers.says, "CVE-2026-0001")
		answers.mu.Unlock()
		if asked, err := pass.Once(ctx); err != nil || asked != 3 {
			t.Fatalf("a month on answered %d (%v), want all three", asked, err)
		}
		if kept := datesOf(t, db, "CVE-2026-0001"); kept.Published == nil || !kept.Published.Equal(published) {
			t.Errorf("an issue OSV stopped serving holds %+v, want the dates it gave kept", kept)
		}
	})
}

// A name OSV holds only as another record's alias is answered by that record:
// curl publishes CVE-2026-86409 as CURL-CVE-2026-86409, and OSV answers the CVE
// with the curl name and no record.
func TestAnIssueOSVHoldsAsAnAliasTakesThatRecordsDates(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		clock := dbtest.NewClock()
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-86409"},
		}); err != nil {
			t.Fatal(err)
		}
		answers := &osv{
			aliases: map[string][]string{"CVE-2026-86409": {"CURL-CVE-2026-86409"}},
			says:    map[string]issuedate.Dates{"CURL-CVE-2026-86409": {Published: published, Modified: modified}},
		}
		if asked, err := newPass(db, answers, clock).Once(ctx); err != nil || asked != 1 {
			t.Fatalf("answered %d (%v), want the one issue", asked, err)
		}
		got := datesOf(t, db, "CVE-2026-86409")
		if got.Published == nil || !got.Published.Equal(published) || got.Modified == nil || !got.Modified.Equal(modified) {
			t.Errorf("an issue OSV holds as an alias holds %+v, want the dates of the record it names; asked %v",
				got, answers.asked)
		}
	})
}

// A record reached through an alias is not followed further, and no name is
// asked twice for one issue, so aliases naming each other end; the requests
// for one issue are bounded however many names answers send it to.
func TestFollowingAliasesEnds(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		clock := dbtest.NewClock()
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-0050"},
			{Identifier: "CVE-2026-0051", Aliases: []string{
				"GHSA-aaaa-aaaa-aaa1", "GHSA-aaaa-aaaa-aaa2", "GHSA-aaaa-aaaa-aaa3", "GHSA-aaaa-aaaa-aaa4",
			}},
			{Identifier: "CVE-2026-0052", Aliases: []string{"GHSA-bbbb-bbbb-bbbb"}},
		}); err != nil {
			t.Fatal(err)
		}
		answers := &osv{aliases: map[string][]string{
			// A names B; B names A, itself, and a record that would answer.
			"CVE-2026-0050": {"LOOP-B"},
			"LOOP-B":        {"CVE-2026-0050", "LOOP-B", "LOOP-KNOWN"},
			// Every name sends the pass to three more.
			"CVE-2026-0051":       {"FAN-1", "FAN-2", "FAN-3"},
			"GHSA-AAAA-AAAA-AAA1": {"FAN-4", "FAN-5", "FAN-6"},
			"GHSA-AAAA-AAAA-AAA2": {"FAN-7", "FAN-8", "FAN-9"},
			// An answer naming one of the issue's own names.
			"CVE-2026-0052": {"GHSA-BBBB-BBBB-BBBB"},
		}, says: map[string]issuedate.Dates{"LOOP-KNOWN": {Published: published}}}
		if asked, err := newPass(db, answers, clock).Once(ctx); err != nil || asked != 3 {
			t.Fatalf("answered %d (%v), want all three issues", asked, err)
		}
		if got := datesOf(t, db, "CVE-2026-0050"); got.Published != nil || got.Asked == nil {
			t.Errorf("an issue whose aliases name each other holds %+v, want asked with no date", got)
		}
		perIssue := map[string]int{}
		for _, name := range answers.asked {
			switch {
			case strings.HasPrefix(name, "LOOP-"), name == "CVE-2026-0050":
				perIssue["loop"]++
			case strings.HasSuffix(name, "0052"), strings.HasPrefix(name, "GHSA-BBBB"):
				perIssue["own"]++
			default:
				perIssue["fan"]++
			}
		}
		if perIssue["loop"] != 2 {
			t.Errorf("the looping issue was asked %d times, want its name and the one record it names: %v",
				perIssue["loop"], answers.asked)
		}
		if perIssue["fan"] != 8 {
			t.Errorf("the fanning issue was asked %d times, want eight, its five names and three followed: %v",
				perIssue["fan"], answers.asked)
		}
		if perIssue["own"] != 2 {
			t.Errorf("an issue whose answer names its own other name was asked %d times, want each name once: %v",
				perIssue["own"], answers.asked)
		}
	})
}

// OSV not answering leaves the issue unasked and ends the pass; turned off,
// the pass asks nothing.
func TestIssueDatesStayDueWhenOSVDoesNotAnswerOrIsTurnedOff(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		clock := dbtest.NewClock()
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-0010"}, {Identifier: "CVE-2026-0011"},
		}); err != nil {
			t.Fatal(err)
		}
		answers := &osv{fails: map[string]bool{"CVE-2026-0010": true, "CVE-2026-0011": true}}
		pass := newPass(db, answers, clock)
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

// A name OSV will not answer about is passed over like one it does not know:
// the issue is asked by its other names, and the pass goes on to the next.
func TestANameOSVWillNotAnswerAboutIsPassedOver(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		clock := dbtest.NewClock()
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-0020", Aliases: []string{"GHSA-dddd-eeee-ffff"}},
			{Identifier: "CVE-2026-0021"},
		}); err != nil {
			t.Fatal(err)
		}
		answers := &osv{
			unaskable: map[string]bool{"CVE-2026-0020": true},
			says: map[string]issuedate.Dates{
				"GHSA-DDDD-EEEE-FFFF": {Published: published},
				"CVE-2026-0021":       {Published: published},
			},
		}
		if asked, err := newPass(db, answers, clock).Once(ctx); err != nil || asked != 2 {
			t.Fatalf("answered %d (%v), want both issues; asked %v", asked, err, answers.asked)
		}
		for _, identifier := range []string{"CVE-2026-0020", "CVE-2026-0021"} {
			if got := datesOf(t, db, identifier); got.Published == nil || !got.Published.Equal(published) {
				t.Errorf("%s holds %+v, want its published date", identifier, got)
			}
		}
	})
}

// A pass asks for its lease again as it goes, and stops where another replica
// has taken it.
func TestAPassStopsWhereItsLeaseIsTaken(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		clock := dbtest.NewClock()
		var named []finding.Named
		for i := range queue.RenewEvery + 5 {
			named = append(named, finding.Named{Identifier: fmt.Sprintf("CVE-2026-%04d", 100+i)})
		}
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, named); err != nil {
			t.Fatal(err)
		}
		if mine, err := queue.NewLeases(db.DB).Take(ctx, issuedate.Lease, "other", time.Hour); err != nil || !mine {
			t.Fatalf("the other replica could not take the lease: %v (%v)", mine, err)
		}
		answers := &osv{}
		if asked, err := newPass(db, answers, clock).Once(ctx); err != nil || asked != queue.RenewEvery {
			t.Errorf("answered %d (%v), want the %d asked before the lease was asked for again",
				asked, err, queue.RenewEvery)
		}
	})
}

// A pass waits between one request and the next, so OSV is asked at a pace
// it is willing to answer.
func TestAPassWaitsBetweenRequests(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		clock := dbtest.NewClock()
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-0030", Aliases: []string{"GHSA-gggg-hhhh-jjjj"}},
		}); err != nil {
			t.Fatal(err)
		}
		pass := newPass(db, &osv{says: map[string]issuedate.Dates{"GHSA-GGGG-HHHH-JJJJ": {Published: published}}}, clock)
		pass.Pause = 50 * time.Millisecond
		started := time.Now()
		if asked, err := pass.Once(ctx); err != nil || asked != 1 {
			t.Fatalf("answered %d (%v), want the one issue", asked, err)
		}
		// One wait before the second name and one after its answer.
		if took := time.Since(started); took < 2*pass.Pause {
			t.Errorf("two requests took %s, want at least two pauses of %s", took, pass.Pause)
		}
	})
}

// running runs a pass on a short interval until the test ends.
func running(t *testing.T, pass *issuedate.Pass) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		pass.Run(ctx, time.Millisecond)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// anything reports whether OSV has been asked anything.
func (o *osv) anything() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.asked) > 0
}

// waitFor waits for a condition, failing the test after ten seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A running pass asks nothing while the setting is off or another replica
// holds the lease, and asks once neither stops it, every cycle reading both.
// A pass turned off does not take the lease either, so it leaves the work to
// a replica where it is on.
func TestARunningPassAsksOnlyWhenOnAndHoldingTheLease(t *testing.T) {
	for _, c := range []struct {
		what    string
		stop    func(t *testing.T, db *database.DB)
		release func(t *testing.T, db *database.DB)
	}{
		{"turned off",
			func(t *testing.T, db *database.DB) {
				if _, _, err := setting.NewStore(db.DB).Change(t.Context(), setting.IssueDates, setting.Off); err != nil {
					t.Fatal(err)
				}
			},
			func(t *testing.T, db *database.DB) {
				if _, _, err := setting.NewStore(db.DB).Change(t.Context(), setting.IssueDates, setting.On); err != nil {
					t.Fatal(err)
				}
			}},
		{"leased elsewhere",
			func(t *testing.T, db *database.DB) {
				if mine, err := queue.NewLeases(db.DB).Take(t.Context(), issuedate.Lease, "other", time.Hour); err != nil || !mine {
					t.Fatalf("the other replica could not take the lease: %v (%v)", mine, err)
				}
			},
			func(t *testing.T, db *database.DB) {
				if err := queue.NewLeases(db.DB).Release(t.Context(), issuedate.Lease, "other"); err != nil {
					t.Fatal(err)
				}
			}},
	} {
		t.Run(c.what, func(t *testing.T) {
			dbtest.Two(t, func(t *testing.T, db *database.DB) {
				ctx := t.Context()
				if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
					{Identifier: "CVE-2026-0040"},
				}); err != nil {
					t.Fatal(err)
				}
				c.stop(t, db)
				clock := dbtest.NewClock()
				answers := &osv{says: map[string]issuedate.Dates{"CVE-2026-0040": {Published: published}}}
				running(t, newPass(db, answers, clock))
				// Many cycles of a millisecond each.
				time.Sleep(100 * time.Millisecond)
				if answers.anything() {
					t.Fatalf("a pass %s asked %v", c.what, answers.asked)
				}
				if c.what == "turned off" {
					leases := queue.NewLeases(db.DB)
					if mine, err := leases.Take(ctx, issuedate.Lease, "other", time.Hour); err != nil || !mine {
						t.Fatalf("a pass turned off holds the lease: %v (%v)", mine, err)
					}
					if err := leases.Release(ctx, issuedate.Lease, "other"); err != nil {
						t.Fatal(err)
					}
				}
				c.release(t, db)
				waitFor(t, "the pass asking once nothing stops it", answers.anything)
			})
		})
	}
}
