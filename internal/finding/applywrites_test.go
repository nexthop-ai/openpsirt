// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// matchedStatements records what was sent to the database and what each
// matched, with identifiers in double quotes whichever quote the engine's
// dialect writes them in.
type matchedStatements struct {
	mu   sync.Mutex
	sent []sent
}

type sent struct {
	query   string
	matched int64
}

func (s *matchedStatements) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (s *matchedStatements) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	var matched int64
	if event.Result != nil && event.Err == nil {
		matched, _ = database.Affected(event.Result)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, sent{query: strings.ReplaceAll(event.Query, "`", `"`), matched: matched})
}

// matching is every statement that begins with prefix, and how many rows
// those matchedStatements matched between them.
func (s *matchedStatements) matching(prefix string) (count int, matched int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, each := range s.sent {
		if strings.HasPrefix(each.query, prefix) {
			count++
			matched += each.matched
		}
	}
	return count, matched
}

// written is what an update to an open finding may have written, by issue and
// place, for comparing two builds.
type written struct {
	Identifier       string     `bun:"identifier"`
	PlaceIdentity    string     `bun:"place_identity"`
	Urgency          int64      `bun:"urgency"`
	Exploited        bool       `bun:"urgency_exploited"`
	Shipped          bool       `bun:"urgency_shipped"`
	FixState         string     `bun:"fix_state"`
	FixedIn          string     `bun:"fixed_in"`
	FixedAt          *time.Time `bun:"fixed_at"`
	Matched          string     `bun:"matched"`
	MatchedFrom      string     `bun:"matched_from"`
	MatchedIn        string     `bun:"matched_in"`
	MatchedRange     string     `bun:"matched_range"`
	SuppressedBy     *int64     `bun:"suppressed_by"`
	StatedBy         *int64     `bun:"stated_by"`
	ClaimedBy        *int64     `bun:"claimed_by"`
	LastChangedAt    time.Time  `bun:"last_changed_at"`
	ExploitedLearned *time.Time `bun:"exploited_learned_at"`
}

// writtenIn is every open finding of one build, by issue and place.
func (f *fixture) writtenIn(t *testing.T, target int64) map[[2]string]written {
	t.Helper()
	var rows []written
	if err := f.db.DB.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		ColumnExpr(`v.identifier AS "identifier"`).
		ColumnExpr(`f.place_identity, f.urgency, f.urgency_exploited, f.urgency_shipped`).
		ColumnExpr(`f.fix_state, f.fixed_in, f.fixed_at, f.matched, f.matched_from`).
		ColumnExpr(`f.matched_in, f.matched_range, f.suppressed_by, f.stated_by, f.claimed_by`).
		ColumnExpr(`f.last_changed_at, f.exploited_learned_at`).
		Where("f.target_id = ?", target).
		Where("f.closed_at IS NULL").
		Scan(t.Context(), &rows); err != nil {
		t.Fatal(err)
	}
	out := map[[2]string]written{}
	for _, row := range rows {
		out[[2]string{row.Identifier, row.PlaceIdentity}] = row
	}
	return out
}

func TestARescanWritesEachMovedFindingWhatAFirstScanOfTheReportWould(t *testing.T) {
	// Findings that move in one scan are written a statement per set of
	// values rather than one per row, so the rows sharing a statement have to
	// be exactly the rows that share every value it writes. A first scan of
	// the same report into a build that has never seen it writes each row on
	// its own, by a different path, and is what the rescanned rows are held
	// to.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		likely := func(id string, likelihood float64) finding.Reported {
			r := found(id, libnl)
			r.Issue.Likelihood = likelihood
			r.FixState, r.FixedIn = finding.NoFix, ""
			return r
		}
		// Pairs that move to values differing in one column each, so two
		// findings sharing a statement they should not is a wrong value.
		yesterday := []finding.Reported{
			likely("CVE-2026-RISES", 0.01),
			likely("CVE-2026-RISES-LESS", 0.01),
			likely("CVE-2026-FIXED", 0.01),
			likely("CVE-2026-FIXED-LATER", 0.01),
			found("CVE-2026-STILL", swss),
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t), yesterday); err != nil {
			t.Fatal(err)
		}
		before := f.writtenIn(t, f.target)

		fixed := likely("CVE-2026-FIXED", 0.01)
		fixed.FixState, fixed.FixedIn = finding.FixedUpstream, "3.9.0"
		later := likely("CVE-2026-FIXED-LATER", 0.01)
		later.FixState, later.FixedIn = finding.FixedUpstream, "3.9.1"
		today := []finding.Reported{
			likely("CVE-2026-RISES", 0.9), likely("CVE-2026-RISES-LESS", 0.3),
			fixed, later, found("CVE-2026-STILL", swss),
		}
		applied, err := f.store.Apply(ctx, f.target, f.run(t), today)
		if err != nil {
			t.Fatal(err)
		}
		// Four issues at the two places libnl sits.
		if applied.Updated != 8 {
			t.Errorf("updated %d findings, want 8", applied.Updated)
		}

		fresh := f.anotherBranch(t, "2.4.0")
		f.shippedTo(t, fresh, twoConsumers())
		if _, err := f.store.Apply(ctx, fresh, f.runOn(t, fresh), today); err != nil {
			t.Fatal(err)
		}

		rescanned, first := f.writtenIn(t, f.target), f.writtenIn(t, fresh)
		if len(rescanned) != 9 || len(first) != 9 {
			t.Fatalf("hold %d and %d open findings, want 9 each", len(rescanned), len(first))
		}
		for at, got := range rescanned {
			want, held := first[at]
			if !held {
				t.Errorf("%v is open in the rescanned build and not in the first scan", at)
				continue
			}
			// The moment a row last changed is its own and is compared below.
			got.LastChangedAt, want.LastChangedAt = time.Time{}, time.Time{}
			if !sameInstant(got.FixedAt, want.FixedAt) || !sameInstant(got.ExploitedLearned,
				want.ExploitedLearned) {
				t.Errorf("%v: moments differ: %+v against %+v", at, got, want)
			}
			got.FixedAt, want.FixedAt = nil, nil
			got.ExploitedLearned, want.ExploitedLearned = nil, nil
			if got.Urgency != want.Urgency || got.FixState != want.FixState ||
				got.FixedIn != want.FixedIn || got.Exploited != want.Exploited ||
				got.Shipped != want.Shipped || got.Matched != want.Matched ||
				got.MatchedFrom != want.MatchedFrom || got.MatchedIn != want.MatchedIn ||
				got.MatchedRange != want.MatchedRange {
				t.Errorf("%v: rescanned as %+v, a first scan writes %+v", at, got, want)
			}
		}
		for at, was := range before {
			now := rescanned[at]
			moved := at[0] != "CVE-2026-STILL"
			if moved == now.LastChangedAt.Equal(was.LastChangedAt) {
				t.Errorf("%v: last changed %v, was %v, and it moved: %v",
					at, now.LastChangedAt, was.LastChangedAt, moved)
			}
		}
	})
}

func TestReRankingAfterAScanLeavesTheScannedBuildAsTheScanRankedIt(t *testing.T) {
	// The scan ranks its own build's findings from the ratings in force, and
	// the re-ranking that follows leaves those rows out. That holds only while
	// both work the order out the same way, from a product's rating as much as
	// from the published word, so this re-ranks the scanned build anyway and
	// requires that nothing moves.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		tag := f.anotherBuild(t, "24.06")
		report := func(likelihood float64) []finding.Reported {
			rated := found("CVE-2026-RATED", libnl)
			rated.Issue.Severity, rated.Issue.Likelihood = "low", likelihood
			published := found("CVE-2026-PUBLISHED", swss)
			published.Issue.Likelihood = likelihood / 2
			return []finding.Reported{rated, published}
		}
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), report(0.01)); err != nil {
			t.Fatal(err)
		}
		f.shippedTo(t, tag, twoConsumers())
		if _, err := f.store.Apply(ctx, tag, f.runOn(t, tag), report(0.01)); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		if _, err := f.store.Assess(ctx, who, f.productID, f.issue(t, "CVE-2026-RATED"),
			"critical", "Reachable from the network in how we ship it."); err != nil {
			t.Fatal(err)
		}

		// Tonight's scan moves both likelihoods. The tag is not rescanned.
		if _, err := f.store.Apply(ctx, f.target, f.run(t), report(0.8)); err != nil {
			t.Fatal(err)
		}
		scanned := f.writtenIn(t, f.target)
		for _, issue := range []string{"CVE-2026-RATED", "CVE-2026-PUBLISHED"} {
			if got, want := f.urgencyIn(t, tag, issue), f.urgencyIn(t, f.target, issue); got != want {
				t.Errorf("%s sits at %d on the tag and %d on the scanned build", issue, got, want)
			}
		}

		issues := []int64{f.issue(t, "CVE-2026-RATED"), f.issue(t, "CVE-2026-PUBLISHED")}
		if err := finding.Reranked(ctx, f.db.DB, issues, time.Now().UTC(), 0); err != nil {
			t.Fatal(err)
		}
		for at, got := range f.writtenIn(t, f.target) {
			if want := scanned[at]; got.Urgency != want.Urgency {
				t.Errorf("%v: re-ranking moved it from %d to %d", at, want.Urgency, got.Urgency)
			}
		}
	})
}
