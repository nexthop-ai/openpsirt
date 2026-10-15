// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"fmt"
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
	ExploitedLearned *time.Time `bun:"exploited_learned_at"`
}

// writtenIn is every open finding of one build, by issue and place.
func (f *fixture) writtenIn(t *testing.T, target int64) map[[2]string]written {
	t.Helper()
	var rows []written
	if err := f.db.DB.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		ColumnExpr(`"v"."identifier" AS "identifier"`).
		ColumnExpr(`"f"."place_identity", "f"."urgency", "f"."urgency_exploited", "f"."urgency_shipped"`).
		ColumnExpr(`"f"."fix_state", "f"."fixed_in", "f"."fixed_at", "f"."matched", "f"."matched_from"`).
		ColumnExpr(`"f"."matched_in", "f"."matched_range", "f"."suppressed_by", "f"."stated_by", "f"."claimed_by"`).
		ColumnExpr(`"f"."exploited_learned_at"`).
		Where(`"f"."target_id" = ?`, target).
		Where(`"f"."closed_at" IS NULL`).
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

func TestWhatClosedBeforeIsReadWithinTheBuildAndTheIssuesAsked(t *testing.T) {
	// The latest closed row of each place is picked by two membership tests
	// joined by OR, which PostgreSQL and MySQL never read as a semi-join. The
	// build, the kind
	// and the issues are repeated on the outer read so it walks only their
	// rows rather than every finding in the deployment.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		asked := &matchedStatements{}
		f.db.AddQueryHook(asked)
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-CLOSED", libnl)}); err != nil {
			t.Fatal(err)
		}
		asked.mu.Lock()
		defer asked.mu.Unlock()
		n := 0
		for _, each := range asked.sent {
			if !strings.Contains(each.query, `MAX("lf"."id")`) {
				continue
			}
			n++
			where := strings.Index(each.query, " WHERE ")
			inner := strings.Index(each.query, "(SELECT ")
			if where < 0 || inner < where {
				t.Fatalf("the read has no outer condition ahead of its arms: %s", each.query)
			}
			outer := each.query[where:inner]
			for _, part := range []string{`"target_id" = `, `"kind" = `, `"closed_at" IS NOT NULL`, `"vulnerability_id" IN (`} {
				if !strings.Contains(outer, part) {
					t.Errorf("the outer read does not ask %q: %s", part, each.query)
				}
			}
		}
		if n == 0 {
			t.Fatal("nothing read what closed before, so this checked nothing")
		}
	})
}

func TestAMovedLikelihoodIsWrittenAStatementPerBatchWithEachRowItsOwnValue(t *testing.T) {
	// A feed moving the likelihood moves it for nearly every issue, each to a
	// value of its own, and with it the order of every place each issue sits.
	// The estimates, the scanned build's order and every other build's order
	// are each written a statement per batch, every row taking its own value
	// by its identifier inside the statement. A value handed to the wrong
	// row shows as an issue holding another's estimate, or as two builds
	// ordering one issue differently.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		yesterday := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		today := yesterday.AddDate(0, 0, 1)
		dated := []string{"CVE-2026-DAY-1", "CVE-2026-DAY-2", "CVE-2026-DAY-3", "CVE-2026-DAY-4"}
		undated := []string{"CVE-2026-UNDATED-1", "CVE-2026-UNDATED-2"}
		likelihoodOf := func(i int, moved bool) float64 {
			if moved {
				return 0.5 - 0.05*float64(i)
			}
			return 0.01 * float64(i+1)
		}
		report := func(moved bool) []finding.Reported {
			on := &yesterday
			if moved {
				on = &today
			}
			var out []finding.Reported
			for i, id := range dated {
				r := found(id, libnl)
				r.Issue.Likelihood, r.Issue.LikelihoodOn = likelihoodOf(i, moved), on
				// Every other one without a percentile, so a batch carries
				// both a number and nothing.
				if i%2 == 0 {
					r.Issue.LikelihoodPercentile = 0.5 + likelihoodOf(i, moved)
				}
				out = append(out, r)
			}
			// Undated and without a percentile, so one batch carries
			// nothing at all for it.
			for i, id := range undated {
				r := found(id, libnl)
				r.Issue.Likelihood = likelihoodOf(len(dated)+i, moved)
				out = append(out, r)
			}
			return out
		}
		tag := f.anotherBuild(t, "24.06")
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), report(false)); err != nil {
			t.Fatal(err)
		}
		f.shippedTo(t, tag, twoConsumers())
		if _, err := f.store.Apply(ctx, tag, f.runOn(t, tag), report(false)); err != nil {
			t.Fatal(err)
		}

		asked := &matchedStatements{}
		f.db.AddQueryHook(asked)
		applied, err := f.store.Apply(ctx, f.target, f.run(t), report(true))
		if err != nil {
			t.Fatal(err)
		}
		all := append(append([]string(nil), dated...), undated...)
		// Every issue at the two places libnl sits.
		if want := 2 * len(all); applied.Updated != want {
			t.Fatalf("updated %d findings, want %d", applied.Updated, want)
		}
		estimates, estimated := asked.matching(`UPDATE "vulnerability" AS "vu" SET "likelihood_ppm" = `)
		ordered, orderedRows := asked.matching(`UPDATE "finding" AS "f" SET "urgency" = CASE "id"`)
		reranked, rerankedRows := asked.matching(`UPDATE "finding" AS "f" SET "urgency" = (CASE WHEN`)
		// One statement for the dated estimates and one for the undated.
		if estimates != 2 || estimated != int64(len(all)) {
			t.Errorf("the estimates were %d statements matching %d issues, want 2 matching %d",
				estimates, estimated, len(all))
		}
		if ordered != 1 || orderedRows != int64(2*len(all)) {
			t.Errorf("the scanned build's order was %d statements matching %d findings, want 1 matching %d",
				ordered, orderedRows, 2*len(all))
		}
		if reranked != 1 || rerankedRows != int64(2*len(all)) {
			t.Errorf("the tag's order was %d statements matching %d findings, want 1 matching %d",
				reranked, rerankedRows, 2*len(all))
		}

		var rows []finding.Vulnerability
		if err := f.db.DB.NewSelect().Model(&rows).
			Where(`"vu"."identifier" LIKE ?`, "CVE-2026-%DATED-%").
			WhereOr(`"vu"."identifier" LIKE ?`, "CVE-2026-DAY-%").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(all) {
			t.Fatalf("read %d issues, want %d", len(rows), len(all))
		}
		held := map[string]finding.Vulnerability{}
		for _, row := range rows {
			held[row.Identifier] = row
		}
		for i, id := range all {
			row := held[id]
			want := int(likelihoodOf(i, true)*1_000_000 + 0.5)
			if row.LikelihoodPPM == nil || *row.LikelihoodPPM != want {
				t.Errorf("%s holds a likelihood of %s, want %d", id, deref(row.LikelihoodPPM), want)
			}
			wantPercentile := "none"
			if i < len(dated) && i%2 == 0 {
				wantPercentile = fmt.Sprint(int((0.5+likelihoodOf(i, true))*1_000_000 + 0.5))
			}
			if got := deref(row.LikelihoodPercentilePPM); got != wantPercentile {
				t.Errorf("%s holds a percentile of %s, want %s", id, got, wantPercentile)
			}
			wantDay := "none"
			if i < len(dated) {
				wantDay = day(&today)
			}
			if got := day(row.LikelihoodOn); got != wantDay {
				t.Errorf("%s holds an estimate for %s, want %s", id, got, wantDay)
			}
		}
		// Falling likelihoods at one severity: each issue below the one
		// before it, and the tag ordering each as the scanned build does.
		var above int64
		for i, id := range all {
			scanned, onTag := f.urgencyIn(t, f.target, id), f.urgencyIn(t, tag, id)
			if scanned != onTag {
				t.Errorf("%s sits at %d on the scanned build and %d on the tag", id, scanned, onTag)
			}
			if i > 0 && scanned >= above {
				t.Errorf("%s sits at %d, at or above %s at %d, with a lower likelihood",
					id, scanned, all[i-1], above)
			}
			above = scanned
		}
	})
}
