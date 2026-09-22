package finding_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAnIssueBecomingWorseMovesTheFindingsItIsOpenAgainst(t *testing.T) {
	// A finding's rank follows what is known about its issue, and what is
	// known moves after the finding opened. Frozen at opening, a finding
	// whose likelihood was revised upward stayed where the first night put
	// it — so the list ordered by a number nobody could reconcile with the
	// row it was drawn beside.
	//
	// The deadline is not touched: score and likelihood are deliberately
	// not in it, and a clock reset by a revised number would never arrive.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		unlikely := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high", Likelihood: 0.01},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{unlikely}); err != nil {
			t.Fatal(err)
		}
		opened := f.open(t)
		if len(opened) != 2 {
			t.Fatalf("opened %d findings", len(opened))
		}
		was := opened[0].Urgency
		due := opened[0].DueAt

		likely := unlikely
		likely.Issue.Likelihood = 0.9
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{likely})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Updated != 2 {
			t.Errorf("a likelihood moving updated %d findings, want both", applied.Updated)
		}
		for _, row := range f.open(t) {
			if row.Urgency <= was {
				t.Errorf("urgency is %d after the likelihood rose from 0.01 to 0.9, was %d",
					row.Urgency, was)
			}
			if !sameInstant(row.DueAt, due) {
				t.Errorf("the deadline moved to %v on a likelihood change, want %v", row.DueAt, due)
			}
		}
	})
}

func TestAReportThatKnowsLessDoesNotLowerAFinding(t *testing.T) {
	// The reason a rank that follows the issue is not a rank that flaps
	// nightly. Reports disagree and arrive in an order nobody controls, so
	// what is stored is the worst anybody has claimed and moves only toward
	// worse — and the rank is read from there rather than from the report
	// being applied. Ranked from the report, one source omitting a likelihood
	// would demote the finding and the next night's report would promote it
	// again, for ever.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		known := finding.Reported{
			Issue: finding.Named{
				Identifier: "CVE-2026-2", Severity: "high",
				Likelihood: 0.9, Exploited: true,
			},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{known}); err != nil {
			t.Fatal(err)
		}
		opened := f.open(t)
		if len(opened) != 2 {
			t.Fatalf("opened %d findings", len(opened))
		}
		was, due := opened[0].Urgency, opened[0].DueAt

		// The same issue, from a report that mentions neither.
		quieter := known
		quieter.Issue.Likelihood = 0
		quieter.Issue.Exploited = false
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{quieter})
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("a report that knew less wrote %+v, want nothing", applied)
		}
		for _, row := range f.open(t) {
			if row.Urgency != was {
				t.Errorf("urgency fell from %d to %d because one report omitted what another said",
					was, row.Urgency)
			}
			if !row.RankExploited {
				t.Error("a finding stopped being exploited because one report did not mention it")
			}
			if !sameInstant(row.DueAt, due) {
				t.Errorf("the deadline moved to %v because one report knew less, want %v", row.DueAt, due)
			}
		}
	})
}

func TestAnIssueBecomingExploitedIsClockedFromWhenThatWasLearned(t *testing.T) {
	// Exploitation is the one signal that decides how long there is, and
	// it arrives after the finding opened at least as often as with it.
	//
	// Counted from the opening, a finding six months old would be given
	// three days that ran out five months ago — a deadline nobody could
	// have met, which is the failure a deadline from urgency names as the
	// way to make the whole overdue figure ignorable. So the recount runs
	// from the scan that learned it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		// Fixed upstream, which is stated rather than incidental: a deadline
		// is only meetable where a version exists to take, so this test's
		// subject needs a finding that carries one at all.
		quiet := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-KEV", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream,
		}
		opening := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, opening, []finding.Reported{quiet}); err != nil {
			t.Fatal(err)
		}
		opened := f.open(t)
		if len(opened) != 2 {
			t.Fatalf("opened %d findings", len(opened))
		}
		if opened[0].RankExploited {
			t.Fatal("nothing said this was exploited")
		}
		// Two hundred days of it sitting there unremarked, so the two ways of
		// counting land months apart rather than milliseconds. The run and
		// the rows it opened both move: the finding carries its own opening,
		// which is the base the wrong answer counts from.
		f.backdate(t, opening, 200*24*time.Hour)
		f.backdateOpenings(t, 200*24*time.Hour)

		exploited := quiet
		exploited.Issue.Exploited = true
		learning := f.run(t)
		applied, err := f.store.Apply(t.Context(), f.target, learning, []finding.Reported{exploited})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Updated != 2 {
			t.Errorf("learning this is exploited updated %d findings, want both", applied.Updated)
		}
		want := f.startedAt(t, learning).Add(finding.DefaultWindows().Exploited)
		for _, row := range f.open(t) {
			if !row.RankExploited {
				t.Error("a finding of an exploited issue is not marked exploited")
			}
			if !finding.Exploiting(row.Urgency) {
				t.Errorf("urgency %d does not read as exploited", row.Urgency)
			}
			if row.DueAt == nil {
				t.Fatal("an exploited finding has no deadline")
			}
			if !row.DueAt.Equal(want) {
				t.Errorf("the deadline is %s, want %s — three days from the scan that learned it",
					row.DueAt.Format(time.RFC3339), want.Format(time.RFC3339))
			}
		}

		// And it stays there. Anything that recounts this issue's deadlines
		// has to reach the same answer: counting from the opening is what the
		// scan above refused to do, and a recount that does it anyway moves
		// the deadline to a date five months in the past, silently, with
		// nothing logged.
		f.recorded(t, 1, "someone")
		if _, err := f.store.Assess(t.Context(), f.holding(t, access.PublicTriage),
			f.productID, f.issue(t, "CVE-2026-KEV"), "critical",
			"Reachable from the network in how we ship it."); err != nil {
			t.Fatal(err)
		}
		for _, row := range f.open(t) {
			if row.DueAt == nil {
				t.Fatal("an exploited finding lost its deadline to a re-rating")
			}
			if !row.DueAt.Equal(want) {
				t.Errorf("a re-rating moved the deadline to %s, want %s — it is counted from "+
					"when exploitation was learned, and nothing since has changed that",
					row.DueAt.Format(time.RFC3339), want.Format(time.RFC3339))
			}
		}
	})
}

// sameInstant compares two deadlines that may be absent.
func sameInstant(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

func TestANewFindingIsClockedByTheRatingInForce(t *testing.T) {
	// Somebody rated this issue worse than the world says, and that rating
	// is what every later reading uses: where it sits, what the line
	// admits, and the deadline of everything already open. A finding of
	// the same issue opened afterwards, on the published word's deadline,
	// would sit beside them with months more to run for no reason anybody
	// chose.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		mild := found("CVE-2026-RAISE", swss)
		mild.Issue.Severity = "low"
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		if _, err := f.store.Assess(t.Context(), who, f.productID, f.issue(t, "CVE-2026-RAISE"),
			"critical", "Reachable from the network in how we ship it."); err != nil {
			t.Fatal(err)
		}

		// The same issue turns up in another build.
		// A branch, because a tag carries no deadline at all: it was built
		// once, so nothing will land in it whatever a date says.
		other := f.anotherBranch(t, "2.4.0")
		f.shippedTo(t, other, twoConsumers())
		run := f.runOn(t, other)
		if _, err := f.store.Apply(t.Context(), other, run, []finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}

		var rows []struct {
			DueAt     *time.Time `bun:"due_at"`
			StartedAt time.Time  `bun:"started_at"`
		}
		err := f.db.DB.NewSelect().
			TableExpr("\"finding\" AS \"f\"").
			Join("JOIN \"scan_run\" AS \"r\" ON r.id = f.opened_run_id").
			ColumnExpr("f.due_at AS \"due_at\"").
			ColumnExpr("r.started_at AS \"started_at\"").
			Where("f.target_id = ?", other).
			Scan(t.Context(), &rows)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("nothing was opened in the other build")
		}
		windows := finding.DefaultWindows()
		for _, row := range rows {
			if row.DueAt == nil {
				t.Fatal("a finding was opened with no deadline")
			}
			if got := row.DueAt.Sub(row.StartedAt); got != windows.Critical {
				t.Errorf("clocked at %v, want the %v a critical gets rather than the %v a low gets",
					got, windows.Critical, windows.Low)
			}
		}
	})
}

func TestAScanDoesNotCloseWhatAPersonRecorded(t *testing.T) {
	// A run is the authority on what it found: it opens what it reports and
	// closes everything open that it no longer reports. That sweep covered
	// every finding against the build, including ones no scanner has an
	// opinion about — so the first nightly scan after somebody recorded a
	// flaw in what we ship would close it, the same night, with a reason
	// that reads like the issue went away.
	//
	// Nothing would have reported that. The row looks exactly like a
	// component that stopped shipping.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		scanned := f.open(t)
		if len(scanned) == 0 {
			t.Fatal("the scan found nothing to build on")
		}

		// Somebody records a flaw in what this build ships. It hangs off a
		// component that is in the build, because that is where it is.
		entered := scanned[0]
		entered.ID = 0
		entered.Kind = finding.Entered
		entered.VulnerabilityID = f.interned(t, "SONIC-2026-0001")
		if _, err := f.db.DB.NewInsert().Model(&entered).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// The next scan reports the same component and nothing else. Under the
		// old sweep this closed the entered row.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		var still int
		err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			Where("kind = ?", finding.Entered).
			Where("closed_at IS NULL").
			ColumnExpr("COUNT(*)").Scan(t.Context(), &still)
		if err != nil {
			t.Fatal(err)
		}
		if still != 1 {
			t.Errorf("%d recorded findings survived a scan that said nothing about them, want 1", still)
		}

		// And the scan still governs its own: a component it stops reporting
		// closes, which is the behavior the narrowing must not have broken.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), nil); err != nil {
			t.Fatal(err)
		}
		var scannedOpen int
		err = f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			Where("kind = ?", finding.Vulnerable).
			Where("closed_at IS NULL").
			ColumnExpr("COUNT(*)").Scan(t.Context(), &scannedOpen)
		if err != nil {
			t.Fatal(err)
		}
		if scannedOpen != 0 {
			t.Errorf("%d scanned findings stayed open after a scan reported none", scannedOpen)
		}
	})
}

// A signal moving reaches every build the issue is open in, not only the one
// being scanned.
//
// Three of the four signals the order is worked out from are properties of
// the issue, and the order is stored per finding — rewritten only for the
// build the scan was about. So a nightly branch scan learning that something
// is being exploited left the shipped tag carrying a number from before:
// below the triage line, answering no exploited filter, on no exploited
// clock, at the bottom of the list, until somebody rescanned the tag, which
// for a tag is never.
func TestLearningSomethingIsExploitedReachesEveryBuildItIsOpenIn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// The same issue in two builds of the product: the branch that is
		// scanned nightly, and a release that was scanned once.
		tag := f.anotherBuild(t, "24.06")
		// Fixed upstream, stated rather than incidental: a deadline is only
		// meetable where there is a version to take, so this test's subject
		// needs a finding that carries one at all.
		quiet := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
		}
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{quiet}); err != nil {
			t.Fatal(err)
		}
		f.shippedTo(t, tag, twoConsumers())
		if _, err := f.store.Apply(ctx, tag, f.runOn(t, tag),
			[]finding.Reported{quiet}); err != nil {
			t.Fatal(err)
		}

		// Tonight's branch scan learns it is being exploited. The tag is not
		// rescanned, and will not be.
		exploited := quiet
		exploited.Issue.Exploited = true
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{exploited}); err != nil {
			t.Fatal(err)
		}

		var onTheTag []finding.Finding
		if err := f.db.DB.NewSelect().Model(&onTheTag).
			Where("target_id = ?", tag).Where("closed_at IS NULL").
			Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(onTheTag) == 0 {
			t.Fatal("the release holds none of it")
		}
		for _, row := range onTheTag {
			if !row.RankExploited {
				t.Error("a release nobody rescanned does not know this is exploited")
			}
			if !finding.Exploiting(row.Urgency) {
				t.Errorf("its urgency is %d, which does not read as exploited", row.Urgency)
			}
			if row.DueAt == nil {
				t.Error("it has no deadline at all")
			}
		}
	})
}

func TestANewFindingIsOrderedByItsOwnProductsRating(t *testing.T) {
	// The one copy of the rating that remains. A finding's urgency is stored
	// so a list can sort on it without joining four signals for every row, and
	// the applying path is what writes it — so it is the thing most likely to
	// go stale now that the rating it is worked out from belongs to a product.
	//
	// Two halves, and both matter. A place that newly pulls the library in
	// here has to arrive at the rating this product made, and a place that
	// newly pulls it in next door has to arrive at the published one.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		mild := found("CVE-2026-ORDER", swss)
		mild.Issue.Severity = "low"
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "other-product")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		published := f.urgencyIn(t, elsewhere, "CVE-2026-ORDER")

		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		if _, err := f.store.Assess(ctx, who, f.productID, f.issue(t, "CVE-2026-ORDER"),
			"critical", "Reachable from the network in how we ship it."); err != nil {
			t.Fatal(err)
		}
		rated := f.urgencyIn(t, f.target, "CVE-2026-ORDER")
		if rated <= published {
			t.Fatalf("the rating did not move the order: %d against %d", rated, published)
		}

		// The same issue turns up in a build of each product that has not seen
		// it before, which is the path that reads the rating at the moment it
		// opens a finding.
		here := f.anotherBranch(t, "2.4.0")
		f.shippedTo(t, here, twoConsumers())
		if _, err := f.store.Apply(ctx, here, f.runOn(t, here),
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		if got := f.urgencyIn(t, here, "CVE-2026-ORDER"); got != rated {
			t.Errorf("a finding opened after the rating sits at %d, want the %d the ones "+
				"beside it sit at", got, rated)
		}

		// And in the product that rated nothing, where the published word is
		// still the answer.
		theirs := f.anotherBranchOf(t, f.productOf(t, elsewhere), "2.4.0")
		f.shippedTo(t, theirs, twoConsumers())
		if _, err := f.store.Apply(ctx, theirs, f.runOn(t, theirs),
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		if got := f.urgencyIn(t, theirs, "CVE-2026-ORDER"); got != published {
			t.Errorf("a finding opened in a product that rated nothing sits at %d, want the %d "+
				"the published word gives — a rating made next door reached it", got, published)
		}
	})
}

// urgencyIn is where an issue sits in the order, in one build.
func (f *fixture) urgencyIn(t *testing.T, target int64, identifier string) int64 {
	t.Helper()
	var rank int64
	err := f.db.DB.NewSelect().
		TableExpr("\"finding\" AS \"f\"").
		Join("JOIN \"vulnerability\" AS \"v\" ON v.id = f.vulnerability_id").
		ColumnExpr("MAX(f.urgency)").
		Where("v.identifier = ?", identifier).
		Where("f.target_id = ?", target).
		Where("f.closed_at IS NULL").
		Scan(t.Context(), &rank)
	if err != nil {
		t.Fatalf("read where %s sits in build %d: %v", identifier, target, err)
	}
	return rank
}

func TestAFallingLikelihoodIsTakenRatherThanItsPeak(t *testing.T) {
	// The estimate is a thirty-day forecast recomputed every day, and it
	// legitimately falls. Kept as the worst anybody ever published — which is
	// right for a score and for being exploited, both of which are claims
	// about the world — a CVE that spiked once read its peak for ever, and
	// ordering by it answered "was ever risky" rather than "is risky".
	//
	// The newer of two reports is a question about the day the estimate
	// was computed for, not about which scan ran last: reports arrive in an
	// order nobody controls.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		spiked := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		settled := time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)

		peak := finding.Reported{
			Issue: finding.Named{
				Identifier: "CVE-2026-3", Severity: "high",
				Likelihood: 0.9, LikelihoodPercentile: 0.99, LikelihoodOn: &spiked,
			},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{peak}); err != nil {
			t.Fatal(err)
		}
		was := f.open(t)[0].Urgency

		// A week later the forecast has come down.
		today := peak
		today.Issue.Likelihood = 0.05
		today.Issue.LikelihoodPercentile = 0.6
		today.Issue.LikelihoodOn = &settled
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{today}); err != nil {
			t.Fatal(err)
		}
		for _, row := range f.open(t) {
			if row.Urgency >= was {
				t.Errorf("urgency is %d after the estimate fell from 0.9 to 0.05, was %d — "+
					"the peak is still what the order reads", row.Urgency, was)
			}
		}

		// And the stale report arriving late does not put the peak back:
		// which of two estimates is newer is about the day, not about which
		// scan ran last.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{peak}); err != nil {
			t.Fatal(err)
		}
		for _, row := range f.open(t) {
			if row.Urgency >= was {
				t.Errorf("a report about an earlier day put the peak back: urgency is %d, "+
					"and the spike read %d", row.Urgency, was)
			}
		}
	})
}

func TestAScoreRisingDoesNotCarryAStaleEstimateWithIt(t *testing.T) {
	// The three signals are raised in one statement under one condition, and
	// that condition is an OR across them: the row matches when *any* of them
	// would move. So a write for one of them writes all three, and a report
	// carrying a rising score alongside a stale estimate put the estimate back
	// — which is the ratchet this branch removed, arriving by the side door.
	//
	// The estimate needs a guard the row-level condition cannot give it,
	// because the condition is shared. A `CASE` inside the same `SET` list is
	// not it either: two engines evaluate assignments left to right and read
	// the already-written value, so a guard on one column would see another's
	// new value. Its own statement is the portable shape.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		spiked := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		settled := time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)

		peak := finding.Reported{
			Issue: finding.Named{
				Identifier: "CVE-2026-5", Severity: "high",
				Likelihood: 0.9, LikelihoodOn: &spiked, Score: 5.0,
			},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{peak}); err != nil {
			t.Fatal(err)
		}

		// A week on the forecast has come down, which is what should stand.
		today := peak
		today.Issue.Likelihood = 0.05
		today.Issue.LikelihoodOn = &settled
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{today}); err != nil {
			t.Fatal(err)
		}

		// Now a report from another source rating it worse, carrying the old
		// estimate. The score is news and must land; the estimate is about an
		// earlier day and must not.
		worse := peak
		worse.Issue.Score = 9.0
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{worse}); err != nil {
			t.Fatal(err)
		}

		var issue finding.Vulnerability
		if err := f.db.DB.NewSelect().Model(&issue).
			Where("identifier = ?", "CVE-2026-5").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if issue.LikelihoodPPM == nil || *issue.LikelihoodPPM != 50_000 {
			t.Errorf("the estimate reads %s after a rising score carried an older one in, "+
				"want the 0.05 of the later day", ppm(issue.LikelihoodPPM))
		}
		if issue.LikelihoodOn == nil || !issue.LikelihoodOn.UTC().Equal(settled) {
			t.Errorf("the day reads %v, want the later one", issue.LikelihoodOn)
		}
		if issue.ScoreCenti == nil || *issue.ScoreCenti != 900 {
			t.Errorf("the score reads %s, want the 9.0 that rose", ppm(issue.ScoreCenti))
		}
	})
}

func TestAnUndatedEstimateDoesNotWipeTheDayAStoredOneHas(t *testing.T) {
	// Writing the day unconditionally clears it where a report carries none,
	// and after that every later report wins on `likelihood_on IS NULL` — so
	// newest-wins is off for that issue for good, and one feed that omits the
	// date undoes the rule for everybody.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		dated := time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)

		known := finding.Reported{
			Issue: finding.Named{
				Identifier: "CVE-2026-6", Severity: "high",
				Likelihood: 0.05, LikelihoodOn: &dated,
			},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{known}); err != nil {
			t.Fatal(err)
		}

		// A feed that states an estimate and no day, alongside a score that
		// rose. The score is what matches the row; the estimate cannot be
		// shown to be newer than a dated one, so it must change nothing —
		// including the day.
		undated := known
		undated.Issue.Likelihood = 0.9
		undated.Issue.LikelihoodOn = nil
		undated.Issue.Score = 9.0
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{undated}); err != nil {
			t.Fatal(err)
		}

		var issue finding.Vulnerability
		if err := f.db.DB.NewSelect().Model(&issue).
			Where("identifier = ?", "CVE-2026-6").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if issue.LikelihoodOn == nil {
			t.Fatal("an undated report cleared the day a dated one had, so nothing later " +
				"can be compared against it")
		}
		if issue.LikelihoodPPM == nil || *issue.LikelihoodPPM != 50_000 {
			t.Errorf("the estimate reads %s, want the dated 0.05 it could not be shown to "+
				"be newer than", ppm(issue.LikelihoodPPM))
		}
	})
}

// ppm reads a stored number back for a message, where absent says so rather
// than printing an address.
func ppm(value *int) string {
	if value == nil {
		return "nothing"
	}
	return fmt.Sprint(*value)
}

func TestLearningSomethingIsExploitedDoesNotHandBackAClockNothingCouldMeet(t *testing.T) {
	// Exploitation says how long there is. It does not say there is a version
	// to take — so an issue upstream has released no fix for stays off the
	// clock, however urgent it becomes.
	//
	// The build that matters is the one nobody rescans. A branch corrects
	// itself the next night; a tag was built once, so a deadline handed back
	// here is one it keeps for as long as the finding is open, and it is a
	// date nobody could ever have met.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		tag := f.anotherBuild(t, "24.06")
		nothing := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-NOFIX", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{nothing}); err != nil {
			t.Fatal(err)
		}
		f.shippedTo(t, tag, twoConsumers())
		if _, err := f.store.Apply(ctx, tag, f.runOn(t, tag),
			[]finding.Reported{nothing}); err != nil {
			t.Fatal(err)
		}

		exploited := nothing
		exploited.Issue.Exploited = true
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{exploited}); err != nil {
			t.Fatal(err)
		}

		var rows []finding.Finding
		if err := f.db.DB.NewSelect().Model(&rows).
			Where("closed_at IS NULL").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("nothing is open")
		}
		for _, row := range rows {
			// It is still exploited, still ranked for it, and still has no
			// deadline: what ends is the clock, not the finding.
			if !row.RankExploited {
				t.Error("a finding of an exploited issue is not marked exploited")
			}
			if row.DueAt != nil {
				t.Errorf("a finding with nothing to take carries a deadline of %s",
					row.DueAt.Format(time.RFC3339))
			}
		}
	})
}
