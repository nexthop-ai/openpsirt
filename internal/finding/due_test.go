package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// seenAt backdates a scan run, so a test can say when a finding was first
// seen. Nothing else can: the run stamps itself with the clock.
func (f *fixture) seenAt(t *testing.T, runID int64, when time.Time) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Table("scan_run").
		Set("started_at = ?", when.UTC().Truncate(time.Microsecond)).
		Where("id = ?", runID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

var testWindows = finding.Windows{
	Exploited: 3 * 24 * time.Hour,
	Critical:  7 * 24 * time.Hour,
	High:      30 * 24 * time.Hour,
	Medium:    90 * 24 * time.Hour,
	Low:       180 * 24 * time.Hour,
}

func TestWhatIsRunningOutIsOrderedByDeadlineNotByAge(t *testing.T) {
	// The defect this replaced: the statement took the oldest findings and a
	// loop then discarded whatever was not due, so an exploited finding due
	// tomorrow lost its place to an old low that had filled the buffer.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		// A low, first seen a hundred days ago. Its window is a hundred and
		// eighty days, so it is not due for another eighty.
		oldRun := f.run(t)
		f.seenAt(t, oldRun, time.Now().UTC().Add(-100*24*time.Hour))
		mild := found("CVE-2026-OLD", swss)
		mild.Issue.Severity = "low"
		if _, err := f.store.Apply(t.Context(), f.target, oldRun,
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}

		// An exploited finding seen two days ago. Its window is three days,
		// so it is due tomorrow — sooner than anything else here.
		newRun := f.run(t)
		f.seenAt(t, newRun, time.Now().UTC().Add(-2*24*time.Hour))
		urgent := found("CVE-2026-NOW", teamd)
		urgent.Issue.Severity = "medium"
		urgent.Issue.Exploited = true
		if _, err := f.store.Apply(t.Context(), f.target, newRun,
			[]finding.Reported{mild, urgent}); err != nil {
			t.Fatal(err)
		}

		// Ninety days ahead, so both are in range and the order is the thing
		// being tested. The low was seen first and is due last.
		who := f.holding(t, access.PublicTriage)
		late, _, err := f.store.RunningOut(t.Context(), who, finding.Scope{}, 90*24*time.Hour, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(late) != 2 {
			t.Fatalf("%d rows are running out of time, want both", len(late))
		}
		if late[0].Vulnerability != "CVE-2026-NOW" {
			t.Errorf("first row is %s, want the exploited finding due soonest",
				late[0].Vulnerability)
		}

		// And a fortnight ahead the low is not in range at all.
		soon, _, err := f.store.RunningOut(t.Context(), who, finding.Scope{}, 14*24*time.Hour, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range soon {
			if row.Vulnerability == "CVE-2026-OLD" {
				t.Error("a low with eighty days left is on the fortnight's list")
			}
		}
	})
}

// The count that comes back is the answer's, not the page's. A screen reading
// it off the rows it was handed reported its own limit as the figure and
// opened a list with twice as many in it.
func TestWhatIsRunningOutCountsPastThePage(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-60*24*time.Hour))
		reported := []finding.Reported{
			found("CVE-2026-A", libnl),
			found("CVE-2026-B", swss),
			found("CVE-2026-C", teamd),
		}
		if _, err := f.store.Apply(t.Context(), f.target, run, reported); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage)
		whole, total, err := f.store.RunningOut(t.Context(), who, finding.Scope{},
			90*24*time.Hour, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(whole) != total {
			t.Fatalf("%d rows against a total of %d, want them equal where nothing was cut",
				len(whole), total)
		}
		if total < 2 {
			t.Fatalf("total is %d, which is too few to page", total)
		}

		page, capped, err := f.store.RunningOut(t.Context(), who, finding.Scope{},
			90*24*time.Hour, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) != 1 {
			t.Fatalf("%d rows came back for a limit of one", len(page))
		}
		if capped != total {
			t.Errorf("a page of one reports a total of %d, want the whole answer's %d",
				capped, total)
		}

		// Past the end, where there is no row to read the count off.
		beyond, still, err := f.store.RunningOutPage(t.Context(), who, finding.Scope{},
			90*24*time.Hour, 50, total+10)
		if err != nil {
			t.Fatal(err)
		}
		if len(beyond) != 0 {
			t.Fatalf("%d rows past the end of the answer", len(beyond))
		}
		if still != total {
			t.Errorf("past the end the total is %d, want %d", still, total)
		}
	})
}

func TestWhatIsRunningOutIsOneRowPerIssueAtAComponent(t *testing.T) {
	// A kernel flaw at sixty places is one thing somebody has to answer.
	// Sixty rows of it is a list with one entry in it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-60*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if places := len(f.open(t)); places != 2 {
			t.Fatalf("expected one issue at two places, got %d", places)
		}

		late, _, err := f.store.RunningOut(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			14*24*time.Hour, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(late) != 1 {
			t.Fatalf("one issue at two places produced %d rows", len(late))
		}
		if late[0].Places != 2 {
			t.Errorf("the row says %d places, want 2", late[0].Places)
		}
	})
}

func TestAnUnratedFindingDoesNotGetTheLongestDeadline(t *testing.T) {
	// Nobody having scored it is not a claim that it is mild. Under the old
	// mapping it took the low window, which put the findings least is known
	// about at the back of the queue.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-100*24*time.Hour))
		unrated := found("CVE-2026-QUIET", swss)
		unrated.Issue.Severity = ""
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{unrated}); err != nil {
			t.Fatal(err)
		}

		// A hundred days in: past the ninety-day medium window, well inside
		// the hundred-and-eighty-day low one.
		late, _, err := f.store.RunningOut(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			0, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(late) != 1 {
			t.Fatalf("an unrated finding a hundred days old produced %d rows, want 1", len(late))
		}
	})
}

func TestOverdueIsCountedAgainstWhoeverIsHoldingIt(t *testing.T) {
	// A large open count on somebody keeping up is not the same signal as the
	// same count on somebody sitting on it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-100*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		triager := f.holding(t, access.PublicTriage, access.Assigner)
		if _, _, err := f.store.Assign(t.Context(), triager, f.target,
			open[0].VulnerabilityID, open[0].ComponentID, ptr(int64(7))); err != nil {
			t.Fatal(err)
		}

		held, err := f.store.HeldBy(t.Context(), triager, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 1 {
			t.Fatalf("%d people are holding something, want 1", len(held))
		}
		// One issue in one component: one thing to answer, whichever consumer
		// reaches it. Counted as two, this screen disagreed with the list it
		// links to, which reports the same work as one item.
		if held[0].Open != 1 {
			t.Errorf("they hold %d pieces of work, want 1", held[0].Open)
		}
		if held[0].Places != 2 {
			t.Errorf("what they hold covers %d findings, want 2", held[0].Places)
		}
		// A high at a hundred days is seventy days past its thirty-day window.
		// Late in the same units: the piece of work is late, not two of it.
		if held[0].Overdue != 1 {
			t.Errorf("%d of what they hold is overdue, want 1", held[0].Overdue)
		}

		// And the two screens say the same thing. This is the check the
		// numbers are for: what one person is reported to hold, and what that
		// person's own list has in it, are one measurement.
		theirs, total, err := f.store.AssignedTo(t.Context(), triager, []int64{7}, finding.Scope{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != held[0].Open || len(theirs) != held[0].Open {
			t.Errorf("who-holds-what says %d, their own list says %d in %d rows",
				held[0].Open, total, len(theirs))
		}
		if len(theirs) == 1 && theirs[0].Places != held[0].Places {
			t.Errorf("who-holds-what says %d places, their own list says %d",
				held[0].Places, theirs[0].Places)
		}
	})
}

func TestOnlyADecisionThatAppliesTakesAFindingOffTheClock(t *testing.T) {
	// A decision that applies takes a finding off the clock — the
	// same condition that decides whether a decision suppresses the finding
	// at all. What is running out of time excluded any live claim, so a
	// proposal waiting for a second person took a finding off that list for
	// as long as it sat in the queue, while what each person was holding
	// excluded nothing and still counted it as overdue. Both are asked here,
	// after every kind of decision, and have to agree with each other and
	// with what applies.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-100*24*time.Hour))
		if _, err := f.store.Apply(ctx, f.target, run,
			[]finding.Reported{found("CVE-2026-1", swss)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		triager := f.holding(t, access.PublicTriage, access.Assigner)
		if _, _, err := f.store.Assign(ctx, triager, f.target,
			open[0].VulnerabilityID, open[0].ComponentID, ptr(int64(7))); err != nil {
			t.Fatal(err)
		}
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		issueID := f.issueID(t, "CVE-2026-1")
		place := finding.PlaceIdentity(swss.Name, "")

		// One decision standing at the place at a time, written the way the
		// triage store writes one: keyed on the version shipping here, live.
		record := func(state string, needsApproval bool, outcome string, until *time.Time, version string) {
			t.Helper()
			if _, err := f.db.DB.NewDelete().Table("decision").
				Where("vulnerability_id = ?", issueID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			// The outcome and the date it defers to are the claim's: one act
			// is one argument, and this row says where it lands.
			claimID := claimSaying(t, f.db, somebody.ID, outcome)
			if until != nil {
				if _, err := f.db.DB.NewUpdate().TableExpr("\"claim\"").
					Set("deferred_until = ?", until.UTC()).
					Where("id = ?", claimID).Exec(ctx); err != nil {
					t.Fatalf("record when it defers to: %v", err)
				}
			}
			row := map[string]any{
				"claim_id":   claimID,
				"product_id": f.productID, "vulnerability_id": issueID,
				"place_identity": place, "visibility": "public",
				"state":          state,
				"needs_approval": needsApproval, "proposed_by": somebody.ID,
				"proposed_at":                time.Now().UTC(),
				"component_upstream_version": version,
				"live_key":                   "the-live-key",
			}
			if _, err := f.db.DB.NewInsert().Model(&row).TableExpr("\"decision\"").Exec(ctx); err != nil {
				t.Fatalf("record a %s claim: %v", state, err)
			}
		}
		// Both answers, which have to be the same answer.
		onTheClock := func(want bool, because string) {
			t.Helper()
			late, _, err := f.store.RunningOut(ctx, triager, finding.Scope{}, 0, 50)
			if err != nil {
				t.Fatal(err)
			}
			if (len(late) == 1) != want {
				t.Errorf("%s: %d rows are running out of time, want on the list: %v",
					because, len(late), want)
			}
			held, err := f.store.HeldBy(ctx, triager, 0)
			if err != nil {
				t.Fatal(err)
			}
			overdue := 0
			for _, holding := range held {
				overdue += holding.Overdue
			}
			if (overdue == 1) != want {
				t.Errorf("%s: %d overdue against whoever holds it, want overdue: %v",
					because, overdue, want)
			}
		}
		// Sending the standing claim back, which is the other way one stops
		// applying: only a claim needing nobody can be both sent back and
		// standing, and while it is returned nobody is relying on it.
		sendBack := func() {
			t.Helper()
			if _, err := f.db.DB.NewUpdate().TableExpr("\"decision\"").
				Set("sent_back_at = ?", time.Now().UTC()).
				Where("vulnerability_id = ?", issueID).Exec(ctx); err != nil {
				t.Fatalf("send the claim back: %v", err)
			}
		}
		yesterday := time.Now().UTC().Add(-24 * time.Hour)
		nextMonth := time.Now().UTC().Add(30 * 24 * time.Hour)

		onTheClock(true, "nothing decided")
		record("proposed", true, "not-applicable", nil, swss.Version)
		onTheClock(true, "a proposal waiting for a second person suppresses nothing")
		record("proposed", false, "deferred", &nextMonth, swss.Version)
		onTheClock(false, "a proposal needing no agreement applies")
		record("approved", true, "not-applicable", nil, swss.Version)
		onTheClock(false, "an approved claim applies")
		record("approved", true, "not-applicable", nil, "0.9.0")
		onTheClock(true, "an approved claim about another version does not apply here")
		record("approved", true, "deferred", &nextMonth, swss.Version)
		onTheClock(false, "a deferral applies until its date")
		record("approved", true, "deferred", &yesterday, swss.Version)
		onTheClock(true, "a deferral past its date is back on the clock")

		// The rule the triage store asks when it decides whether a decision
		// applies, asked here — because it was added to that store's own copy
		// of the condition and to nothing else, so a claim an approver had
		// returned went on holding its finding off the clock, out of this
		// list and out of the overdue figure, while the notice to its author
		// said it applied to nothing until it was revised.
		record("proposed", false, "deferred", &nextMonth, swss.Version)
		onTheClock(false, "a deferral needing no agreement applies")
		sendBack()
		onTheClock(true, "a claim an approver sent back holds nothing off the clock")
	})
}

// deadline reads the stored deadline for one issue, which is the thing a
// policy change has to move.
func (f *fixture) deadline(t *testing.T, identifier string) time.Time {
	t.Helper()
	var due time.Time
	err := f.db.DB.NewSelect().
		TableExpr("\"finding\" AS \"f\"").
		Join("JOIN \"vulnerability\" AS \"v\" ON v.id = f.vulnerability_id").
		ColumnExpr("f.due_at").
		Where("v.identifier = ?", identifier).
		Where("f.closed_at IS NULL").
		Limit(1).Scan(t.Context(), &due)
	if err != nil {
		t.Fatalf("read the stored deadline for %s: %v", identifier, err)
	}
	return due
}

func TestChangingHowLongSomethingMayStayOpenMovesTheDeadline(t *testing.T) {
	// The deadline is worked out when a finding is first seen and stored,
	// so the one event that makes it wrong is somebody changing the policy
	// that set it. A number an administrator just typed that moves nothing
	// is worse than a slow screen — which is the difference between this
	// and urgency, stale until the next scan because nobody edits it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		run := f.run(t)
		seen := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond)
		f.seenAt(t, run, seen)
		high := found("CVE-2026-HIGH", swss)
		high.Issue.Severity = "high"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{high}); err != nil {
			t.Fatal(err)
		}

		// Stored at ingest, as the first sighting plus the window for its
		// rating rather than as anything derived at read time.
		was := f.deadline(t, "CVE-2026-HIGH")
		want := seen.Add(testWindows.High)
		if was.Sub(want).Abs() > time.Second {
			t.Fatalf("stored deadline is %s, want the first sighting plus the high window, %s",
				was, want)
		}

		shorter := testWindows
		shorter.High = 15 * 24 * time.Hour
		changed, err := f.store.Recompute(t.Context(), shorter)
		if err != nil {
			t.Fatal(err)
		}
		if changed == 0 {
			t.Fatal("the policy changed and nothing was rewritten")
		}

		now := f.deadline(t, "CVE-2026-HIGH")
		if now.Sub(seen.Add(shorter.High)).Abs() > time.Second {
			t.Errorf("deadline after halving the window is %s, want %s",
				now, seen.Add(shorter.High))
		}
		if !now.Before(was) {
			t.Errorf("the window was halved and the deadline did not move earlier: %s then %s",
				was, now)
		}
	})
}

func TestWhatIsRunningOutNarrowsToWhatIsSelected(t *testing.T) {
	// The screens that span products answer for whatever the picker has
	// selected, with "all" offered at each level rather than being the
	// only option — so the narrowing has to happen in the statement, not
	// in whatever is drawing the result.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-40*24*time.Hour))
		high := found("CVE-2026-SCOPE", swss)
		high.Issue.Severity = "high"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{high}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage)
		window := 90 * 24 * time.Hour

		everything, _, err := f.store.RunningOut(t.Context(), who, finding.Scope{}, window, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(everything) == 0 {
			t.Fatal("nothing is running out, so there is nothing to narrow")
		}

		here := f.productID
		mine, _, err := f.store.RunningOut(t.Context(), who,
			finding.Scope{ProductID: &here}, window, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(mine) != len(everything) {
			t.Errorf("narrowing to the only product there is returned %d of %d rows",
				len(mine), len(everything))
		}

		// A product this build does not belong to. Nothing here is in it, and
		// an empty answer is the whole point: a scoped page that quietly
		// ignored the scope would report another product's numbers under this
		// product's name.
		elsewhere := here + 1000
		none, _, err := f.store.RunningOut(t.Context(), who,
			finding.Scope{ProductID: &elsewhere}, window, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(none) != 0 {
			t.Errorf("narrowing to another product returned %d rows, want none", len(none))
		}
	})
}

// setting writes one deployment setting, so a test can put a line in place
// before a scan is applied.
func (f *fixture) setting(t *testing.T, name, value string) error {
	t.Helper()
	return setting.NewStore(f.db.DB).Set(t.Context(), name, value)
}

// deadlineOrZero reads a stored deadline, or the zero time where there is
// none. Below the line there is none, which is the thing being asserted.
func (f *fixture) deadlineOrZero(t *testing.T, identifier string) time.Time {
	t.Helper()
	var due *time.Time
	err := f.db.DB.NewSelect().
		TableExpr("\"finding\" AS \"f\"").
		Join("JOIN \"vulnerability\" AS \"v\" ON v.id = f.vulnerability_id").
		ColumnExpr("f.due_at").
		Where("v.identifier = ?", identifier).
		Where("f.closed_at IS NULL").
		Limit(1).Scan(t.Context(), &due)
	if err != nil {
		t.Fatalf("read the stored deadline for %s: %v", identifier, err)
	}
	if due == nil {
		return time.Time{}
	}
	return *due
}

// urgency reads where an issue's findings sit in the order.
func (f *fixture) urgency(t *testing.T, identifier string) int64 {
	t.Helper()
	var rank int64
	err := f.db.DB.NewSelect().
		TableExpr("\"finding\" AS \"f\"").
		Join("JOIN \"vulnerability\" AS \"v\" ON v.id = f.vulnerability_id").
		ColumnExpr("MAX(f.urgency)").
		Where("v.identifier = ?", identifier).
		Where("f.closed_at IS NULL").
		Scan(t.Context(), &rank)
	if err != nil {
		t.Fatalf("read where %s sits: %v", identifier, err)
	}
	return rank
}

// ratings reads what was published about an issue and what we say instead.
func (f *fixture) ratings(t *testing.T, identifier string) (string, string) {
	t.Helper()
	return f.ratingsIn(t, f.productID, identifier)
}

// ratingsIn is ratings for a product named rather than the fixture's own,
// which is what a check about two products holding different ratings needs.
func (f *fixture) ratingsIn(t *testing.T, productID int64, identifier string) (string, string) {
	t.Helper()
	var row struct {
		Published string `bun:"published"`
		Assessed  string `bun:"assessed"`
	}
	err := f.db.DB.NewSelect().
		TableExpr("\"vulnerability\" AS \"v\"").
		Join(rating.Here, productID).
		ColumnExpr(`COALESCE(v.severity, '') AS "published"`).
		ColumnExpr("COALESCE(ir.severity, '') AS \"assessed\"").
		Where("v.identifier = ?", identifier).
		Scan(t.Context(), &row)
	if err != nil {
		t.Fatalf("read the ratings for %s: %v", identifier, err)
	}
	return row.Published, row.Assessed
}

// rate writes a rating in force for one product, without going through the
// claim that would ordinarily put it there. What a test taking this route is
// checking is what a reader does with a rating rather than how one is made.
func (f *fixture) rate(t *testing.T, productID int64, identifier, severity string) {
	t.Helper()
	if _, err := f.db.DB.NewInsert().Model(&finding.IssueRating{
		VulnerabilityID: f.issue(t, identifier), ProductID: productID, Severity: severity,
	}).Exec(t.Context()); err != nil {
		t.Fatalf("rate %s in product %d: %v", identifier, productID, err)
	}
}

// issue resolves an identifier to what it is stored as.
func (f *fixture) issue(t *testing.T, identifier string) int64 {
	t.Helper()
	var id int64
	err := f.db.DB.NewSelect().
		TableExpr("\"vulnerability\" AS \"v\"").
		ColumnExpr("v.id").
		Where("v.identifier = ?", identifier).
		Scan(t.Context(), &id)
	if err != nil {
		t.Fatalf("read what %s is: %v", identifier, err)
	}
	return id
}

// recorded puts a person row in place at a known identifier, which the
// subjects these tests build are matched on.
//
// An assessment names whoever made it, and that is a real reference rather
// than a number in a column — the subjects these tests hold are made up, so
// the row has to be put there for them.
//
// Written column by column rather than through the access store because the
// identifier has to be the one the subject carries, and a store assigns its
// own. The cost is that a column added to the table with no default has to be
// added here too — which is what the four-engine run reports, in the same
// words on every engine.
func (f *fixture) recorded(t *testing.T, id int64, identity string) {
	t.Helper()
	n, err := f.db.DB.NewSelect().Table("person").Where("id = ?", id).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n > 0 {
		return
	}
	// The party they are assignable as, which every person has.
	party := &access.Party{Kind: access.APerson}
	if _, err := f.db.DB.NewInsert().Model(party).Exec(t.Context()); err != nil {
		t.Fatalf("record the party a person is assignable as: %v", err)
	}
	_, err = f.db.DB.NewInsert().
		Model(&map[string]interface{}{
			"id": id, "party_id": party.ID, "identity": identity, "display_name": identity,
			"is_admin": false, "is_bootstrap": false, "admin_derived": false,
			"audits": false, "audits_derived": false,
			"email_source": "", "digest": false, "digest_unassigned": false,
			"created_at": time.Now().UTC().Truncate(time.Microsecond),
		}).
		TableExpr("\"person\"").
		Exec(t.Context())
	if err != nil {
		t.Fatalf("record a person to hang a claim on: %v", err)
	}
}

func TestAFindingWithNoRunIsStillOnTheClockAndOnTheChart(t *testing.T) {
	// A finding somebody recorded has no scan run. Three passes reached the
	// run for one column — when it opened — and reached it with an inner join,
	// so a finding without one was not mis-reported but absent: off the
	// trend, and never rewritten when the deadline policy changed.
	//
	// Absent is the worse failure. A wrong number invites somebody to check
	// it; a missing row looks like there was nothing to say.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		scan := f.run(t)
		f.seenAt(t, scan, time.Now().UTC().Add(-14*24*time.Hour))
		rated := found("CVE-2026-HIGH", libnl)
		rated.Issue.Severity = "high"
		if _, err := f.store.Apply(t.Context(), f.target, scan,
			[]finding.Reported{rated}); err != nil {
			t.Fatal(err)
		}

		// One recorded by hand, opened a fortnight ago, rated high like the
		// scanned one so the same window applies to both.
		opened := time.Now().UTC().Add(-14 * 24 * time.Hour).Truncate(time.Microsecond)
		entered := finding.Finding{
			TargetID: f.target, Kind: finding.Entered,
			Visibility:      access.Public,
			VulnerabilityID: f.interned(t, "SONIC-2026-0007"),
			ComponentID:     f.open(t)[0].ComponentID,
			PlaceIdentity:   "place-of-something-we-build",
			LastChangedAt:   opened,
			OpenedAt:        opened,
			DueAt:           ptr(opened.Add(testWindows.High)),
		}
		if _, err := f.db.DB.NewInsert().Model(&entered).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// The deadline policy changes. Everything open is rewritten, whatever
		// opened it.
		shorter := testWindows
		shorter.High = 15 * 24 * time.Hour
		if _, err := f.store.Recompute(t.Context(), shorter); err != nil {
			t.Fatal(err)
		}
		var now time.Time
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			ColumnExpr("due_at").Where("id = ?", entered.ID).
			Scan(t.Context(), &now); err != nil {
			t.Fatal(err)
		}
		if now.Sub(opened.Add(shorter.High)).Abs() > time.Second {
			t.Errorf("a recorded finding's deadline is %s after the policy changed, want %s",
				now, opened.Add(shorter.High))
		}

		// And it is on the chart. Counted as issues, so this is one more than
		// the scan alone produced.
		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicRead),
			finding.Scope{}, time.Now().UTC().Add(-28*24*time.Hour), 7*24*time.Hour, 4, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if len(points) == 0 {
			t.Fatal("the trend answered with no points")
		}
		last := points[len(points)-1]
		if last.Open != 2 {
			t.Errorf("the trend counts %d issues open, want 2 — the scanned one and the "+
				"recorded one", last.Open)
		}
	})
}

func TestAFindingOnATagCarriesNoDeadline(t *testing.T) {
	// A tag was built once and is what somebody received. Nothing will land in
	// it whatever a date says, so a deadline on one was unmeetable the moment
	// it was written — and real deployments accumulate tags while branches do
	// not, so every one of them inflates every overdue figure with work nobody
	// could ever have done.
	//
	// Measured on the demo before this: all 26 open findings on its one tag
	// carried a deadline.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		tag := f.anotherBuild(t, "v2.4.1")
		branch := f.anotherBranch(t, "release-2.5")

		for _, target := range []int64{tag, branch} {
			f.shippedTo(t, target, twoConsumers())
			if _, err := f.store.Apply(ctx, target, f.runOn(t, target),
				[]finding.Reported{found("CVE-2026-8899", libnl)}); err != nil {
				t.Fatal(err)
			}
		}

		clocked := func(target int64) int {
			t.Helper()
			n, err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
				Where("target_id = ?", target).
				Where("closed_at IS NULL").
				Where("due_at IS NOT NULL").Count(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		if clocked(tag) != 0 {
			t.Errorf("%d findings on a tag carry a deadline", clocked(tag))
		}
		if clocked(branch) == 0 {
			t.Error("nothing on the branch carries a deadline, so this proves nothing")
		}

		// And a sweep takes one away that was written before the release was a
		// tag, or before this rule was.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("due_at = ?", time.Now().UTC().AddDate(0, 0, 30)).
			Where("target_id = ?", tag).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Recompute(ctx, finding.DefaultWindows()); err != nil {
			t.Fatal(err)
		}
		if clocked(tag) != 0 {
			t.Errorf("after a sweep %d findings on a tag still carry a deadline", clocked(tag))
		}
		if clocked(branch) == 0 {
			t.Error("the sweep took the deadline off the branch too")
		}
	})
}

func TestEachOpeningKeepsItsOwnDeadlineWhenThePolicyMoves(t *testing.T) {
	// The rewrite carries a set of openings in one statement rather than
	// issuing one per opening: the other way round the statement count was
	// openings × bands × identifier slices, which on a product scanned
	// nightly for a year is 189,000 statements against this function's own
	// note promising a handful — and almost all of them matched nothing,
	// because one opening lives in one slice.
	//
	// The part that shape has to get right, and one opening cannot show, is
	// that each row lands on *its own* opening plus its own window.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())

		reported := make([]finding.Reported, 0, 3)
		named := []string{"CVE-2026-ONE", "CVE-2026-TWO", "CVE-2026-THREE"}
		for _, each := range named {
			high := found(each, swss)
			high.Issue.Severity = "high"
			reported = append(reported, high)
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}

		// Three openings, days apart, so the three deadlines are far enough
		// apart that a shared one is unmistakable. Written onto the rows,
		// which is where the rewrite reads them from.
		opened := map[string]time.Time{}
		for i, each := range named {
			seen := time.Now().UTC().Add(-time.Duration(10+i*10) * 24 * time.Hour).
				Truncate(time.Microsecond)
			opened[each] = seen
			if _, err := f.db.DB.NewUpdate().TableExpr("\"finding\" AS \"f\"").
				Set("opened_at = ?", seen).
				Where(`f.vulnerability_id IN (SELECT v.id FROM "vulnerability" AS "v"`+
					` WHERE v.identifier = ?)`, each).
				Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		shorter := testWindows
		shorter.High = 15 * 24 * time.Hour
		if _, err := f.store.Recompute(ctx, shorter); err != nil {
			t.Fatal(err)
		}

		for each, seen := range opened {
			want := seen.Add(shorter.High)
			if got := f.deadline(t, each); got.Sub(want).Abs() > time.Second {
				t.Errorf("%s is due %s, want %s — its own opening plus the window, not "+
					"another finding's", each, got, want)
			}
		}
	})
}

func TestADeadlineRunsFromWhenTheFixExistedRatherThanFromWhenWeSawIt(t *testing.T) {
	// The case this was wrong about, and the common one for an inventory made
	// of distribution packages: the flaw is seen before upstream has released
	// anything, so counting from the sighting sets a deadline against a
	// version that does not exist yet.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		// Seen with nothing to take, then a fix appears a hundred days later.
		none := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-LATE", Severity: "high"},
			Component: libnl, FixState: finding.FixUnknown,
		}
		opening := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, opening,
			[]finding.Reported{none}); err != nil {
			t.Fatal(err)
		}
		f.backdate(t, opening, 100*24*time.Hour)
		f.backdateOpenings(t, 100*24*time.Hour)
		opened := f.startedAt(t, opening)

		released := none
		released.FixState = finding.FixedUpstream
		released.FixedIn = "3.5.7"
		arrived := opened.Add(100 * 24 * time.Hour)
		released.FixedAt = &arrived

		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{released}); err != nil {
			t.Fatal(err)
		}
		// Thirty days from when the fix existed, not from when the finding
		// opened — which would have been seventy days in the past.
		want := arrived.Add(finding.DefaultWindows().High)
		if got := f.deadline(t, "CVE-2026-LATE"); !got.Equal(want) {
			t.Errorf("the deadline is %s, want %s — counted from when the fix arrived",
				got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}

func TestAFixThatLandedBeforeWeSawItLeavesTheDeadlineWhereItWas(t *testing.T) {
	// The other direction, and the ordinary case. If a fix already existed
	// when the finding opened, the clock starts at the sighting: the response
	// time genuinely is from when it was learned, and counting from an older
	// fix date would set a deadline in the past.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		long := time.Now().UTC().Add(-365 * 24 * time.Hour)
		old := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-OLD", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream,
			FixedIn: "3.5.7", FixedAt: &long,
		}
		opening := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, opening,
			[]finding.Reported{old}); err != nil {
			t.Fatal(err)
		}
		want := f.startedAt(t, opening).Add(finding.DefaultWindows().High)
		if got := f.deadline(t, "CVE-2026-OLD"); !got.Equal(want) {
			t.Errorf("the deadline is %s, want %s — counted from when we saw it",
				got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}

func TestNothingUpstreamWouldCloseItSoItCarriesNoDeadline(t *testing.T) {
	// A deadline nobody can meet is not a deadline. Where upstream has
	// released nothing, and where upstream has declined, there is no version
	// to take — and the clock runs anyway, so the overdue list carries rows no
	// upgrade would answer, which is how people stop reading the color.
	//
	// A scanner that did not answer is a different thing, and stays on the
	// clock: reading silence as "nothing exists" is a claim about the world
	// made out of a gap in a report.
	for _, one := range []struct {
		what       string
		identifier string
		state      finding.FixState
		clock      bool
	}{
		{"upstream has released nothing", "CVE-2026-NONE", finding.NoFix, false},
		{"upstream declined", "CVE-2026-DECLINED", finding.WontFix, false},
		{"the scanner did not say", "CVE-2026-SILENT", finding.FixUnknown, true},
		{"a fix exists", "CVE-2026-READY", finding.FixedUpstream, true},
	} {
		t.Run(one.what, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.shipped(t, twoConsumers())
				identifier := one.identifier
				reported := finding.Reported{
					Issue:     finding.Named{Identifier: identifier, Severity: "high"},
					Component: libnl, FixState: one.state,
				}
				if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
					[]finding.Reported{reported}); err != nil {
					t.Fatal(err)
				}
				due := f.deadlineOrZero(t, identifier)
				if one.clock && due.IsZero() {
					t.Errorf("%s carries no deadline, and an upgrade would answer it", one.what)
				}
				if !one.clock && !due.IsZero() {
					t.Errorf("%s carries a deadline of %s, and no upgrade would answer it",
						one.what, due.Format(time.RFC3339))
				}
				// It still exists and still ranks. What ends is the clock.
				if f.urgency(t, identifier) == 0 {
					t.Errorf("%s left the finding unranked", one.what)
				}
			})
		})
	}
}

func TestAFixArrivingStartsAClockThatWasNotRunning(t *testing.T) {
	// The corollary, and the half a rule keyed on what moved would miss: a fix
	// appearing upstream touches no ranking signal at all, so a deadline
	// recounted only when the ranking moved would leave the finding with none
	// for ever.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		none := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-APPEARS", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{none}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-APPEARS"); !due.IsZero() {
			t.Fatalf("a finding with nothing to take carries a deadline of %s", due)
		}

		released := none
		released.FixState = finding.FixedUpstream
		released.FixedIn = "3.5.7"
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{released}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-APPEARS"); due.IsZero() {
			t.Error("a fix appeared upstream and the finding still carries no deadline")
		}
	})
}

func TestUpstreamWithdrawingAFixStopsTheClock(t *testing.T) {
	// And back the other way, because the rule is one rule rather than two.
	// A finding whose fix is withdrawn has nothing to take again, and a
	// deadline left standing is one nobody can meet.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		released := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-WITHDRAWN", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream, FixedIn: "3.5.7",
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{released}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-WITHDRAWN"); due.IsZero() {
			t.Fatal("a finding with a fix available carries no deadline")
		}

		gone := released
		gone.FixState, gone.FixedIn = finding.NoFix, ""
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{gone}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-WITHDRAWN"); !due.IsZero() {
			t.Errorf("the fix went away and the deadline of %s stayed", due.Format(time.RFC3339))
		}
	})
}

func TestNoOtherPathHandsBackAClockNothingCouldMeet(t *testing.T) {
	// The rule landed on the scan path and three other places write a
	// deadline. Each of them is reached by an ordinary act — somebody rating
	// an issue, an administrator saving a window, a feed reporting
	// exploitation — so a rule enforced on one of four is a rule that holds
	// until somebody does their job.
	//
	// Worse on a tag, which is scanned once: a branch corrects itself the next
	// night, and a tag keeps whatever it was handed for as long as the finding
	// is open.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		nothing := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-STUCK", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{nothing}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-STUCK"); !due.IsZero() {
			t.Fatalf("a finding with nothing to take opened with a deadline of %s", due)
		}

		for _, act := range []struct {
			what string
			do   func(t *testing.T)
		}{
			{
				// Somebody rates the issue, which recounts every deadline it
				// is open against. Through the store rather than by writing a
				// rating row, because the recount is what is being tested and
				// a row written straight to the table never reaches it.
				"somebody rates the issue",
				func(t *testing.T) {
					t.Helper()
					f.recorded(t, 1, "someone")
					if _, err := f.store.Assess(ctx, f.holding(t, access.PublicTriage),
						f.productID, f.issue(t, "CVE-2026-STUCK"), "critical",
						"Reachable from the network in how we ship it."); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				// An administrator saves a remediation window, which recounts
				// every deadline in the deployment.
				"an administrator saves a window",
				func(t *testing.T) {
					t.Helper()
					shorter := testWindows
					shorter.High = 15 * 24 * time.Hour
					if _, err := f.store.Recompute(ctx, shorter); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				// A feed reports it as exploited, which sets an exploited
				// clock on every build it is open in.
				"a feed reports it exploited",
				func(t *testing.T) {
					t.Helper()
					exploited := nothing
					exploited.Issue.Exploited = true
					if _, err := f.store.Apply(ctx, f.target, f.run(t),
						[]finding.Reported{exploited}); err != nil {
						t.Fatal(err)
					}
				},
			},
		} {
			act.do(t)
			if due := f.deadlineOrZero(t, "CVE-2026-STUCK"); !due.IsZero() {
				t.Errorf("after %s, a finding with nothing to take carries %s",
					act.what, due.Format(time.RFC3339))
			}
		}
	})
}

func TestAFixDatedAfterWeSawItIsNotWhatTheClockRunsFrom(t *testing.T) {
	// The fix date is a feed's, parsed and never checked, and this rule made
	// it load-bearing. One entry dated two centuries out would carry the
	// deadline with it — and the finding would leave the overdue list and the
	// compliance rate for as long as it stayed open, which is the silent
	// disappearance this whole rule exists to stop, arriving through the field
	// that implements it.
	//
	// A fix cannot have arrived after the moment we saw that it had, so that
	// is the ceiling.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		ahead := time.Now().UTC().Add(180 * 365 * 24 * time.Hour)
		absurd := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-AHEAD", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream,
			FixedIn: "3.9.0", FixedAt: &ahead,
		}
		opening := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, opening,
			[]finding.Reported{absurd}); err != nil {
			t.Fatal(err)
		}
		// Counted from when we saw it, as though the feed had said nothing.
		want := f.startedAt(t, opening).Add(finding.DefaultWindows().High)
		got := f.deadline(t, "CVE-2026-AHEAD")
		if !got.Equal(want) {
			t.Errorf("the deadline is %s, want %s — the fix date is in the future",
				got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}
