// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// putOffUntilTakenBack records a deferral that was withdrawn on a date, which
// is what decides how much of what it asked for it actually held.
func (f *fixture) putOffUntilTakenBack(t *testing.T, occurrence string, from, until,
	takenBack time.Time) {

	t.Helper()
	f.putOffEnding(t, occurrence, from, until, triage.Withdrawn, &takenBack)
}

// putOff records one deferral at an occurrence, from a moment until a moment.
//
// Written directly rather than proposed through the store: what is under test
// is the report, and reaching three deferrals at one occurrence through the normal
// path means three approvals and two supersessions, none of which this is
// about.
func (f *fixture) putOff(t *testing.T, occurrence string, from, until time.Time, state triage.State) {
	t.Helper()
	f.putOffEnding(t, occurrence, from, until, state, nil)
}

// putOffIn is putOff against a product other than the fixture's own.
func (f *fixture) putOffIn(t *testing.T, product int64, occurrence string, from, until time.Time,
	state triage.State) {

	t.Helper()
	f.putOffAt(t, product, occurrence, from, until, state, nil)
}

func (f *fixture) putOffEnding(t *testing.T, occurrence string, from, until time.Time,
	state triage.State, endedAt *time.Time) {

	t.Helper()
	f.putOffAt(t, f.product, occurrence, from, until, state, endedAt)
}

func (f *fixture) putOffAt(t *testing.T, product int64, occurrence string, from, until time.Time,
	state triage.State, endedAt *time.Time) {
	t.Helper()
	// Every row belongs to a decision, even one covering a single occurrence, so
	// the report reads the same rows a real deferral produces.
	// The words are the decision's; the landing place is the row's.
	decision := &triage.Decision{
		Kind: triage.FindingDecision, ProposedBy: f.proposer, ProposedAt: from,
		Outcome: triage.Deferred, DeferredUntil: &until,
	}
	if _, err := f.db.DB.NewInsert().Model(decision).Exec(t.Context()); err != nil {
		t.Fatalf("record a decision: %v", err)
	}
	// The key carries the product, as a real one does: two products may hold
	// the same occurrence and both may be decided about.
	live := fmt.Sprintf("%d|%s|%s", product, occurrence, until.Format(time.RFC3339Nano))
	row := &triage.DecisionOccurrence{
		DecisionID: decision.ID, ProductID: product, VulnerabilityID: f.issue,
		OccurrenceIdentity: occurrence, Visibility: access.Public,
		State: state, ProposedBy: f.proposer, ProposedAt: from, EndedAt: endedAt,
	}
	if state.Live() {
		row.LiveKey = &live
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
		t.Fatalf("record a deferral: %v", err)
	}
}

func TestWhatKeepsBeingPutOffIsListedWithHowOftenAndHowLong(t *testing.T) {
	// The cumulative threshold refuses a further deferral one item at a
	// time; what it cannot show is that forty items have each been put off
	// three times, which is a policy nobody wrote down and nobody agreed
	// to.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		// One occurrence put off twice, another once.
		f.putOff(t, "place-a", now.Add(-60*24*time.Hour), now.Add(-30*24*time.Hour), triage.Approved)
		f.putOff(t, "place-a", now.Add(-30*24*time.Hour), now.Add(30*24*time.Hour), triage.Approved)
		f.putOff(t, "place-b", now.Add(-10*24*time.Hour), now.Add(20*24*time.Hour), triage.Approved)

		rows, _, err := f.store.RepeatsPage(t.Context(), f.triager, 0, 2, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("listed %d occurrences, want the one put off more than once: %+v", len(rows), rows)
		}
		got := rows[0]
		if got.Times != 2 {
			t.Errorf("it says %d deferrals, want 2", got.Times)
		}
		// Thirty days and sixty days, added up — the figure the per-item
		// threshold already measures, shown across everything.
		if got.TotalDays < 85 || got.TotalDays > 95 {
			t.Errorf("it says %.1f days in total, want about 90", got.TotalDays)
		}
		if !got.Standing {
			t.Error("a deferral running until next month does not read as standing")
		}
		if got.OccurrenceIdentity != "place-a" {
			t.Errorf("it names the occurrence %q", got.OccurrenceIdentity)
		}
	})
}

func TestSomethingPutOffOnceIsNotAPattern(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.putOff(t, "place-a", now, now.Add(30*24*time.Hour), triage.Approved)

		rows, _, err := f.store.RepeatsPage(t.Context(), f.triager, 0, triage.DefaultRepeatedAt, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("one deferral was listed as a pattern: %+v", rows)
		}
	})
}

func TestTimeTakenBackCountsForAsLongAsItHeld(t *testing.T) {
	// A withdrawal shortens the time something was put off; it does not erase
	// it. Erased, the pattern this list exists to show is invisible in it:
	// withdraw and defer again, each span under the line, for ever.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.putOff(t, "place-a", now.Add(-90*24*time.Hour), now.Add(-60*24*time.Hour), triage.Approved)
		// Asked for sixty days and taken back after thirty.
		f.putOffUntilTakenBack(t, "place-a", now.Add(-60*24*time.Hour),
			now.Add(-1*time.Hour), now.Add(-30*24*time.Hour))

		rows, _, err := f.store.RepeatsPage(t.Context(), f.triager, 0, 2, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("listed %d occurrences, want the one put off twice: %+v", len(rows), rows)
		}
		if rows[0].Times != 2 {
			t.Errorf("it says %d deferrals, want the two that held", rows[0].Times)
		}
		// Thirty days, then thirty of the sixty asked for.
		if rows[0].TotalDays < 55 || rows[0].TotalDays > 65 {
			t.Errorf("it says %.1f days, want about 60: the whole of the first and "+
				"the part of the second that ran", rows[0].TotalDays)
		}
	})
}

func TestADeferralTakenBackBeforeItHeldCountsForNothing(t *testing.T) {
	// The case the old exclusion was right about. Correcting a mistake is not
	// avoiding the work, and counting it would make the two look the same.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.putOff(t, "place-a", now.Add(-90*24*time.Hour), now.Add(-60*24*time.Hour), triage.Approved)
		from := now.Add(-60 * 24 * time.Hour)
		f.putOffUntilTakenBack(t, "place-a", from, now.Add(30*24*time.Hour), from)

		rows, _, err := f.store.RepeatsPage(t.Context(), f.triager, 0, 2, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("a deferral taken back before it held was counted: %+v", rows)
		}
	})
}

func TestSomebodyWhoHoldsNothingIsToldOfNoDeferrals(t *testing.T) {
	// The same rule as every list: an answer is over what the asker may
	// reach, and it is the data layer that decides.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.putOff(t, "place-a", now.Add(-60*24*time.Hour), now.Add(-30*24*time.Hour), triage.Approved)
		f.putOff(t, "place-a", now.Add(-30*24*time.Hour), now.Add(30*24*time.Hour), triage.Approved)

		stranger := access.NewPerson(99, "nobody@example.com", false, nil, 0)
		rows, _, err := f.store.RepeatsPage(t.Context(), stranger, 0, 2, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("somebody holding nothing was shown %d rows", len(rows))
		}
	})
}

// Two products a catalog displays alike are still two products.
//
// The grouping was on the display name, which carries no uniqueness rule —
// only the product's own name does, and that is not the one anybody reads. So
// one ordinary decision in each of two products merged into a single row
// reading as a repeated-deferral pattern, with a total summed across both.
func TestTwoProductsDisplayedAlikeAreNotOnePattern(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// A second product the catalog displays under the same words.
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "sonic-lite",
			fixtures.ProductDisplayName)
		if err != nil {
			t.Fatal(err)
		}
		if err := access.NewStore(f.db.DB).GrantRole(ctx, f.proposer, other.ID,
			access.PublicTriage); err != nil {
			t.Fatal(err)
		}

		now := time.Now().UTC()
		f.putOff(t, "place-a", now.Add(-60*24*time.Hour), now.Add(-30*24*time.Hour),
			triage.Approved)
		f.putOffIn(t, other.ID, "place-a", now.Add(-60*24*time.Hour),
			now.Add(-30*24*time.Hour), triage.Approved)

		// Re-read, because the grant is what decides which rows come back.
		who, err := access.NewStore(f.db.DB).Resolve(ctx, "proposer")
		if err != nil {
			t.Fatal(err)
		}
		rows, _, err := f.store.RepeatsPage(ctx, who, 0, 2, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("one deferral in each of two products read as a pattern: %+v", rows)
		}
	})
}

// putOffAtTwoVersions records one deferral decision with two rows at one occurrence,
// which is what one decision keyed at two upstream versions writes.
func (f *fixture) putOffAtTwoVersions(t *testing.T, occurrence string, from, until time.Time) {
	t.Helper()
	decision := &triage.Decision{
		Kind: triage.FindingDecision, ProposedBy: f.proposer, ProposedAt: from,
		Outcome: triage.Deferred, DeferredUntil: &until,
	}
	if _, err := f.db.DB.NewInsert().Model(decision).Exec(t.Context()); err != nil {
		t.Fatalf("record a decision: %v", err)
	}
	for _, version := range []string{"1.2.3", "1.2.4"} {
		live := fmt.Sprintf("%d|%s|%s", f.product, occurrence, version)
		row := &triage.DecisionOccurrence{
			DecisionID: decision.ID, ProductID: f.product, VulnerabilityID: f.issue,
			OccurrenceIdentity: occurrence, Visibility: access.Public, LiveKey: &live,
			State: triage.Approved, ProposedBy: f.proposer, ProposedAt: from,
		}
		if _, err := f.db.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
			t.Fatalf("record a deferral: %v", err)
		}
	}
}

func TestALapsedDeferralCountsForAsLongAsItHeldAndOverlapsCountOnce(t *testing.T) {
	// A lapse ends a deferral's effect the way a withdrawal does, so it counts
	// for as long as it held. Re-affirmed, the new decision carries the old
	// date: the occurrence was hidden from the first day to the date once, less
	// the day between, and never twice.
	each(t, func(t *testing.T, f *fixture) {
		// Midnight, because a deferral returns on a day and the servers keep
		// the date alone.
		now := time.Now().UTC().Truncate(24 * time.Hour)
		day := func(n int) time.Time { return now.Add(time.Duration(n-30) * 24 * time.Hour) }
		lapsed := day(5)
		f.putOffEnding(t, "place-a", day(0), day(25), triage.LapsedState, &lapsed)
		f.putOff(t, "place-a", day(6), day(25), triage.Approved)

		rows, _, err := f.store.RepeatsPage(t.Context(), f.triager, 0, 2, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("listed %d occurrences, want the one: %+v", len(rows), rows)
		}
		if rows[0].Times != 2 {
			t.Errorf("it says %d deferrals, want the two decisions", rows[0].Times)
		}
		if rows[0].TotalDays < 23.9 || rows[0].TotalDays > 24.1 {
			t.Errorf("it says %.1f days, want 24: five before the lapse and nineteen after",
				rows[0].TotalDays)
		}

		held, err := f.store.DeferredAt(t.Context(), f.triager, f.product, f.issue,
			[]string{"place-a"})
		if err != nil {
			t.Fatal(err)
		}
		if got := held["place-a"]; got != 24*24*time.Hour {
			t.Errorf("the threshold measures %v put off, want 24 days", got)
		}
	})
}

func TestOneDecisionAtTwoVersionsIsOneDeferral(t *testing.T) {
	// One decision keyed at two versions writes two rows over one stretch. It
	// put the occurrence off once.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC().Truncate(24 * time.Hour)
		f.putOff(t, "place-b", now.Add(-40*24*time.Hour), now.Add(-30*24*time.Hour), triage.Approved)
		f.putOffAtTwoVersions(t, "place-b", now.Add(-10*24*time.Hour), now.Add(10*24*time.Hour))

		rows, _, err := f.store.RepeatsPage(t.Context(), f.triager, 0, 2, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("listed %d occurrences, want the one: %+v", len(rows), rows)
		}
		if rows[0].Times != 2 {
			t.Errorf("it says %d deferrals, want the two decisions", rows[0].Times)
		}
		if rows[0].TotalDays < 29.9 || rows[0].TotalDays > 30.1 {
			t.Errorf("it says %.1f days, want 30", rows[0].TotalDays)
		}

		held, err := f.store.DeferredAt(t.Context(), f.triager, f.product, f.issue,
			[]string{"place-b"})
		if err != nil {
			t.Fatal(err)
		}
		if got := held["place-b"]; got != 30*24*time.Hour {
			t.Errorf("the threshold measures %v put off, want 30 days", got)
		}
	})
}
