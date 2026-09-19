package triage_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// putOffUntilTakenBack records a deferral that was withdrawn on a date, which
// is what decides how much of what it asked for it actually held.
func (f *fixture) putOffUntilTakenBack(t *testing.T, place string, from, until,
	takenBack time.Time) {

	t.Helper()
	f.putOffEnding(t, place, from, until, triage.Withdrawn, &takenBack)
}

// putOff records one deferral at a place, from a moment until a moment.
//
// Written directly rather than proposed through the store: what is under test
// is the report, and reaching three deferrals at one place through the normal
// path means three approvals and two supersessions, none of which this is
// about.
func (f *fixture) putOff(t *testing.T, place string, from, until time.Time, state triage.State) {
	t.Helper()
	f.putOffEnding(t, place, from, until, state, nil)
}

// putOffIn is putOff against a product other than the fixture's own.
func (f *fixture) putOffIn(t *testing.T, product int64, place string, from, until time.Time,
	state triage.State) {

	t.Helper()
	f.putOffAt(t, product, place, from, until, state, nil)
}

func (f *fixture) putOffEnding(t *testing.T, place string, from, until time.Time,
	state triage.State, endedAt *time.Time) {

	t.Helper()
	f.putOffAt(t, f.product, place, from, until, state, endedAt)
}

func (f *fixture) putOffAt(t *testing.T, product int64, place string, from, until time.Time,
	state triage.State, endedAt *time.Time) {
	t.Helper()
	// Every decision belongs to a claim, even one covering a single place, so
	// the report reads the same rows a real deferral produces.
	// The words are the claim's; the landing place is the row's.
	claim := &triage.Claim{
		Kind: triage.FindingClaim, ProposedBy: f.proposer, ProposedAt: from,
		Outcome: triage.Deferred, DeferredUntil: &until,
	}
	if _, err := f.db.DB.NewInsert().Model(claim).Exec(t.Context()); err != nil {
		t.Fatalf("record a claim: %v", err)
	}
	// The key carries the product, as a real one does: two products may hold
	// the same place and both may be decided about.
	live := fmt.Sprintf("%d\x00%s%s", product, place, until.Format(time.RFC3339Nano))
	row := &triage.Decision{
		ClaimID: claim.ID, ProductID: product, VulnerabilityID: f.issue,
		PlaceIdentity: place, Visibility: access.Public,
		State: state, ProposedBy: f.proposer, ProposedAt: from, EndedAt: endedAt,
	}
	if state != triage.Withdrawn {
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
		// One place put off twice, another once.
		f.putOff(t, "place-a", now.Add(-60*24*time.Hour), now.Add(-30*24*time.Hour), triage.Approved)
		f.putOff(t, "place-a", now.Add(-30*24*time.Hour), now.Add(30*24*time.Hour), triage.Approved)
		f.putOff(t, "place-b", now.Add(-10*24*time.Hour), now.Add(20*24*time.Hour), triage.Approved)

		rows, _, err := f.store.Repeats(t.Context(), f.triager, 0, 2, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("listed %d places, want the one put off more than once: %+v", len(rows), rows)
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
		if got.PlaceIdentity != "place-a" {
			t.Errorf("it names the place %q", got.PlaceIdentity)
		}
	})
}

func TestSomethingPutOffOnceIsNotAPattern(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.putOff(t, "place-a", now, now.Add(30*24*time.Hour), triage.Approved)

		rows, _, err := f.store.Repeats(t.Context(), f.triager, 0, triage.DefaultRepeatedAt, 100)
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

		rows, _, err := f.store.Repeats(t.Context(), f.triager, 0, 2, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("listed %d places, want the one put off twice: %+v", len(rows), rows)
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

		rows, _, err := f.store.Repeats(t.Context(), f.triager, 0, 2, 100)
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
		rows, _, err := f.store.Repeats(t.Context(), stranger, 0, 2, 100)
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
// one ordinary judgment in each of two products merged into a single row
// reading as a repeated-deferral pattern, with a total summed across both.
func TestTwoProductsDisplayedAlikeAreNotOnePattern(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// A second product the catalog displays under the same words.
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "sonic-lite", "SONiC")
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
		rows, _, err := f.store.Repeats(ctx, who, 0, 2, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("one deferral in each of two products read as a pattern: %+v", rows)
		}
	})
}
