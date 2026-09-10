package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// putOff records one deferral at a place, from a moment until a moment.
//
// Written directly rather than proposed through the store: what is under test
// is the report, and reaching three deferrals at one place through the normal
// path means three approvals and two supersessions, none of which this is
// about.
func (f *fixture) putOff(t *testing.T, place string, from, until time.Time, state triage.State) {
	t.Helper()
	// Every decision belongs to a claim, even one covering a single place, so
	// the report reads the same rows a real deferral produces.
	// What it says is the claim's; where it lands is the row's.
	claim := &triage.Claim{
		Kind: triage.FindingClaim, ProposedBy: f.proposer, ProposedAt: from,
		Outcome: triage.Deferred, DeferredUntil: &until,
	}
	if _, err := f.db.DB.NewInsert().Model(claim).Exec(t.Context()); err != nil {
		t.Fatalf("record a claim: %v", err)
	}
	live := place + until.Format(time.RFC3339Nano)
	row := &triage.Decision{
		ClaimID: claim.ID, ProductID: f.product, VulnerabilityID: f.issue,
		PlaceIdentity: place, Visibility: access.Public,
		State: state, ProposedBy: f.proposer, ProposedAt: from,
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

		rows, err := f.store.Repeats(t.Context(), f.triager, 0, 2, 100)
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

		rows, err := f.store.Repeats(t.Context(), f.triager, 0, triage.DefaultRepeatedAt, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("one deferral was listed as a pattern: %+v", rows)
		}
	})
}

func TestTimeTakenBackIsNotTimeSomethingWasPutOff(t *testing.T) {
	// A withdrawn deferral is a judgment somebody retracted. Counting it would
	// make taking a decision back look like avoiding the work.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.putOff(t, "place-a", now.Add(-60*24*time.Hour), now.Add(-30*24*time.Hour), triage.Approved)
		f.putOff(t, "place-a", now.Add(-30*24*time.Hour), now.Add(30*24*time.Hour), triage.Withdrawn)

		rows, err := f.store.Repeats(t.Context(), f.triager, 0, 2, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("a withdrawn deferral was counted toward the pattern: %+v", rows)
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
		rows, err := f.store.Repeats(t.Context(), stranger, 0, 2, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("somebody holding nothing was shown %d rows", len(rows))
		}
	})
}
