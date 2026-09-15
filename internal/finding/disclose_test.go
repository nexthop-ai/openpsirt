package finding_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAnEmbargoGetsAnEndAndIsSurfacedBeforeItArrives(t *testing.T) {
	// An embargo with no end is the indefinite secrecy the disclosure
	// frameworks warn about, arrived at by nobody deciding anything. And
	// the date arriving is the last moment to act on it, not the first
	// useful warning — a list that only ever showed what was already past
	// would be a list of decisions somebody has already failed to make.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)

		rows, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Severity: "high",
			Summary: "The management socket answers before anyone authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		row := rows[0]
		if err != nil {
			t.Fatal(err)
		}
		if row.DiscloseAt == nil {
			t.Fatal("an undisclosed finding has no end to its embargo")
		}
		if got := row.DiscloseAt.Sub(row.OpenedAt); (got - 90*24*time.Hour).Abs() > time.Minute {
			t.Errorf("the embargo runs %s, want the ninety days a deployment starts with", got)
		}

		// A month out it is not on a thirty-day list yet, because ninety days
		// is further away than that.
		soon, err := f.store.Disclosing(t.Context(), who, finding.Scope{},
			30*24*time.Hour, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(soon) != 0 {
			t.Errorf("something ninety days out is on a thirty-day list: %+v", soon)
		}

		// Wider than the embargo, and it is there — before the date, with what
		// somebody needs to act on it.
		ahead, err := f.store.Disclosing(t.Context(), who, finding.Scope{},
			120*24*time.Hour, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(ahead) != 1 {
			t.Fatalf("%d findings are approaching disclosure, want 1", len(ahead))
		}
		if ahead[0].Summary == "" || ahead[0].Product == "" || ahead[0].Component == "" {
			t.Errorf("the row does not say enough to act on: %+v", ahead[0])
		}
		if ahead[0].Passed(time.Now().UTC()) {
			t.Error("a date ninety days away reads as passed")
		}

		// A disclosed finding carries no date: it is already public, and a
		// date on it would be a deadline for something that has happened.
		discloseds, _, err := f.store.Enter(t.Context(), f.planner(t, access.PrivateTriage),
			finding.Entering{
				TargetIDs: []int64{f.target}, Severity: "high", Disclosed: true,
				Summary: "Already announced.",
			})
		if err != nil {
			t.Fatal(err)
		}
		disclosed := discloseds[0]
		if err != nil {
			t.Fatal(err)
		}
		if disclosed.DiscloseAt != nil {
			t.Errorf("a public finding carries an embargo ending %s", disclosed.DiscloseAt)
		}
	})
}

func TestWhatIsApproachingDisclosureIsItselfUndisclosed(t *testing.T) {
	// Every row on this list is a finding nobody has announced, so the list is
	// a disclosure in its own right. Somebody who may not read undisclosed
	// work in a product sees none of that product's — and a count would say as
	// much as a row.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, _, err := f.store.Enter(t.Context(), f.planner(t, access.PrivateTriage),
			finding.Entering{
				TargetIDs: []int64{f.target}, Severity: "critical",
				Summary: "Something nobody outside knows about.",
			}); err != nil {
			t.Fatal(err)
		}

		for _, role := range []access.Role{access.PublicRead, access.PublicTriage} {
			rows, err := f.store.Disclosing(t.Context(), f.planner(t, role),
				finding.Scope{}, 365*24*time.Hour, 50)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Errorf("somebody holding %s was shown %d undisclosed findings", role, len(rows))
			}
		}

		rows, err := f.store.Disclosing(t.Context(), f.planner(t, access.PrivateRead),
			finding.Scope{}, 365*24*time.Hour, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Errorf("somebody who may read undisclosed work sees %d, want 1", len(rows))
		}
	})
}

// embargoed records an undisclosed flaw and returns the issue it was filed as.
func (f *fixture) embargoed(t *testing.T, who access.Subject) int64 {
	t.Helper()
	rows, _, err := f.store.Enter(t.Context(), who, finding.Entering{
		TargetIDs: []int64{f.target}, Severity: "high",
		Summary: "Not announced anywhere yet.",
	})
	if err != nil {
		t.Fatal(err)
	}
	row := rows[0]
	if err != nil {
		t.Fatal(err)
	}
	return row.VulnerabilityID
}

// endsAt is where this issue's embargo currently ends.
func (f *fixture) endsAt(t *testing.T, issue int64) time.Time {
	t.Helper()
	var at time.Time
	if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
		ColumnExpr("MAX(disclose_at)").
		Where("vulnerability_id = ?", issue).Scan(t.Context(), &at); err != nil {
		t.Fatal(err)
	}
	return at
}

func TestAShortExtensionStandsAndALongOneWaits(t *testing.T) {
	// and the same shape as a deferral because it is the same act: keeping
	// risk hidden for longer. A short one is ordinary triage and gating it
	// would put every routine act through a queue; past the threshold it
	// needs a second person.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		issue := f.embargoed(t, who)
		was := f.endsAt(t, issue)

		// A week. Under the thirty-day threshold, so it stands on its own and
		// the date moves.
		short, err := f.store.Extend(t.Context(), who, f.productID, issue,
			was.Add(7*24*time.Hour), "The fix missed the release train.")
		if err != nil {
			t.Fatal(err)
		}
		if short.NeedsApproval {
			t.Error("a week's extension was sent to a queue")
		}
		if got := f.endsAt(t, issue); !got.Equal(was.Add(7 * 24 * time.Hour)) {
			t.Errorf("the embargo ends %s, want it moved by a week to %s",
				got, was.Add(7*24*time.Hour))
		}

		// Another four weeks. Measured against what it has already been moved
		// by, this crosses the line — which is the whole point: measured per
		// request the exception swallows the rule three weeks at a time.
		now := f.endsAt(t, issue)
		long, err := f.store.Extend(t.Context(), who, f.productID, issue,
			now.Add(28*24*time.Hour), "Upstream has not answered.")
		if err != nil {
			t.Fatal(err)
		}
		if !long.NeedsApproval {
			t.Error("five weeks in total stood on one person's say-so")
		}
		// And nothing moved. An embargo that ran on while somebody thought
		// about it would be the extension taking effect anyway.
		if got := f.endsAt(t, issue); !got.Equal(now) {
			t.Errorf("the embargo moved to %s while the request was still waiting", got)
		}

		// The person who asked may not be the one who agrees.
		if err := f.store.AgreeToExtension(t.Context(), who, long.ID); err == nil {
			t.Error("somebody agreed to their own extension")
		}
		other := f.someoneElse(t, access.PrivateTriage)
		if err := f.store.AgreeToExtension(t.Context(), other, long.ID); err != nil {
			t.Fatal(err)
		}
		if got := f.endsAt(t, issue); !got.Equal(now.Add(28 * 24 * time.Hour)) {
			t.Errorf("after agreement the embargo ends %s, want %s",
				got, now.Add(28*24*time.Hour))
		}

		// And a third person agreeing is told it has already been agreed to,
		// and the date does not move again.
		//
		// **This is the read's answer, not the write's.** The row is read
		// before the update and the second agreement is refused there. What
		// the update's own `approved_at IS NULL` clause guards is the race —
		// two people agreeing between that read and that write — and the
		// count it produces is now reported rather than discarded, which is
		// what makes the clause say something. Forcing that interleave needs
		// the barrier `internal/catalog/race_test.go` is written against, and
		// is not covered here.
		third := f.someoneElse(t, access.PrivateTriage)
		if err := f.store.AgreeToExtension(t.Context(), third, long.ID); !errors.Is(
			err, finding.ErrAlreadyAgreed) {
			t.Errorf("agreeing a second time answered %v, want ErrAlreadyAgreed", err)
		}
		if got := f.endsAt(t, issue); !got.Equal(now.Add(28 * 24 * time.Hour)) {
			t.Errorf("a second agreement moved the embargo again, to %s", got)
		}
	})
}

func TestAnExtensionSaysWhyAndOnlyEverMovesForward(t *testing.T) {
	// An extension with no reason is the record saying somebody moved it and
	// nothing else, which is the state the whole history exists to prevent.
	// And "extension" means later: bringing a date forward is disclosing
	// sooner, which is a different act and not this one.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		issue := f.embargoed(t, who)
		was := f.endsAt(t, issue)

		if _, err := f.store.Extend(t.Context(), who, f.productID, issue,
			was.Add(24*time.Hour), "  "); err == nil {
			t.Error("an embargo was extended for no stated reason")
		}
		if _, err := f.store.Extend(t.Context(), who, f.productID, issue,
			was.Add(-24*time.Hour), "Bringing it forward."); !errors.Is(err, finding.ErrBackwards) {
			t.Errorf("a date was moved earlier by an extension: %v", err)
		}
		// Somebody who may not see undisclosed work cannot move one either.
		if _, err := f.store.Extend(t.Context(), f.planner(t, access.PublicTriage),
			f.productID, issue, was.Add(24*time.Hour), "Because."); err == nil {
			t.Error("somebody holding only public triage moved an embargo")
		}

		// Every attempt that took effect is kept, and so is one still waiting.
		if _, err := f.store.Extend(t.Context(), who, f.productID, issue,
			was.Add(3*24*time.Hour), "Two more days of testing."); err != nil {
			t.Fatal(err)
		}
		history, err := f.store.Extensions(t.Context(), who, f.productID, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(history) != 1 {
			t.Fatalf("%d extensions on record, want the one that happened", len(history))
		}
		if history[0].Reason == "" || !history[0].Was.Equal(was) {
			t.Errorf("the record does not say what was moved or why: %+v", history[0])
		}
	})
}
