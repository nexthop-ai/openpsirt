// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// flaw records a flaw in the fixture's build, told as given, and returns its
// issue.
func (f *fixture) flaw(t *testing.T, who access.Subject, told finding.Told) int64 {
	t.Helper()
	f.shipped(t, twoConsumers())
	rows, _, err := f.store.Enter(t.Context(), who, finding.Entering{
		TargetIDs: []int64{f.target}, Severity: "high",
		Summary: "The management socket answers before anyone authenticated.",
		Told:    told,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows[0].VulnerabilityID
}

// claim records a claim told as given and returns its reference.
func (f *fixture) claim(t *testing.T, who access.Subject, told finding.Told) string {
	t.Helper()
	row, err := f.store.Record(t.Context(), who, f.productID, finding.Claimed{
		Summary: "The management socket lets anybody in.", Told: told,
	})
	if err != nil {
		t.Fatal(err)
	}
	return row.Reference
}

// duplicate rules claims a duplicate of an issue.
func (f *fixture) duplicate(t *testing.T, who access.Subject, issue int64,
	references ...string) *finding.ReportRuling {

	t.Helper()
	ruling, err := f.store.Rule(t.Context(), who, f.productID, finding.Ruled{
		References: references, Disposition: finding.Duplicate, DuplicateOf: issue,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ruling
}

// flawEnds is where the embargo ends on every open place of an issue, failing
// where two places disagree.
func (f *fixture) flawEnds(t *testing.T, issue int64) *time.Time {
	t.Helper()
	var rows []finding.Finding
	if err := f.db.DB.NewSelect().Model(&rows).
		Where("vulnerability_id = ?", issue).
		Where("closed_at IS NULL").
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("the issue has no open place")
	}
	for _, row := range rows[1:] {
		if !sameInstant(row.DiscloseAt, rows[0].DiscloseAt) {
			t.Fatalf("two places end on %v and %v", rows[0].DiscloseAt, row.DiscloseAt)
		}
	}
	return rows[0].DiscloseAt
}

// windowAfter is a day's midnight plus the disclosure window.
func (f *fixture) windowAfter(t *testing.T, day string) time.Time {
	t.Helper()
	arrived, err := time.Parse(time.DateOnly, day)
	if err != nil {
		t.Fatal(err)
	}
	window, err := setting.NewStore(f.db.DB).Duration(t.Context(),
		setting.DiscloseAfter, setting.DefaultDiscloseAfter)
	if err != nil {
		t.Fatal(err)
	}
	return arrived.Add(window)
}

// movedBy reads an embargo's record, oldest first.
func (f *fixture) movedBy(t *testing.T, who access.Subject, issue int64) []finding.Movement {
	t.Helper()
	rows, err := f.store.Movements(t.Context(), who, f.productID, issue)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestADuplicateFromOutsideStartsTheDateOnAFlawFoundHere(t *testing.T) {
	// The reporter publishes on their own clock whoever found the flaw first,
	// and it started when the earliest of them told us.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{FoundHere: true})
		later := f.claim(t, who, finding.Told{Received: "2026-09-05"})
		earlier := f.claim(t, who, finding.Told{Received: "2026-09-01"})

		ruling := f.duplicate(t, who, issue, later, earlier)
		want := f.windowAfter(t, "2026-09-01")
		if got := f.flawEnds(t, issue); !isAt(got, want) {
			t.Errorf("the flaw ends %v, want %s", got, want)
		}
		moved := f.movedBy(t, who, issue)
		if len(moved) != 1 {
			t.Fatalf("%d movements recorded, want the one the ruling made", len(moved))
		}
		row := moved[0]
		if row.Act != finding.Duplicated || row.Was != nil || !isAt(row.Until, want) ||
			row.RulingID == nil || *row.RulingID != ruling.ID || row.Report != earlier {
			t.Errorf("the movement is %s from %v to %v by ruling %v counting from %q, "+
				"want duplicate from none to %s by %d counting from %s",
				row.Act, row.Was, row.Until, row.RulingID, row.Report, want, ruling.ID, earlier)
		}
		if row.InForce() != true || row.NeedsApproval {
			t.Error("a date a ruling started waits for a second person")
		}
	})
}

func TestAClaimFoundHereStartsNoDate(t *testing.T) {
	// Nobody outside is counting down to a publication.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{FoundHere: true})
		f.duplicate(t, who, issue, f.claim(t, who, finding.Told{FoundHere: true, Received: "2026-09-01"}))
		if got := f.flawEnds(t, issue); got != nil {
			t.Errorf("a claim found here dated the flaw %s", got)
		}
		if moved := f.movedBy(t, who, issue); len(moved) != 0 {
			t.Errorf("a claim found here recorded %+v", moved)
		}
	})
}

func TestAClaimNotSayingWhenItArrivedCountsFromWhenItWasRecorded(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{FoundHere: true})
		reference := f.claim(t, who, finding.Told{ReportedBy: "a researcher"})
		recorded := f.reportNamed(t, who, reference).RecordedAt
		f.duplicate(t, who, issue, reference)
		window, err := setting.NewStore(f.db.DB).Duration(t.Context(),
			setting.DiscloseAfter, setting.DefaultDiscloseAfter)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := f.flawEnds(t, issue), recorded.Add(window); !isAt(got, want) {
			t.Errorf("the flaw ends %v, want %s", got, want)
		}
	})
}

func TestADuplicateMovesADateOnlyEarlier(t *testing.T) {
	// An end already earlier is one somebody is held to. An earlier claim
	// brings a later end in, and says where it was.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{Received: "2026-06-01"})
		first := f.windowAfter(t, "2026-06-01")

		f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-07-01"}))
		if got := f.flawEnds(t, issue); !isAt(got, first) {
			t.Errorf("a later claim moved the flaw to %v, want it kept at %s", got, first)
		}
		if moved := f.movedBy(t, who, issue); len(moved) != 0 {
			t.Errorf("a claim that moved nothing recorded %+v", moved)
		}

		// Twelve days in, well inside the thirty-day threshold, so in force.
		ruling := f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-05-20"}))
		want := f.windowAfter(t, "2026-05-20")
		if got := f.flawEnds(t, issue); !isAt(got, want) {
			t.Errorf("an earlier claim left the flaw at %v, want %s", got, want)
		}
		moved := f.movedBy(t, who, issue)
		if len(moved) != 1 || !isAt(moved[0].Was, first) || *moved[0].RulingID != ruling.ID ||
			moved[0].NeedsApproval {
			t.Errorf("recorded %+v, want one movement in force from %s by ruling %d",
				moved, first, ruling.ID)
		}

		// The twelve days count toward the threshold as a shortening's do: a
		// twenty-day extension after them is past thirty.
		asked, err := f.store.Extend(t.Context(), who, f.productID, issue,
			want.Add(20*24*time.Hour), "The fix slipped.")
		if err != nil {
			t.Fatal(err)
		}
		if !asked.NeedsApproval {
			t.Error("an extension past the threshold, counting the ruling's shortening, needs nobody")
		}
	})
}

func TestADuplicateBringingADateEarlierPastTheThresholdWaitsForASecondPerson(t *testing.T) {
	// Bringing an existing date in is a shortening, whoever brings it in: past
	// the threshold, the date stays until somebody else agrees.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		second := f.somebody(t, "second@example.com", access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{Received: "2026-06-01"})
		first := f.windowAfter(t, "2026-06-01")

		f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-04-01"}))
		if got := f.flawEnds(t, issue); !isAt(got, first) {
			t.Errorf("a shortening waiting for agreement moved the flaw to %v", got)
		}
		moved := f.movedBy(t, who, issue)
		if len(moved) != 1 || !moved[0].NeedsApproval || moved[0].InForce() {
			t.Fatalf("recorded %+v, want one movement waiting for a second person", moved)
		}
		if _, err := f.store.AgreeToMovement(t.Context(), who, moved[0].ID); !errors.Is(err, finding.ErrSamePerson) {
			t.Errorf("the ruling's proposer agreeing was answered %v", err)
		}
		if _, err := f.store.AgreeToMovement(t.Context(), second, moved[0].ID); err != nil {
			t.Fatal(err)
		}
		if got, want := f.flawEnds(t, issue), f.windowAfter(t, "2026-04-01"); !isAt(got, want) {
			t.Errorf("agreed, the flaw ends %v, want %s", got, want)
		}
	})
}

func TestAWaitingShortenedDateCannotBeAgreedOnceItsRulingIsWithdrawn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		second := f.somebody(t, "second@example.com", access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{Received: "2026-06-01"})
		ruling := f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-04-01"}))
		moved := f.movedBy(t, who, issue)
		if _, err := f.store.WithdrawRuling(t.Context(), who, f.productID, ruling.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AgreeToMovement(t.Context(), second, moved[0].ID); !errors.Is(err, finding.ErrWithdrawn) {
			t.Errorf("agreeing to a withdrawn ruling's shortening was answered %v", err)
		}
		waiting, _, err := f.store.PendingPage(t.Context(), second, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 0 {
			t.Errorf("a withdrawn ruling's shortening is still waiting: %+v", waiting)
		}
		if got := f.flawEnds(t, issue); !isAt(got, f.windowAfter(t, "2026-06-01")) {
			t.Errorf("the flaw ends %v, want the date it had", got)
		}
	})
}

func TestWithdrawingADuplicatePutsTheDateBackWhereTheRestLeaveIt(t *testing.T) {
	// Two duplicates date one flaw found here. Withdrawing the one whose date
	// the other overtook moves nothing; withdrawing the other leaves the flaw
	// with no date, because neither ruling still stands.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{FoundHere: true})
		// A disclosure asked of the flaw while it had no date, still waiting,
		// which records today as where the embargo stood.
		if _, err := f.store.Disclose(t.Context(), who, f.productID, issue,
			"Fixed in every release."); err != nil {
			t.Fatal(err)
		}
		overtaken := f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-08-01"}))
		standing := f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-07-20"}))
		earlier := f.windowAfter(t, "2026-07-20")

		if _, err := f.store.WithdrawRuling(t.Context(), who, f.productID, overtaken.ID); err != nil {
			t.Fatal(err)
		}
		if got := f.flawEnds(t, issue); !isAt(got, earlier) {
			t.Errorf("withdrawing a duplicate another overtook moved the flaw to %v", got)
		}
		if moved := f.movedBy(t, who, issue); len(moved) != 3 {
			t.Errorf("withdrawing a duplicate that set nothing still standing recorded %+v", moved)
		}

		if _, err := f.store.WithdrawRuling(t.Context(), who, f.productID, standing.ID); err != nil {
			t.Fatal(err)
		}
		if got := f.flawEnds(t, issue); got != nil {
			t.Errorf("with every duplicate withdrawn the flaw still ends %s", got)
		}
		moved := f.movedBy(t, who, issue)
		last := moved[len(moved)-1]
		if last.Act != finding.Unduplicated || !isAt(last.Was, earlier) || last.Until != nil ||
			*last.RulingID != standing.ID {
			t.Errorf("the withdrawal recorded %s from %v to %v by ruling %v, "+
				"want duplicate-undone from %s to none by %d",
				last.Act, last.Was, last.Until, last.RulingID, earlier, standing.ID)
		}
	})
}

func TestWithdrawingADuplicateKeepsADateAPersonSetSince(t *testing.T) {
	// The ruling set the date and somebody moved it after. What stands is
	// theirs, and the ruling going takes nothing of it back.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{FoundHere: true})
		ruling := f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-08-01"}))
		extended := f.windowAfter(t, "2026-08-01").Add(10 * 24 * time.Hour)
		if _, err := f.store.Extend(t.Context(), who, f.productID, issue, extended,
			"The fix slipped a week."); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.WithdrawRuling(t.Context(), who, f.productID, ruling.ID); err != nil {
			t.Fatal(err)
		}
		if got := f.flawEnds(t, issue); !isAt(got, extended) {
			t.Errorf("the flaw ends %v, want the %s somebody extended it to", got, extended)
		}
	})
}

func TestADuplicateOfAScannedIssueStartsNoDate(t *testing.T) {
	// A scanned issue is published by whoever published its advisory, so no
	// reporter is counting down to it here, even at a place held undisclosed.
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.anIssueHereShipped(t, who)
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Private).
			Where("vulnerability_id = ?", issue).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-09-01"}))
		if got := f.flawEnds(t, issue); got != nil {
			t.Errorf("a duplicate of a scanned issue dated it %s", got)
		}
	})
}

func TestTheRulingFormIsToldTheDateADuplicateWouldStart(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{FoundHere: true})
		named := f.claim(t, who, finding.Told{Received: "2026-09-01"})

		starts, err := f.store.DuplicateStarts(t.Context(), who, f.productID, issue, []string{named})
		if err != nil {
			t.Fatal(err)
		}
		want := f.windowAfter(t, "2026-09-01")
		if starts == nil || !starts.At.Equal(want) || starts.NeedsApproval {
			t.Errorf("the form is told %+v, want %s taking effect at once", starts, want)
		}
		if got := f.flawEnds(t, issue); got != nil {
			t.Errorf("asking what a ruling would start dated the flaw %s", got)
		}

		// Ruled, the same claim again would start nothing.
		f.duplicate(t, who, issue, named)
		if starts, err := f.store.DuplicateStarts(t.Context(), who, f.productID, issue,
			[]string{f.claim(t, who, finding.Told{Received: "2026-09-10"})}); err != nil || starts != nil {
			t.Errorf("a later claim would start %v (%v), want nothing", starts, err)
		}
		// Two months earlier brings the date in past the threshold, which
		// waits for a second person.
		if early, err := f.store.DuplicateStarts(t.Context(), who, f.productID, issue,
			[]string{f.claim(t, who, finding.Told{Received: "2026-07-01"})}); err != nil ||
			early == nil || !early.NeedsApproval {
			t.Errorf("a claim two months earlier would start %+v (%v), want it to wait", early, err)
		}

		// Asked under the rule proposing the ruling is.
		reader := f.somebody(t, "reader@example.com", access.PrivateRead)
		if _, err := f.store.DuplicateStarts(t.Context(), reader, f.productID, issue,
			[]string{named}); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody who may not rule was answered %v", err)
		}
	})
}
