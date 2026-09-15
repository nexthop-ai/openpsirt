package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestTheRecordCarriesWhoProposedAndWhoAgreed(t *testing.T) {
	// What an auditor asks for: the judgment, the words it rests on, and two
	// different people with the date each of them acted. Assembled for a page
	// rather than looked up one decision at a time, because the question is
	// about a period rather than about a row.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// A finding at the place, because a decision stores a hash of names
		// rather than the names — what it was about is recovered from a
		// finding sitting there.
		at := f.at()
		in := f.build(t, f.product, "for-the-record")
		f.finds(t, in, f.component(t, "libfoo", "1.2.3"), at.PlaceIdentity, access.Public)
		claimed := f.agreed(t, at)

		rows, total, err := f.store.Audit(ctx, f.reviewer, triage.Filter{},
			time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(rows) != 1 {
			t.Fatalf("the record holds %d judgments, want the one that was made", total)
		}
		row := rows[0]
		if row.ID != claimed.ID {
			t.Errorf("the record names decision %d, want %d", row.ID, claimed.ID)
		}
		if row.Reasoning == "" {
			t.Error("a judgment in the record carries no reasoning, which is the thing being audited")
		}
		if row.ProposedByName == "" || row.ProposedAt.IsZero() {
			t.Errorf("no record of who proposed it or when: %+v", row)
		}
		if len(row.Approvals) != 1 {
			t.Fatalf("%d agreements recorded, want 1", len(row.Approvals))
		}
		if row.Approvals[0].By == "" || row.Approvals[0].At.IsZero() {
			t.Errorf("no record of who agreed or when: %+v", row.Approvals[0])
		}
		if row.Approvals[0].By == row.ProposedByName {
			t.Errorf("the same person proposed and agreed: %q", row.Approvals[0].By)
		}
		// The control stated as a fact about this record rather than as a rule
		// that exists. A report that said the rule held because the rule
		// exists would be reporting on itself.
		if !row.BySomebodyElse() {
			t.Error("a judgment two people made does not read as one")
		}
		if !row.Standing() {
			t.Error("an agreed judgment does not read as standing")
		}
		// And what it was about, named from the finding at the place: a
		// decision stores a hash of names rather than the names.
		if row.Issue == "" || row.Component == "" || row.Product == "" {
			t.Errorf("the record does not say what the judgment was about: %+v", row)
		}
	})
}

func TestTheRecordKeepsAnAgreementThatWasTakenBack(t *testing.T) {
	// What somebody agreed to and then stopped agreeing to is exactly what
	// an audit is looking for, so a withdrawn approval is part of the
	// record rather than removed from it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.agreed(t, f.at())

		// Editing the words withdraws the agreement given for them.
		if _, err := f.store.Revise(ctx, f.triager, claimed.ClaimID,
			"On reflection, the parser is reachable after all."); err != nil {
			t.Fatal(err)
		}

		rows, _, err := f.store.Audit(ctx, f.reviewer, triage.Filter{},
			time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the record holds %d judgments", len(rows))
		}
		row := rows[0]
		if len(row.Approvals) != 1 {
			t.Fatalf("%d agreements recorded, want the one that was taken back", len(row.Approvals))
		}
		if row.Approvals[0].WithdrawnAt == nil {
			t.Error("an agreement withdrawn by a revision reads as still standing")
		}
		// And it no longer counts toward the control.
		if row.BySomebodyElse() {
			t.Error("a judgment whose only agreement was withdrawn still reads as two people's")
		}
		// The words shown are the words in force, so what is read and what was
		// agreed to cannot drift apart.
		if row.Reasoning != "On reflection, the parser is reachable after all." {
			t.Errorf("the record shows %q, want the revised words", row.Reasoning)
		}
	})
}

func TestTheExceptionReportIsTheOneExpectedToComeBackEmpty(t *testing.T) {
	// Filtered for judgments one person made, the answer is large and
	// entirely legitimate: an outcome that hides nothing needs no second
	// person. Read as "the exceptions", the filter proves the opposite of
	// what its name suggests.
	//
	// What it is for is showing that no *dismissal* sits in that
	// population. Not-applicable, will-not-fix and already-fixed all require
	// approval, so asked of one of those it should return nothing, and a
	// row in it is a control that failed.
	//
	// It is computed from the record rather than read back from a flag,
	// which is what makes asking it a test of the two-person rule rather
	// than of an assertion somebody made about it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.at()
		in := f.build(t, f.product, "for-the-record")
		f.finds(t, in, f.component(t, "libfoo", "1.2.3"), at.PlaceIdentity, access.Public)

		// A dismissal nobody has agreed to yet. It is a proposal rather than a
		// standing judgment, and that is exactly the state the report is for.
		claimed := f.claims(t, at)

		alone := triage.Filter{Alone: true, Outcomes: []triage.Outcome{triage.NotApplicable}}
		rows, total, err := f.store.Audit(ctx, f.reviewer, alone, time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(rows) != 1 || rows[0].ID != claimed.ID {
			t.Fatalf("the dismissal nobody agreed to is not in the exception report: %d rows", total)
		}

		// Agreed to by somebody else, and it leaves.
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		_, total, err = f.store.Audit(ctx, f.reviewer, alone, time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 0 {
			t.Errorf("a dismissal two people made is still in the exception report: %d rows", total)
		}

		// And an agreement taken back puts it back, which is the whole
		// reason the question is asked of the record rather than of a
		// flag set once. Revising the words withdraws the agreement
		// given for them, so this is the ordinary way it happens
		// rather than a contrivance.
		if _, err := f.store.Revise(ctx, f.triager, claimed.ClaimID,
			"On reading it again, the encoder does reach the parser."); err != nil {
			t.Fatal(err)
		}
		_, total, err = f.store.Audit(ctx, f.reviewer, alone, time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 {
			t.Errorf("a withdrawn agreement left the judgment out of the exception report")
		}

		// And an agreement from the proposer is not a second person, which is
		// the clause that matters and the one the write path makes
		// unreachable. Written straight to the table for that reason: the
		// report is computed from the record precisely so that it answers
		// correctly about rows the rules should have prevented, and a report
		// that trusted the write path would be reporting on itself.
		var revision struct {
			ID int64 `bun:"id"`
		}
		if err := f.db.DB.NewSelect().TableExpr(`"claim_revision" AS dr`).
			ColumnExpr("dr.id AS id").Where("dr.claim_id = ?", claimed.ClaimID).
			Order("dr.id DESC").Limit(1).Scan(ctx, &revision); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewInsert().TableExpr(`"claim_approval"`).
			Model(&map[string]any{
				"claim_id":    claimed.ClaimID,
				"revision_id": revision.ID,
				"approved_by": f.proposer,
				"approved_at": time.Now().UTC().Truncate(time.Microsecond),
			}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		_, total, err = f.store.Audit(ctx, f.reviewer, alone, time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 {
			t.Error("the proposer agreeing with themselves counted as a second person")
		}
	})
}

func TestTheRecordIsFoundByWhoActedAndWhatItWasAbout(t *testing.T) {
	// The four an auditor reaches for and none of which existed: who proposed
	// it, who agreed to it, which issue, and which component.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.at()
		in := f.build(t, f.product, "for-the-record")
		f.finds(t, in, f.component(t, "libfoo", "1.2.3"), at.PlaceIdentity, access.Public)
		f.agreed(t, at)

		counted := func(filter triage.Filter) int {
			t.Helper()
			_, total, err := f.store.Audit(ctx, f.reviewer, filter, time.Time{}, time.Time{}, 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return total
		}
		for _, each := range []struct {
			what string
			hit  triage.Filter
			miss triage.Filter
		}{
			{"proposer", triage.Filter{Proposer: "proposer"}, triage.Filter{Proposer: "approver"}},
			{"approver", triage.Filter{Approver: "approver"}, triage.Filter{Approver: "proposer"}},
			{"issue", triage.Filter{Issue: "CVE-2026-1"}, triage.Filter{Issue: "CVE-2026-9999"}},
			{"component", triage.Filter{Component: "libfoo"}, triage.Filter{Component: "libbar"}},
		} {
			if got := counted(each.hit); got != 1 {
				t.Errorf("filtering on the %s that matches found %d, want 1", each.what, got)
			}
			if got := counted(each.miss); got != 0 {
				t.Errorf("filtering on a %s that does not match found %d, want 0", each.what, got)
			}
		}
	})
}

func TestTheRecordNarrowsToSeveralOutcomesAndStatesAtOnce(t *testing.T) {
	// "Dismissed or deferred" and "waiting or agreed" are the questions
	// somebody reading the record actually has, and one value cannot ask
	// either — so asking them meant reading two lists in turn and adding them
	// up, which is a search dressed as an answer.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		soon := time.Now().UTC().Add(7 * 24 * time.Hour)

		// One dismissal, agreed to, and one short deferral that needed
		// nobody. Different outcomes and different states, so each filter has
		// something it excludes.
		dismissed := f.at()
		in := f.build(t, f.product, "for-the-record")
		f.finds(t, in, f.component(t, "libfoo", "1.2.3"), dismissed.PlaceIdentity, access.Public)
		f.agreed(t, dismissed)

		deferred := f.at()
		deferred.PlaceIdentity = "place-of-libfoo-under-libbaz"
		f.finds(t, in, f.component(t, "libbaz", "4.5.6"), deferred.PlaceIdentity, access.Public)
		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: deferred, Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Not this sprint.", By: f.proposer, NeedsApproval: false,
		}); err != nil {
			t.Fatal(err)
		}

		counted := func(filter triage.Filter) int {
			t.Helper()
			_, total, err := f.store.Audit(ctx, f.reviewer, filter, time.Time{}, time.Time{}, 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return total
		}
		for _, each := range []struct {
			what   string
			filter triage.Filter
			want   int
		}{
			{"nothing named", triage.Filter{}, 2},
			{"one outcome", triage.Filter{Outcomes: []triage.Outcome{triage.NotApplicable}}, 1},
			{"both outcomes", triage.Filter{
				Outcomes: []triage.Outcome{triage.NotApplicable, triage.Deferred},
			}, 2},
			{"an outcome nothing has", triage.Filter{
				Outcomes: []triage.Outcome{triage.WontFix},
			}, 0},
			{"one state", triage.Filter{States: []triage.State{triage.Approved}}, 1},
			{"both states", triage.Filter{
				States: []triage.State{triage.Approved, triage.Proposed},
			}, 2},
			{"one product", triage.Filter{ProductIDs: []int64{f.product}}, 2},
			{"a product nothing is in", triage.Filter{ProductIDs: []int64{f.product + 9999}}, 0},
			// Narrowing on two questions at once still means both, not
			// either: a set within a filter is an "or", and two filters are
			// an "and".
			{"both questions", triage.Filter{
				Outcomes: []triage.Outcome{triage.NotApplicable, triage.Deferred},
				States:   []triage.State{triage.Approved},
			}, 1},
		} {
			if got := counted(each.filter); got != each.want {
				t.Errorf("narrowing on %s found %d, want %d", each.what, got, each.want)
			}
		}
	})
}

func TestTheRecordIsNarrowedToWhatTheReaderMaySee(t *testing.T) {
	// Nothing about this view is exempt from the visibility rules. A report
	// showing more than the screens it summarizes would be a way around them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		hidden := f.at()
		hidden.Visibility = access.Private
		insider := f.privately(t)
		if _, err := f.store.Propose(ctx, insider, triage.Proposal{
			Place: hidden, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Reasoning:     "The parser is never reached.",
			By:            insider.ID, NeedsApproval: true,
		}); err != nil {
			t.Fatal(err)
		}

		// A public reader is shown nothing about it.
		if _, total, err := f.store.Audit(ctx, f.reviewer, triage.Filter{},
			time.Time{}, time.Time{}, 50, 0); err != nil || total != 0 {
			t.Errorf("an undisclosed judgment was in a public reader's record: %d (%v)", total, err)
		}
		// And somebody who may see it does, so the check above is not passing
		// on a record that shows nothing to anybody.
		if _, total, err := f.store.Audit(ctx, insider, triage.Filter{},
			time.Time{}, time.Time{}, 50, 0); err != nil || total != 1 {
			t.Errorf("somebody who may read it was shown %d judgments (%v)", total, err)
		}
	})
}

func TestTheRecordIsBoundedByWhenAJudgmentWasProposed(t *testing.T) {
	// The period is the proposal's date, not the approval's: a judgment
	// belongs to when it was argued, and dating it by its agreement would move
	// it out of the period it was made in whenever an approval came late,
	// which is the ordinary case.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.claims(t, f.at())

		before := claimed.ProposedAt.Add(-time.Hour)
		after := claimed.ProposedAt.Add(time.Hour)

		if _, total, err := f.store.Audit(ctx, f.reviewer, triage.Filter{},
			before, after, 50, 0); err != nil || total != 1 {
			t.Errorf("a judgment inside the period was not in the record: %d (%v)", total, err)
		}
		if _, total, err := f.store.Audit(ctx, f.reviewer, triage.Filter{},
			after, time.Time{}, 50, 0); err != nil || total != 0 {
			t.Errorf("a judgment proposed before the period was in it: %d (%v)", total, err)
		}
		if _, total, err := f.store.Audit(ctx, f.reviewer, triage.Filter{},
			time.Time{}, before, 50, 0); err != nil || total != 0 {
			t.Errorf("a judgment proposed after the period was in it: %d (%v)", total, err)
		}
	})
}

func TestTheRecordNamesOneFindingRatherThanTheLeastOfEach(t *testing.T) {
	// A decision is keyed on a place, and a place sits in more than one build:
	// the same pair of names at two components is the ordinary shape of a
	// version bump. A minimum per column over that set is five independent
	// answers, so the row named a component, a version and a consumer that no
	// finding ever had — which is exactly what an auditor cannot check.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.at()
		first := f.build(t, f.product, "2026.03")
		second := f.build(t, f.product, "2026.06")
		// The earliest row is libfoo; the alphabetically-least component name
		// and the least version belong to the other one.
		f.finds(t, first, f.component(t, "libfoo", "9.9.9"), at.PlaceIdentity, access.Public)
		f.finds(t, second, f.component(t, "libbar", "1.0.0"), at.PlaceIdentity, access.Public)
		f.agreed(t, at)

		rows, _, err := f.store.Audit(ctx, f.reviewer, triage.Filter{},
			time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the record holds %d judgments, want the one", len(rows))
		}
		if rows[0].Component != "libfoo" || rows[0].Version != "9.9.9" {
			t.Errorf("the record says %q at %q, which is not a pair any finding had",
				rows[0].Component, rows[0].Version)
		}
	})
}
