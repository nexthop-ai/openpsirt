// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// ends puts one row of a decision where a lapse leaves it: ended at a moment,
// holding no live key.
func (f *fixture) ends(t *testing.T, occurrenceID int64, at time.Time) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Model((*triage.DecisionOccurrence)(nil)).
		Set(`"state" = ?`, triage.LapsedState).
		Set(`"live_key" = ?`, nil).
		Set(`"ended_at" = ?`, at).
		Where(`"id" = ?`, occurrenceID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// row reads one decision occurrence back as stored.
func (f *fixture) row(t *testing.T, id int64) triage.DecisionOccurrence {
	t.Helper()
	var row triage.DecisionOccurrence
	if err := f.db.DB.NewSelect().Model(&row).Where(`"de"."id" = ?`, id).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestUndoingAnApprovalLeavesARowThatHasEndedAlone(t *testing.T) {
	// A lapse leaves the approval standing, so the decision is still in the
	// batch. Returned to waiting, the lapsed row would be a proposal holding
	// no live key, which nothing stops a contradicting decision from joining.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		made := f.decisionsMany(t, f.occurrences("under-a", "under-b"))
		if err := agreeTo(ctx, f.store, f.reviewer, made[0].DecisionID, "one-afternoon"); err != nil {
			t.Fatal(err)
		}
		ended := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		f.ends(t, made[1].ID, ended)

		undone, err := f.store.UndoBatch(ctx, f.reviewer, "one-afternoon")
		if err != nil {
			t.Fatal(err)
		}
		if undone.Rows != 1 {
			t.Errorf("%d rows returned to waiting, want the one still standing", undone.Rows)
		}
		if got := f.row(t, made[0].ID); got.State != triage.Proposed {
			t.Errorf("the standing row is %q, want it waiting again", got.State)
		}
		lapsed := f.row(t, made[1].ID)
		if lapsed.State != triage.LapsedState || lapsed.LiveKey != nil {
			t.Errorf("the lapsed row became %q holding key %v", lapsed.State, lapsed.LiveKey)
		}
	})
}

func TestRevivingADecisionWhoseOccurrenceIsTakenNamesTheDecisionStandingThere(t *testing.T) {
	// Revising a withdrawn decision retakes its occurrences. Where another decision
	// holds one since, the refusal is the one proposing there gets.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := f.decisions(t, f.at())
		if _, err := f.store.Withdraw(ctx, f.triager, first.DecisionID); err != nil {
			t.Fatal(err)
		}
		standing := f.decisions(t, f.at())

		_, err := f.store.Revise(ctx, f.triager, first.DecisionID, "On reflection it holds.")
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("reviving onto a taken occurrence answered %v, want it already decided", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("decision occurrence %d ", standing.ID)) {
			t.Errorf("the refusal %q does not name decision occurrence %d", err, standing.ID)
		}
	})
}

func TestRevivingAPartlyEndedDecisionNamesTheDecisionAtTheTakenOccurrence(t *testing.T) {
	// One occurrence of two lapsed and another decision took it. The refusal names
	// that decision's row, never the reviving decision's own row still standing at
	// the other occurrence.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		made := f.decisionsMany(t, f.occurrences("under-a", "under-b"))
		f.ends(t, made[1].ID, time.Now().UTC().Truncate(time.Microsecond))
		standing := f.decisions(t, f.occurrences("under-b")[0])

		_, err := f.store.Revise(ctx, f.triager, made[0].DecisionID, "On reflection it holds.")
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("reviving onto a taken occurrence answered %v, want it already decided", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("decision occurrence %d ", standing.ID)) {
			t.Errorf("the refusal %q does not name decision occurrence %d", err, standing.ID)
		}
	})
}

func TestMovingAWithdrawnPromiseOntoATakenOccurrenceNamesTheDecisionThere(t *testing.T) {
	// Changing a promise revives it, so it meets the same refusal a revision
	// does, and names the decision standing at the occurrence the same way.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		by := time.Now().UTC().AddDate(0, 0, 30).Truncate(time.Second)
		promised, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.at(), Outcome: triage.UpgradeNeeded, UpgradeTo: "2.0", CommittedTo: &by,
			Reasoning: "Moving to the release that drops the parser.", By: f.proposer,
			NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Withdraw(ctx, f.triager, promised.DecisionID); err != nil {
			t.Fatal(err)
		}
		standing := f.decisions(t, f.at())

		_, _, err = f.store.Repromise(ctx, f.triager, promised.DecisionID, "2.1", by,
			"The release moved.")
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("moving a promise onto a taken occurrence answered %v, want it already decided", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("decision occurrence %d ", standing.ID)) {
			t.Errorf("the refusal %q does not name decision occurrence %d", err, standing.ID)
		}
	})
}

func TestAWithdrawnDecisionIsNotOfferedForReaffirming(t *testing.T) {
	// Withdrawing a partly lapsed decision leaves its lapsed row lapsed. The
	// decision was taken back, so re-affirming it would re-make a decision its
	// author withdrew.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		made := f.decisionsMany(t, f.occurrences("under-a", "under-b"))
		f.ends(t, made[1].ID, time.Now().UTC().Truncate(time.Microsecond))
		if ok, err := f.store.Reaffirmable(ctx, f.triager, made[0].DecisionID); err != nil || !ok {
			t.Fatalf("a partly lapsed decision reads as re-affirmable %v (%v), want true, "+
				"so this checks nothing", ok, err)
		}
		if _, err := f.store.Withdraw(ctx, f.triager, made[0].DecisionID); err != nil {
			t.Fatal(err)
		}

		if ok, err := f.store.Reaffirmable(ctx, f.triager, made[0].DecisionID); err != nil || ok {
			t.Errorf("a withdrawn decision reads as re-affirmable %v (%v)", ok, err)
		}
		listed, total, err := f.store.ToReaffirm(ctx, f.triager, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 0 || total != 0 {
			t.Errorf("a withdrawn decision is listed to re-affirm: %d rows, total %d", len(listed), total)
		}
	})
}

func TestASweepLapsingMoreThanOneBatchTellsEachProposerOnce(t *testing.T) {
	// A sweep lapses a bounded batch at a time. One proposer whose rows span
	// batches is one entry, counting every row.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		moved := f.component(t, "libfoo", "1.2.4")
		made := f.decisions(t, f.at())
		now := time.Now().UTC().Truncate(time.Microsecond)
		size := database.InBulk.Most + 1
		findings := make([]finding.Finding, 0, size)
		rows := make([]triage.DecisionOccurrence, 0, size)
		for i := range size {
			occurrence := fmt.Sprintf("place-%04d", i)
			findings = append(findings, finding.Finding{
				TargetID: in.target, Kind: finding.Vulnerable, VulnerabilityID: f.issue,
				Visibility: access.Public, ComponentID: moved, OccurrenceIdentity: occurrence,
				OpenedAt: now, OpenedRunID: &in.run,
			})
			key := fmt.Sprintf("bulk-%04d", i)
			version := "1.2.3"
			rows = append(rows, triage.DecisionOccurrence{
				DecisionID: made.DecisionID, ProductID: f.product, VulnerabilityID: f.issue,
				OccurrenceIdentity: occurrence, Visibility: access.Public,
				ComponentUpstreamVersion: &version, State: triage.Proposed,
				NeedsApproval: true, ProposedBy: made.ProposedBy, ProposedAt: now, LiveKey: &key,
			})
		}
		if _, err := f.db.DB.NewInsert().Model(&findings).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewInsert().Model(&rows).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		lapsed, err := f.store.Lapse(ctx, in.target)
		if err != nil {
			t.Fatal(err)
		}
		if lapsed.Rows != int64(size) {
			t.Errorf("the sweep lapsed %d rows, want %d", lapsed.Rows, size)
		}
		if len(lapsed.Told) != 1 || lapsed.Told[0].Rows != size {
			t.Errorf("the sweep tells %+v, want one proposer told of %d rows", lapsed.Told, size)
		}
	})
}

func TestAProposerWhoseRowsSpanSeveralReadsIsToldOnce(t *testing.T) {
	// A sweep lapsing more rows than one read names reads who to tell in
	// pieces. One person is one notice however the rows fall.
	each(t, func(t *testing.T, f *fixture) {
		made := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))
		ids := []int64{made[2].ID, made[0].ID, made[1].ID}
		told, err := f.store.ProposersOfAll(t.Context(), ids, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(told) != 1 {
			t.Fatalf("one proposer came back as %d entries: %+v", len(told), told)
		}
		if told[0].Rows != 3 || told[0].DecisionOccurrenceID != made[0].ID {
			t.Errorf("told %+v, want three rows represented by decision occurrence %d", told[0], made[0].ID)
		}
	})
}

func TestASimilarDecisionCountsEveryIssueItCovers(t *testing.T) {
	// A bulk decision offered as similar covers far more rows than one read
	// returns. Its issue count is over all of them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other := f.at()
		other.VulnerabilityID = f.secondIssue(t)
		other.OccurrenceIdentity = "under-b"
		agreed := f.decisionsMany(t, []triage.Occurrence{other})
		if _, err := f.store.ApproveDecision(ctx, f.reviewer, agreed[0].DecisionID, "", nil, ""); err != nil {
			t.Fatal(err)
		}
		// Many more rows of the same decision about the second issue, then one
		// about a third, written last.
		template := f.row(t, agreed[0].ID)
		filler := make([]triage.DecisionOccurrence, 0, 601)
		for i := range 600 {
			row := template
			row.ID = 0
			row.LiveKey = nil
			row.OccurrenceIdentity = fmt.Sprintf("filler-%03d", i)
			filler = append(filler, row)
		}
		last := template
		last.ID, last.LiveKey = 0, nil
		last.OccurrenceIdentity = "filler-last"
		last.VulnerabilityID = f.anotherIssue(t, "CVE-2026-3")
		filler = append(filler, last)
		if _, err := f.db.DB.NewInsert().Model(&filler).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		similar, err := f.store.SimilarAt(ctx, f.reviewer, f.product, f.issue,
			[]string{"under-b"})
		if err != nil || len(similar) != 1 {
			t.Fatalf("the bulk decision is not offered: %+v (%v)", similar, err)
		}
		if similar[0].Issues != 2 {
			t.Errorf("a decision over two issues is offered as covering %d", similar[0].Issues)
		}
	})
}

func TestWhatAPersonGotThroughIsCountedInDecisions(t *testing.T) {
	// One argument over many occurrences is one piece of work, whether it was
	// made, agreed to or taken back. Counted per row, a bulk proposer reads
	// as forty-five times busier than the approver of the same decision.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		kept := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))
		if err := agreeTo(ctx, f.store, f.reviewer, kept[0].DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		dropped := f.decisionsMany(t, f.occurrences("under-d", "under-e"))
		if _, err := f.store.Withdraw(ctx, f.triager, dropped[0].DecisionID); err != nil {
			t.Fatal(err)
		}

		measured, err := f.store.Measure(ctx, f.reviewer, triage.Measuring{}, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]triage.Worked{}
		for _, one := range measured.Throughput {
			got[one.Person] = one
		}
		if p := got["proposer"]; p.Proposed != 2 || p.Withdrawn != 1 {
			t.Errorf("the proposer made %d decisions and withdrew %d, want 2 and 1", p.Proposed, p.Withdrawn)
		}
		if a := got["approver"]; a.Approved != 1 {
			t.Errorf("the approver agreed to %d decisions, want 1", a.Approved)
		}
	})
}

func TestADecisionThatGrewIsReportedHoweverManyWereAgreedToBeforeIt(t *testing.T) {
	// The cap applies to the decisions that grew, worst first. Taken off the
	// oldest agreements, a decision agreed to after them never appears.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		libfoo := f.component(t, "libfoo", "1.2.3")
		for _, occurrence := range []string{"place-a", "place-b"} {
			at := f.at()
			at.OccurrenceIdentity = occurrence
			at.ConsumerUpstream = ""
			f.agreed(t, at)
		}
		// The newer decision now reaches a finding nobody agreed to it covering.
		f.finds(t, in, libfoo, "place-b", access.Public)

		scrutiny, err := f.store.Scrutinize(ctx, f.reviewer, nil, time.Time{}, time.Time{}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(scrutiny.Grew) != 1 || scrutiny.Grew[0].CoversNow != 1 {
			t.Fatalf("what grew reads %+v, want the decision at place-b covering one", scrutiny.Grew)
		}
	})
}

func TestADecisionGrowsOnlyByWhatItsLiveRowsReach(t *testing.T) {
	// A lapsed row covers nothing, so a build holding its occurrence again is not
	// growth anybody has to be told about.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		occurrences := make([]triage.Occurrence, 0, 2)
		for _, name := range []string{"place-live", "place-lapsed"} {
			at := f.at()
			at.OccurrenceIdentity, at.ConsumerUpstream = name, ""
			occurrences = append(occurrences, at)
		}
		made := f.decisionsMany(t, occurrences)
		if err := agreeTo(ctx, f.store, f.reviewer, made[0].DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		f.ends(t, made[1].ID, time.Now().UTC().Truncate(time.Microsecond))
		in := f.build(t, f.product, "2026.03")
		libfoo := f.component(t, "libfoo", "1.2.3")
		f.finds(t, in, libfoo, "place-live", access.Public)
		f.finds(t, in, libfoo, "place-lapsed", access.Public)

		scrutiny, err := f.store.Scrutinize(ctx, f.reviewer, nil, time.Time{}, time.Time{}, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(scrutiny.Grew) != 1 || scrutiny.Grew[0].CoversNow != 1 {
			t.Errorf("what grew reads %+v, want the decision covering one through its live row",
				scrutiny.Grew)
		}
	})
}

func TestAWithdrawnDecisionReachesNothing(t *testing.T) {
	// What a decision covers now is what it suppresses. Taken back, it
	// suppresses nothing, however well its versions still match.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		at := f.at()
		at.OccurrenceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		f.finds(t, in, f.component(t, "libfoo", "1.2.3"), "place-of-libfoo", access.Public)
		made := f.decisions(t, at)

		before, err := f.store.Whole(ctx, f.triager, made.DecisionID)
		if err != nil {
			t.Fatal(err)
		}
		if before.Reach.Findings != 1 || len(before.Builds) != 1 {
			t.Fatalf("a standing decision reaches %+v in %v, want one finding in one build",
				before.Reach, before.Builds)
		}
		if _, err := f.store.Withdraw(ctx, f.triager, made.DecisionID); err != nil {
			t.Fatal(err)
		}
		after, err := f.store.Whole(ctx, f.triager, made.DecisionID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Reach.Findings != 0 || len(after.Builds) != 0 {
			t.Errorf("a withdrawn decision reaches %+v in %v, want nothing", after.Reach, after.Builds)
		}
	})
}

func TestAWithdrawnDecisionReportsWhatItReachedWhenItWasWithdrawn(t *testing.T) {
	// Taken back, a decision reaches nothing now. What it reached then is the
	// builds holding one of its occurrences open at that moment: a finding closed
	// before it and one opened after it are not part of it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.at()
		at.OccurrenceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		libfoo := f.component(t, "libfoo", "1.2.3")

		held := f.build(t, f.product, "2026.03")
		f.finds(t, held, libfoo, at.OccurrenceIdentity, access.Public)
		gone := f.build(t, f.product, "2026.02")
		closed := f.finds(t, gone, libfoo, at.OccurrenceIdentity, access.Public)
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"closed_at" = ?`, time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)).
			Set(`"closed_run_id" = ?`, gone.run).
			Where(`"id" = ?`, closed).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		made := f.decisions(t, at)
		if _, err := f.store.Withdraw(ctx, f.triager, made.DecisionID); err != nil {
			t.Fatal(err)
		}
		later := f.build(t, f.product, "2026.04")
		f.opened(t, f.finds(t, later, libfoo, at.OccurrenceIdentity, access.Public),
			time.Now().UTC().Add(time.Hour))

		whole, err := f.store.Whole(ctx, f.triager, made.DecisionID)
		if err != nil {
			t.Fatal(err)
		}
		if whole.Reach.Findings != 0 || len(whole.Builds) != 0 {
			t.Errorf("a withdrawn decision reaches %+v in %v now, want nothing", whole.Reach, whole.Builds)
		}
		if len(whole.Ended) != 1 {
			t.Fatalf("ended parts %+v, want the withdrawn one alone", whole.Ended)
		}
		part := whole.Ended[0]
		if part.State != triage.Withdrawn || part.Rows != 1 || part.Occurrences != 1 {
			t.Errorf("the withdrawn part is %+v, want one row at one occurrence", part)
		}
		if len(part.Builds) != 1 || !strings.HasPrefix(part.Builds[0], "2026.03") {
			t.Errorf("it reached %v when withdrawn, want 2026.03 alone", part.Builds)
		}
		if part.At.IsZero() {
			t.Error("the withdrawn part carries no moment")
		}
	})
}

func TestAPartlyLapsedDecisionReportsTheLapsedPartApart(t *testing.T) {
	// One occurrence of two lapsed. The decision still reaches the other now, and
	// what the lapsed one reached when it lapsed is reported on its own.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		libfoo := f.component(t, "libfoo", "1.2.3")
		in := f.build(t, f.product, "2026.03")
		f.finds(t, in, libfoo, "under-a", access.Public)
		made := f.decisionsMany(t, f.occurrences("under-a", "under-b"))
		f.ends(t, made[0].ID, time.Now().UTC().Truncate(time.Microsecond))

		whole, err := f.store.Whole(ctx, f.triager, made[0].DecisionID)
		if err != nil {
			t.Fatal(err)
		}
		if len(whole.Ended) != 1 {
			t.Fatalf("ended parts %+v, want the lapsed one alone", whole.Ended)
		}
		part := whole.Ended[0]
		if part.State != triage.LapsedState || part.Rows != 1 || part.Occurrences != 1 {
			t.Errorf("the lapsed part is %+v, want one row at one occurrence", part)
		}
		if len(part.Builds) != 1 || !strings.HasPrefix(part.Builds[0], "2026.03") {
			t.Errorf("it reached %v when it lapsed, want 2026.03 alone", part.Builds)
		}
	})
}

func TestADecisionNothingEndedReportsNoEndedPart(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		made := f.decisions(t, f.at())
		whole, err := f.store.Whole(t.Context(), f.triager, made.DecisionID)
		if err != nil {
			t.Fatal(err)
		}
		if len(whole.Ended) != 0 {
			t.Errorf("a standing decision reports ended parts %+v", whole.Ended)
		}
	})
}

func TestWithdrawingADecisionLeavesARowThatHasEndedAsItEnded(t *testing.T) {
	// A lapse records when and why a row stopped applying. Withdrawing the
	// decision afterwards is about the rows still standing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		made := f.decisionsMany(t, f.occurrences("under-a", "under-b"))
		ended := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
		f.ends(t, made[1].ID, ended)

		if _, err := f.store.Withdraw(ctx, f.triager, made[0].DecisionID); err != nil {
			t.Fatal(err)
		}
		if got := f.row(t, made[0].ID); got.State != triage.Withdrawn {
			t.Errorf("the standing row is %q, want withdrawn", got.State)
		}
		lapsed := f.row(t, made[1].ID)
		if lapsed.State != triage.LapsedState {
			t.Errorf("the lapsed row became %q, want it still lapsed", lapsed.State)
		}
		if lapsed.EndedAt == nil || !lapsed.EndedAt.Equal(ended) {
			t.Errorf("the lapsed row ended %v, want %v", lapsed.EndedAt, ended)
		}
	})
}

func TestARevivedDecisionHasNoMomentItStoppedApplying(t *testing.T) {
	// Revising a withdrawn decision brings its rows back to life, and a live row
	// carries no end.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := f.decisions(t, f.at())
		if _, err := f.store.Withdraw(ctx, f.triager, first.DecisionID); err != nil {
			t.Fatal(err)
		}
		if got := f.row(t, first.ID); got.EndedAt == nil {
			t.Fatal("the withdrawn row has no end, so this checks nothing")
		}
		if _, err := f.store.Revise(ctx, f.triager, first.DecisionID, "On reflection it holds."); err != nil {
			t.Fatal(err)
		}
		got := f.row(t, first.ID)
		if got.State != triage.Proposed || got.LiveKey == nil {
			t.Fatalf("the revised row is %q holding key %v, want it live", got.State, got.LiveKey)
		}
		if got.EndedAt != nil {
			t.Errorf("the revived row still ended at %v", got.EndedAt)
		}
	})
}

func TestADecisionWithAWithdrawnRowIsNotReaffirmedAmongMany(t *testing.T) {
	// Withdrawing a partly lapsed decision leaves its lapsed row lapsed, and the
	// row's finding is still open. Re-affirming many decisions, and one decision
	// whole, ask the rule the single form asks: the decision was taken back.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.selection(t)
		var run int64
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).Column("opened_run_id").
			Where(`"target_id" = ?`, at.TargetID).Limit(1).Scan(ctx, &run); err != nil {
			t.Fatal(err)
		}
		f.finds(t, build{target: at.TargetID, run: run}, at.ComponentID, "second-place-of-libfoo",
			access.Public)
		decisionID, recorded, _, err := f.store.BulkDecision(ctx, f.triager, at, f.wontFix(),
			triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) < 2 {
			t.Fatalf("the decision holds %d rows, want a lapsed one and a withdrawn one", len(recorded))
		}
		f.ends(t, recorded[0], time.Now().UTC().Truncate(time.Microsecond))
		if ok, err := f.store.Reaffirmable(ctx, f.triager, decisionID); err != nil || !ok {
			t.Fatalf("a partly lapsed decision reads as re-affirmable %v (%v), want true, "+
				"so this checks nothing", ok, err)
		}
		if _, err := f.store.Withdraw(ctx, f.triager, decisionID); err != nil {
			t.Fatal(err)
		}

		if _, err := f.store.ReaffirmMany(ctx, f.triager, triage.ReaffirmingMany{
			DecisionIDs: []int64{decisionID},
			Reasoning:   "Still in a driver this image never loads.", By: f.proposer,
			Bounds: triage.DefaultBounds(),
		}); !refusal.In(err) || !strings.Contains(err.Error(), "has not lapsed") {
			t.Errorf("a withdrawn decision was re-affirmed among many: %v", err)
		}
		if _, err := f.store.ReaffirmDecision(ctx, f.triager, triage.ReaffirmingDecision{
			PreviousDecisionID: decisionID,
			Reasoning:          "Still in a driver this image never loads.", By: f.proposer,
			Bounds: triage.DefaultBounds(),
		}); !refusal.In(err) || !strings.Contains(err.Error(), "has not lapsed") {
			t.Errorf("a withdrawn decision was re-affirmed whole: %v", err)
		}
	})
}
