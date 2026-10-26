// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// holder is a person who may hold work, with the party it is assigned to.
func (f *fixture) holder(t *testing.T, identity string, roles ...access.Role) access.Subject {
	t.Helper()
	rights := access.NewStore(f.db.DB)
	person, err := rights.Ensure(t.Context(), identity, identity, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if err := rights.GrantRole(t.Context(), person.ID, f.productID, role); err != nil {
			t.Fatal(err)
		}
	}
	return access.NewPerson(person.ID, identity, false,
		map[int64][]access.Role{f.productID: roles}, person.PartyID)
}

// aReport records one claim and answers it.
func (f *fixture) aReport(t *testing.T, who access.Subject, summary string) *finding.FlawReport {
	t.Helper()
	row, err := f.store.Record(t.Context(), who, f.productID, finding.Claimed{
		Title: "A title", Summary: summary,
		Told: finding.Told{ReportedBy: "A. Researcher", Contact: "a@example.org", Received: "2026-09-01"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestAnEditKeepsWhatTheReportSaidBefore(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		row := f.aReport(t, who, "The first words.")

		edited, err := f.store.Revise(ctx, who, f.productID, row.Reference, finding.Rewritten{
			Title: "A better title", Summary: "The second words.",
			ReportedBy: "A. Researcher", Contact: "new@example.org", Received: "2026-08-30",
		})
		if err != nil {
			t.Fatal(err)
		}
		if edited.Summary != "The second words." || edited.Contact != "new@example.org" ||
			edited.ReceivedOn.Format(time.DateOnly) != "2026-08-30" {
			t.Errorf("the edit reads %+v", edited)
		}
		// An edit that changes nothing keeps nothing.
		if _, err := f.store.Revise(ctx, who, f.productID, row.Reference, finding.Rewritten{
			Title: "A better title", Summary: "The second words.",
			ReportedBy: "A. Researcher", Contact: "new@example.org", Received: "2026-08-30",
		}); err != nil {
			t.Fatal(err)
		}
		was, err := f.store.Revisions(ctx, who, f.productID, row.Reference)
		if err != nil {
			t.Fatal(err)
		}
		if len(was) != 1 {
			t.Fatalf("two edits, one of them changing nothing, kept %d revisions, want 1", len(was))
		}
		if was[0].Ordinal != 1 || was[0].Summary != "The first words." ||
			was[0].Title != "A title" || was[0].Contact != "a@example.org" ||
			was[0].ReceivedOn.Format(time.DateOnly) != "2026-09-01" || was[0].ReplacedBy != who.ID {
			t.Errorf("the original reads %+v", was[0])
		}
		counts, err := finding.RevisionCounts(ctx, f.db.DB, []int64{row.ID})
		if err != nil {
			t.Fatal(err)
		}
		if counts[row.ID] != 1 {
			t.Errorf("the report counts %d edits, want 1", counts[row.ID])
		}
	})
}

func TestAnEditIsRefusedWhereItWouldChangeWhatWasJudged(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		edit := finding.Rewritten{Summary: "Changed."}

		// A ruling waiting for a second person holds it: the approver reads
		// the claim as it stands.
		waiting := f.aReport(t, who, "Waiting.")
		if _, err := f.store.Rule(ctx, who, f.productID, finding.Ruled{
			References: []string{waiting.Reference}, Disposition: finding.Rejected,
			Reasoning: "It describes intended behavior.",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(ctx, who, f.productID, waiting.Reference, edit); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("a report under a waiting ruling was edited: %v", err)
		}

		// A ruling in force has judged it.
		ruled := f.aReport(t, who, "Ruled.")
		if _, err := f.store.Rule(ctx, who, f.productID, finding.Ruled{
			References: []string{ruled.Reference}, Disposition: finding.NotReproducible,
			Reasoning: "Nobody could make it happen.",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(ctx, who, f.productID, ruled.Reference, edit); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("a ruled report was edited: %v", err)
		}

		// Accepted as an issue, the issue's description carries it.
		issue := f.anIssueHereShipped(t, who)
		accepted := f.aReport(t, who, "Accepted.")
		if _, err := f.store.JudgeAsIssue(ctx, who, f.productID, accepted.Reference, issue); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(ctx, who, f.productID, accepted.Reference, edit); !errors.Is(err, finding.ErrAlreadyJudged) {
			t.Errorf("an accepted report was edited: %v", err)
		}
		for _, row := range []*finding.FlawReport{waiting, ruled, accepted} {
			if was, err := f.store.Revisions(ctx, who, f.productID, row.Reference); err != nil || len(was) != 0 {
				t.Errorf("a refused edit of %s kept %d revisions (%v)", row.Reference, len(was), err)
			}
		}
	})
}

func TestAnEmptyClaimIsRefusedWhenRecordedAndWhenEdited(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		if _, err := f.store.Record(ctx, who, f.productID,
			finding.Claimed{Summary: "  \n "}); !errors.Is(err, finding.ErrNothingClaimed) {
			t.Errorf("an empty claim was recorded: %v", err)
		}
		row := f.aReport(t, who, "Something.")
		if _, err := f.store.Revise(ctx, who, f.productID, row.Reference,
			finding.Rewritten{Summary: " "}); !errors.Is(err, finding.ErrNothingClaimed) {
			t.Errorf("a claim was edited to nothing: %v", err)
		}
		if _, err := f.store.Revise(ctx, who, f.productID, row.Reference,
			finding.Rewritten{Summary: "Something.", Received: "last tuesday"}); !errors.Is(err, finding.ErrUnreadableDay) {
			t.Errorf("an unreadable day was accepted on an edit: %v", err)
		}
		if _, err := f.store.Revise(ctx, who, f.productID, row.Reference,
			finding.Rewritten{Summary: "Something.", Title: "two\nlines"}); !errors.Is(err, finding.ErrTitleOneLine) {
			t.Errorf("a title across lines was accepted: %v", err)
		}
	})
}

func TestAMessageIsRecordedOnAReportFromOutsideAndNoOther(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		row := f.aReport(t, who, "From outside.")
		ahead := time.Now().UTC().AddDate(0, 0, 3).Format(time.DateOnly)
		for _, c := range []struct {
			in   finding.Logged
			want error
		}{
			{finding.Logged{Direction: "sideways", Body: "x"}, finding.ErrNoDirection},
			{finding.Logged{Direction: finding.Sent, Body: "  "}, finding.ErrMessageEmpty},
			{finding.Logged{Direction: finding.Sent, Body: "x", Dated: "soon"}, finding.ErrUnreadableDay},
			{finding.Logged{Direction: finding.Sent, Body: "x", Dated: ahead}, finding.ErrDatedAhead},
		} {
			if _, _, err := f.store.LogMessage(ctx, who, f.productID, row.Reference, c.in); !errors.Is(err, c.want) {
				t.Errorf("%+v was answered %v, want %v", c.in, err, c.want)
			}
		}
		message, _, err := f.store.LogMessage(ctx, who, f.productID, row.Reference,
			finding.Logged{Direction: finding.Received, Body: "Any news?"})
		if err != nil {
			t.Fatal(err)
		}
		today := time.Now().UTC().Format(time.DateOnly)
		if message.Dated.Format(time.DateOnly) != today {
			t.Errorf("a message given no day is dated %s, want today", message.Dated)
		}
		read, err := f.store.Messages(ctx, who, f.productID, row.Reference)
		if err != nil || len(read) != 1 || read[0].Body != "Any news?" {
			t.Errorf("the correspondence reads %+v (%v)", read, err)
		}

		here, err := f.store.Record(ctx, who, f.productID, finding.Claimed{
			Summary: "Found here.", Told: finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.LogMessage(ctx, who, f.productID, here.Reference,
			finding.Logged{Direction: finding.Sent, Body: "To nobody."}); !errors.Is(err, finding.ErrFoundHere) {
			t.Errorf("a message was recorded on a flaw found here: %v", err)
		}
	})
}

func TestANoteOnAReportIsChangedOnlyByItsAuthorAndKeepsWhatItSaid(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		author := f.holder(t, "author@example.com", access.PrivateTriage)
		other := f.holder(t, "other@example.com", access.PrivateTriage)
		row := f.aReport(t, author, "Something.")
		second := f.aReport(t, author, "Something else.")

		note, _, err := f.store.NoteOnReport(ctx, author, f.productID, row.Reference, "First thought.")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.NoteOnReport(ctx, author, f.productID, row.Reference, " "); !errors.Is(err, finding.ErrNoteSaysNothing) {
			t.Errorf("an empty note was written: %v", err)
		}
		if _, _, err := f.store.RewordReportNote(ctx, other, f.productID, row.Reference,
			note.ID, "Their words."); !errors.Is(err, finding.ErrNoteNotYours) {
			t.Errorf("somebody else changed a note: %v", err)
		}
		// A note is reached through its own report and no other.
		if _, _, err := f.store.RewordReportNote(ctx, author, f.productID, second.Reference,
			note.ID, "Moved."); !errors.Is(err, finding.ErrNoSuchReportNote) {
			t.Errorf("a note was changed through another report: %v", err)
		}
		if _, err := f.store.EarlierReportNote(ctx, author, f.productID, second.Reference,
			note.ID); !errors.Is(err, finding.ErrNoSuchReportNote) {
			t.Errorf("a note's history was read through another report: %v", err)
		}
		if _, _, err := f.store.RewordReportNote(ctx, author, f.productID, row.Reference,
			note.ID, "Second thought."); err != nil {
			t.Fatal(err)
		}
		notes, err := f.store.ReportNotes(ctx, author, f.productID, row.Reference)
		if err != nil || len(notes) != 1 || notes[0].Body != "Second thought." || notes[0].EditedAt == nil {
			t.Fatalf("the notes read %+v (%v)", notes, err)
		}
		was, err := f.store.EarlierReportNote(ctx, author, f.productID, row.Reference, note.ID)
		if err != nil || len(was) != 1 || was[0].Body != "First thought." {
			t.Errorf("what the note said before reads %+v (%v)", was, err)
		}
	})
}

// admitsAll is a recipient check that lets anybody hold anything, recording
// what it was asked about.
func admitsAll(asked *[]access.Visibility) finding.Admits {
	return func(_ context.Context, _ bun.IDB, withheld []access.Visibility) error {
		*asked = append(*asked, withheld...)
		return nil
	}
}

func TestAReportIsTakenGivenAndHandedBackUnderTheFindingRule(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		worker := f.holder(t, "worker@example.com", access.PrivateTriage)
		colleague := f.holder(t, "colleague@example.com", access.PrivateTriage)
		lead := f.holder(t, "lead@example.com", access.PrivateTriage, access.Assigner)
		row := f.aReport(t, worker, "Something.")

		// Taking one nobody holds is working reports.
		var asked []access.Visibility
		mine := worker.Party()
		taken, err := f.store.AssignReport(ctx, worker, f.productID, row.Reference, &mine, admitsAll(&asked))
		if err != nil {
			t.Fatal(err)
		}
		if taken.AssignedTo == nil || *taken.AssignedTo != mine {
			t.Fatalf("taking it left it held by %v", taken.AssignedTo)
		}
		// The recipient is asked about undisclosed work, which a report is.
		if !slices.Equal(asked, []access.Visibility{access.Private}) {
			t.Errorf("the recipient was asked about %v, want undisclosed work", asked)
		}

		// Taking one somebody else holds, or giving one away, needs the
		// assigner right.
		theirs := colleague.Party()
		if _, err := f.store.AssignReport(ctx, colleague, f.productID, row.Reference, &theirs, nil); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a colleague took a report somebody holds: %v", err)
		}
		if _, err := f.store.AssignReport(ctx, worker, f.productID, row.Reference, &theirs, nil); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a worker gave a report away without the right: %v", err)
		}
		if _, err := f.store.AssignReport(ctx, lead, f.productID, row.Reference, &theirs, nil); err != nil {
			t.Fatalf("an assigner could not give it to somebody: %v", err)
		}
		// A refusal from the recipient check stops the write.
		refused := errors.New("they may not read it")
		if _, err := f.store.AssignReport(ctx, lead, f.productID, row.Reference, &mine,
			func(context.Context, bun.IDB, []access.Visibility) error { return refused }); !errors.Is(err, refused) {
			t.Errorf("a recipient who may not hold it was given it: %v", err)
		}

		held, total, err := f.store.HeldReports(ctx, colleague, 0, []int64{theirs}, 50, 0)
		if err != nil || total != 1 || len(held) != 1 || held[0].Reference != row.Reference {
			t.Fatalf("the colleague's reports read %+v of %d (%v)", held, total, err)
		}
		if held[0].Product == "" {
			t.Error("a held report does not name its product")
		}
		// Handing it back puts it in the list of what nobody holds.
		if _, err := f.store.AssignReport(ctx, colleague, f.productID, row.Reference, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, total, err := f.store.HeldReports(ctx, colleague, 0, nil, 50, 0); err != nil || total != 1 {
			t.Errorf("a report handed back is in the unheld list %d times (%v)", total, err)
		}

		// Somebody who does not read the product's reports holds a list of
		// nothing, and counts nothing.
		outsider := f.holder(t, "outsider@example.com", access.PublicTriage)
		if rows, total, err := f.store.HeldReports(ctx, outsider, 0, nil, 50, 0); err != nil || total != 0 || len(rows) != 0 {
			t.Errorf("somebody who reads no reports listed %d (%v)", total, err)
		}
		if counts, err := f.store.ReportHoldings(ctx, outsider, 0); err != nil || len(counts) != 0 {
			t.Errorf("somebody who reads no reports counted %v (%v)", counts, err)
		}

		// A report in a product somebody does not read reports in is in none
		// of their lists and none of their counts.
		elsewhere, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		both := access.NewPerson(lead.ID, "lead@example.com", false, map[int64][]access.Role{
			f.productID: {access.PrivateTriage}, elsewhere.ID: {access.PrivateTriage, access.Assigner},
		}, lead.Party())
		there, err := f.store.Record(ctx, both, elsewhere.ID, finding.Claimed{Summary: "Elsewhere."})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AssignReport(ctx, both, elsewhere.ID, there.Reference, &theirs, nil); err != nil {
			t.Fatal(err)
		}
		if rows, total, err := f.store.HeldReports(ctx, colleague, 0, []int64{theirs}, 50, 0); err != nil || total != 0 || len(rows) != 0 {
			t.Errorf("a report in a product the colleague does not read is in their list: %d (%v)", total, err)
		}
		if counts, err := f.store.ReportHoldings(ctx, colleague, 0); err != nil || counts[theirs] != 0 {
			t.Errorf("a report in a product the colleague does not read is counted: %v (%v)", counts, err)
		}
		if rows, total, err := f.store.HeldReports(ctx, both, 0, []int64{theirs}, 50, 0); err != nil || total != 1 || len(rows) != 1 {
			t.Errorf("somebody reading both products' reports lists %d (%v), want one", total, err)
		}

		// Judged, it leaves every list and is held by nobody new.
		if _, err := f.store.AssignReport(ctx, worker, f.productID, row.Reference, &mine, nil); err != nil {
			t.Fatal(err)
		}
		if counts, err := f.store.ReportHoldings(ctx, worker, 0); err != nil || counts[mine] != 1 {
			t.Errorf("the worker's count reads %v (%v), want one", counts, err)
		}
		if _, err := f.store.Rule(ctx, worker, f.productID, finding.Ruled{
			References: []string{row.Reference}, Disposition: finding.NotReproducible,
			Reasoning: "Nobody could make it happen.",
		}); err != nil {
			t.Fatal(err)
		}
		if _, total, err := f.store.HeldReports(ctx, worker, 0, []int64{mine}, 50, 0); err != nil || total != 0 {
			t.Errorf("a judged report is still held: %d (%v)", total, err)
		}
		if _, err := f.store.AssignReport(ctx, lead, f.productID, row.Reference, &theirs, nil); !errors.Is(err, finding.ErrReportJudged) {
			t.Errorf("a judged report was given to somebody: %v", err)
		}

		// Every change of holder is in its history.
		events, err := f.store.ReportHistory(ctx, worker, f.productID, row.Reference)
		if err != nil {
			t.Fatal(err)
		}
		var acts []finding.ReportAct
		for _, e := range events {
			acts = append(acts, e.Act)
		}
		want := []finding.ReportAct{finding.ActRecorded, finding.ActAssigned, finding.ActAssigned,
			finding.ActHandedBack, finding.ActAssigned, finding.ActRulingProposed, finding.ActRulingSettled}
		if !slices.Equal(acts, want) {
			t.Errorf("the history reads %v, want %v", acts, want)
		}
	})
}

func TestAStandingRulePlacesReportsWhereItsTeamMayReadThem(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage, access.Assigner)
		before := f.aReport(t, who, "Recorded before any rule.")

		blind := f.teamReading(t, "blind", access.PublicRead)
		seeing := f.teamReading(t, "seeing", access.PrivateRead)
		if _, err := f.store.AddReportRule(ctx, who, f.productID, blind, "to the blind"); err != nil {
			t.Fatal(err)
		}
		rule, err := f.store.AddReportRule(ctx, who, f.productID, seeing, "to the seeing")
		if err != nil {
			t.Fatal(err)
		}
		if !rule.Reports || rule.Upstream != "" || rule.Beneath != "" {
			t.Errorf("a rule placing reports reads %+v", rule)
		}
		seen, err := access.NewStore(f.db.DB).TeamsByID(ctx, []int64{seeing})
		if err != nil {
			t.Fatal(err)
		}
		party := seen[seeing].PartyID

		// Recorded now, it is placed as it is recorded, skipping the team
		// nobody on which reads it.
		after := f.aReport(t, who, "Recorded after.")
		if after.AssignedTo == nil || *after.AssignedTo != party {
			t.Errorf("a report recorded under a rule went to %v, want the seeing team", after.AssignedTo)
		}

		// The sweep places what was open before.
		caught, err := f.store.ReportsWouldMatch(ctx, who, f.productID)
		if err != nil || caught.Open != 2 || caught.Unheld != 1 {
			t.Errorf("the preview reads %+v (%v), want two open and one unheld", caught, err)
		}
		if _, _, _, err := f.store.ApplyRules(ctx, f.productID, 0); err != nil {
			t.Fatal(err)
		}
		row, err := f.store.ReportBy(ctx, who, f.productID, before.Reference)
		if err != nil {
			t.Fatal(err)
		}
		if row.AssignedTo == nil || *row.AssignedTo != party {
			t.Errorf("the sweep left the earlier report with %v", row.AssignedTo)
		}
		events, err := f.store.ReportHistory(ctx, who, f.productID, before.Reference)
		if err != nil {
			t.Fatal(err)
		}
		last := events[len(events)-1]
		if last.Act != finding.ActAssigned || last.RuleID == nil || *last.RuleID != rule.ID || last.By != nil {
			t.Errorf("the placement reads %+v, want the rule and no person", last)
		}

		// Somebody who reads no reports previews nothing.
		outsider := f.holder(t, "outsider@example.com", access.PublicTriage)
		if caught, err := f.store.ReportsWouldMatch(ctx, outsider, f.productID); err != nil || caught.Open != 0 {
			t.Errorf("somebody who reads no reports previewed %+v (%v)", caught, err)
		}
	})
}

func TestAHandOverMovesTheReportsSomebodyHolds(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		leaving := f.holder(t, "leaving@example.com", access.PrivateTriage)
		staying := f.holder(t, "staying@example.com", access.PrivateTriage)
		blind := f.holder(t, "blind@example.com", access.PublicTriage)
		row := f.aReport(t, leaving, "Something.")
		mine := leaving.Party()
		if _, err := f.store.AssignReport(ctx, leaving, f.productID, row.Reference, &mine, nil); err != nil {
			t.Fatal(err)
		}
		admin := access.NewPerson(leaving.ID, "admin", true, nil, 0)
		if _, err := f.store.HandOver(ctx, admin, mine, blind.Party()); !errors.Is(err, finding.ErrRecipientMayNotRead) {
			t.Errorf("a report was handed to somebody who reads no reports: %v", err)
		}
		moved, err := f.store.HandOver(ctx, admin, mine, staying.Party())
		if err != nil || moved != 1 {
			t.Fatalf("the hand-over moved %d (%v), want the one report", moved, err)
		}
		if _, total, err := f.store.HeldReports(ctx, staying, 0, []int64{staying.Party()}, 50, 0); err != nil || total != 1 {
			t.Errorf("the recipient holds %d reports (%v)", total, err)
		}
		if moved, err := f.store.Release(ctx, admin, staying.Party()); err != nil || moved != 1 {
			t.Errorf("releasing moved %d (%v), want the one report", moved, err)
		}
	})
}

// Withdrawing somebody's last role on a product hands back the reports they
// hold there, and they wait for somebody again.
func TestWithdrawingALastRoleHandsBackTheReportsHeld(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		leaving := f.holder(t, "leaving@example.com", access.PrivateTriage)
		row := f.aReport(t, leaving, "Something.")
		mine := leaving.Party()
		if _, err := f.store.AssignReport(ctx, leaving, f.productID, row.Reference, &mine, nil); err != nil {
			t.Fatal(err)
		}
		admin := access.NewPerson(leaving.ID, "admin", true, nil, 0)
		moved, err := f.store.ReleaseIn(ctx, admin, mine, f.productID)
		if err != nil || moved != 1 {
			t.Fatalf("withdrawing the last role moved %d (%v), want the one report", moved, err)
		}
		waiting, total, err := f.store.HeldReports(ctx, leaving, f.productID, nil, 50, 0)
		if err != nil || total != 1 || len(waiting) != 1 || waiting[0].Reference != row.Reference {
			t.Errorf("after the hand-back %d reports wait for somebody (%v), want the one handed back", total, err)
		}
	})
}

func TestAReportsHistoryHoldsEveryAct(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		row := f.aReport(t, who, "Something.")
		if _, err := f.store.Revise(ctx, who, f.productID, row.Reference,
			finding.Rewritten{Summary: "Something more."}); err != nil {
			t.Fatal(err)
		}
		note, _, err := f.store.NoteOnReport(ctx, who, f.productID, row.Reference, "A thought.")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.RewordReportNote(ctx, who, f.productID, row.Reference, note.ID, "Another."); err != nil {
			t.Fatal(err)
		}
		for _, d := range []finding.Direction{finding.Sent, finding.Received} {
			if _, _, err := f.store.LogMessage(ctx, who, f.productID, row.Reference,
				finding.Logged{Direction: d, Body: "A message."}); err != nil {
				t.Fatal(err)
			}
		}
		issue := f.anIssueHereShipped(t, who)
		if _, err := f.store.JudgeAsIssue(ctx, who, f.productID, row.Reference, issue); err != nil {
			t.Fatal(err)
		}
		events, err := f.store.ReportHistory(ctx, who, f.productID, row.Reference)
		if err != nil {
			t.Fatal(err)
		}
		var acts []finding.ReportAct
		for _, e := range events {
			acts = append(acts, e.Act)
			if e.By == nil || *e.By != who.ID {
				t.Errorf("%s does not say who did it", e.Act)
			}
		}
		want := []finding.ReportAct{finding.ActRecorded, finding.ActEdited, finding.ActNoted,
			finding.ActNoteEdited, finding.ActSent, finding.ActReceived, finding.ActAccepted}
		if !slices.Equal(acts, want) {
			t.Errorf("the history reads %v, want %v", acts, want)
		}
		// Nobody who may not read the report reads its history.
		outsider := f.holder(t, "outsider@example.com", access.PublicTriage)
		if _, err := f.store.ReportHistory(ctx, outsider, f.productID, row.Reference); !errors.Is(err, finding.ErrNoSuchReport) {
			t.Errorf("somebody who reads no reports read a report's history: %v", err)
		}
	})
}

// Two edits at once keep every version: the one that commits second, having
// read the report before the first committed, is taken again and keeps what
// the first wrote as the version it replaced.
func TestTwoEditsAtOnceKeepEveryVersion(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		row := f.aReport(t, who, "The first words.")
		edit := func(summary string) finding.Rewritten {
			return finding.Rewritten{Title: "A title", Summary: summary,
				ReportedBy: "A. Researcher", Contact: "a@example.org", Received: "2026-09-01"}
		}
		// The rival lands after the report is read and before the next
		// statement, which is where a count read after the report would
		// count the rival's edit and keep text the report no longer held.
		hooked, rival := dbtest.RivalAfterSelect(t, f.db, "flaw_report", 5*time.Second,
			func() error {
				_, err := f.store.Revise(context.Background(), who, f.productID, row.Reference,
					edit("The rival's words."))
				return err
			})
		if _, err := finding.NewStore(hooked).Revise(ctx, who, f.productID, row.Reference,
			edit("The last words.")); err != nil {
			t.Fatalf("the edit that lost the race was not taken again: %v", err)
		}
		if err := rival(); err != nil {
			t.Fatalf("the rival edit: %v", err)
		}
		was, err := f.store.Revisions(ctx, who, f.productID, row.Reference)
		if err != nil {
			t.Fatal(err)
		}
		var said []string
		for _, revision := range was {
			said = append(said, revision.Summary)
		}
		if !slices.Equal(said, []string{"The first words.", "The rival's words."}) {
			t.Errorf("the revisions kept read %q, want the first words, then the rival's", said)
		}
	})
}

// Two edits of one note at once keep every wording, for the same reason.
func TestTwoEditsOfANoteAtOnceKeepEveryWording(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		row := f.aReport(t, who, "A claim.")
		note, _, err := f.store.NoteOnReport(ctx, who, f.productID, row.Reference, "First.")
		if err != nil {
			t.Fatal(err)
		}
		hooked, rival := dbtest.RivalAfterSelect(t, f.db, "report_note", 5*time.Second,
			func() error {
				_, _, err := f.store.RewordReportNote(context.Background(), who, f.productID,
					row.Reference, note.ID, "The rival's.")
				return err
			})
		if _, _, err := finding.NewStore(hooked).RewordReportNote(ctx, who, f.productID,
			row.Reference, note.ID, "The last."); err != nil {
			t.Fatalf("the edit that lost the race was not taken again: %v", err)
		}
		if err := rival(); err != nil {
			t.Fatalf("the rival edit: %v", err)
		}
		was, err := f.store.EarlierReportNote(ctx, who, f.productID, row.Reference, note.ID)
		if err != nil {
			t.Fatal(err)
		}
		var said []string
		for _, revision := range was {
			said = append(said, revision.Body)
		}
		if !slices.Equal(said, []string{"First.", "The rival's."}) {
			t.Errorf("the wordings kept read %q, want the first, then the rival's", said)
		}
	})
}
