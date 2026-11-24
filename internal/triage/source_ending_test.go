// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// perfAt is where the perf world's linux-perf sits for an issue.
func (f *fixture) perfAt(issue int64) triage.Occurrence {
	return triage.Occurrence{ProductID: f.product, VulnerabilityID: issue,
		OccurrenceIdentity: "place-of-linux-perf", Visibility: access.Public, ComponentUpstream: "6.12.117-1"}
}

// rowOf is a decision occurrence as it stands now.
func (f *fixture) rowOf(t *testing.T, id int64) triage.DecisionOccurrence {
	t.Helper()
	row := new(triage.DecisionOccurrence)
	if err := f.db.DB.NewSelect().Model(row).Where(`"de"."id" = ?`, id).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return *row
}

// agreedPerf is the perf correction proposed and agreed to, with its rows by
// issue.
func (f *fixture) agreedPerf(t *testing.T, batch string) (int64, map[int64]triage.DecisionOccurrence) {
	t.Helper()
	proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
	if err != nil {
		t.Fatal(err)
	}
	if err := agreeTo(t.Context(), f.store, f.reviewer, proposed.DecisionID, batch); err != nil {
		t.Fatal(err)
	}
	rows, _ := f.answeredIssues(t, proposed.DecisionID)
	return proposed.DecisionID, rows
}

// An incident recorded through an issue withdraws the correction's answer
// about that issue alone, whether the correction was agreed or waiting, and
// tells the proposer; its answers about other issues stand.
func TestAnIncidentWithdrawsOnlyTheAttackedIssuesAnswer(t *testing.T) {
	for _, agreed := range []bool{true, false} {
		t.Run(map[bool]string{true: "agreed", false: "waiting"}[agreed], func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				w := f.perfWorld(t)
				proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
				if err != nil {
					t.Fatal(err)
				}
				if agreed {
					if err := agreeTo(t.Context(), f.store, f.reviewer, proposed.DecisionID, ""); err != nil {
						t.Fatal(err)
					}
				}
				rows, _ := f.answeredIssues(t, proposed.DecisionID)
				incident, undone, err := f.store.RecordIncident(t.Context(), f.triager, f.product, w.outside, knownAt,
					"Exploited through the USB PHY on a customer's board.")
				if err != nil {
					t.Fatal(err)
				}
				if len(undone.Lapsed) != 1 || undone.Lapsed[0].PersonID != f.triager.ID ||
					undone.Lapsed[0].SourceWithdrawn != triage.WithdrawnByIncident {
					t.Errorf("agreed %v: who is told reads %+v, want the proposer, for the incident", agreed, undone.Lapsed)
				}
				if got := f.rowOf(t, rows[w.outside].ID); got.State != triage.LapsedState || got.LiveKey != nil {
					t.Errorf("agreed %v: the attacked issue's answer is %q, want lapsed", agreed, got.State)
				}
				if !agreed {
					if err := agreeTo(t.Context(), f.store, f.reviewer, proposed.DecisionID, ""); err != nil {
						t.Fatal(err)
					}
				}
				if got := f.rowOf(t, rows[w.alsoOutside].ID); got.State != triage.Approved {
					t.Errorf("agreed %v: the answer beside it is %q, want approved", agreed, got.State)
				}
				if got := f.rowOf(t, rows[w.outside].ID); got.State != triage.LapsedState {
					t.Errorf("agreed %v: agreeing brought the attacked answer back as %q", agreed, got.State)
				}
				answers, err := f.store.SourceAnswers(t.Context(), []int64{rows[w.outside].ID})
				if err != nil {
					t.Fatal(err)
				}
				if got := answers[rows[w.outside].ID]; got.Because != triage.WithdrawnByIncident {
					t.Errorf("agreed %v: the answer reads %+v, want withdrawn by the incident", agreed, got)
				}
				// Clearing the record restores nothing.
				if err := f.store.ClearIncident(t.Context(), f.triager, incident.ID, "Not exploited after all."); err != nil {
					t.Fatal(err)
				}
				if pass, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil || pass.Answered != 0 {
					t.Errorf("agreed %v: after clearing, the scan answered %d (%v), want none", agreed, pass.Answered, err)
				}
			})
		})
	}
}

// An answer something withdrew is re-affirmed only with a second person: the
// agreement it had was not given over what withdrew it.
func TestAWithdrawnAnswerIsReaffirmedOnlyWithASecondPerson(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		_, rows := f.agreedPerf(t, "")
		f.setFiles(t, w.outside, "tools/perf/util/evsel.c")
		if pass, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil || pass.Withdrawn.Rows != 1 {
			t.Fatalf("the scan withdrew %d (%v), want one", pass.Withdrawn.Rows, err)
		}
		again, err := f.store.Reaffirm(t.Context(), f.triager, triage.Reaffirmation{
			PreviousID: rows[w.outside].ID, Occurrence: f.perfAt(w.outside),
			Reasoning: "Still not the kernel.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if again.State != triage.Proposed || !again.NeedsApproval {
			t.Errorf("the re-affirmed answer is %q needing approval %v, want waiting for a second person",
				again.State, again.NeedsApproval)
		}
	})
}

// Revising a correction brings back its answers that were not withdrawn, and
// leaves the withdrawn ones lapsed; a correction that was withdrawn is not
// revised.
func TestRevisingACorrectionLeavesWithdrawnAnswersLapsed(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		decision, rows := f.agreedPerf(t, "")
		f.setFiles(t, w.outside, "tools/perf/util/evsel.c")
		if _, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(t.Context(), f.triager, decision, "Built from tools/ alone."); err != nil {
			t.Fatal(err)
		}
		if got := f.rowOf(t, rows[w.outside].ID); got.State != triage.LapsedState {
			t.Errorf("revising brought a withdrawn answer back as %q", got.State)
		}
		if got := f.rowOf(t, rows[w.alsoOutside].ID); got.State != triage.Proposed {
			t.Errorf("the answer still borne out is %q after revising, want waiting", got.State)
		}

		if _, err := f.store.Withdraw(t.Context(), f.triager, decision); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(t.Context(), f.triager, decision, "Again."); !errors.Is(err, triage.ErrSourceWithdrawn) {
			t.Errorf("revising a withdrawn correction gave %v, want refused", err)
		}
	})
}

// A correction withdrawn whole leaves nothing of its in To reaffirm, its
// answers a record withdrew first included.
func TestAWithdrawnCorrectionLeavesNothingToReaffirm(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		decision, _ := f.agreedPerf(t, "")
		f.setFiles(t, w.outside, "tools/perf/util/evsel.c")
		f.setFiles(t, w.alsoOutside)
		if _, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil {
			t.Fatal(err)
		}
		listed, _, err := f.store.ToReaffirm(t.Context(), f.triager, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 1 || listed[0].SourceWithdrawn != triage.WithdrawnByRecord {
			t.Fatalf("To reaffirm lists %+v, want the correction, withdrawn by the record", listed)
		}
		if _, err := f.store.Withdraw(t.Context(), f.triager, decision); err != nil {
			t.Fatal(err)
		}
		if listed, _, err = f.store.ToReaffirm(t.Context(), f.triager, 0, 50, 0); err != nil || len(listed) != 0 {
			t.Errorf("To reaffirm lists %d after the correction was withdrawn (%v), want none", len(listed), err)
		}
	})
}

// A scan matching an answered issue at the occurrence other than through the
// source, on the package's own name or a CPE, withdraws the answer.
func TestAMatchOtherThanThroughTheSourceWithdrawsTheAnswer(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		_, rows := f.agreedPerf(t, "")
		later := f.build(t, f.product, "2026.12")
		f.throughSource(t, later, w.outside, w.perf, "place-of-linux-perf", "", access.Public)
		f.throughSource(t, later, w.alsoOutside, w.perf, "place-of-linux-perf", "linux", access.Public)
		pass, err := f.store.AnswerBySource(t.Context(), later.build)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Withdrawn.Rows != 1 || len(pass.Withdrawn.Told) != 1 ||
			pass.Withdrawn.Told[0].SourceWithdrawn != triage.WithdrawnByMatch {
			t.Errorf("the scan withdrew %d, telling %+v, want one, for the match", pass.Withdrawn.Rows, pass.Withdrawn.Told)
		}
		if got := f.rowOf(t, rows[w.outside].ID); got.State != triage.LapsedState {
			t.Errorf("an answer the package's own name now matches is %q, want lapsed", got.State)
		}
		if got := f.rowOf(t, rows[w.alsoOutside].ID); got.State != triage.Approved {
			t.Errorf("an answer still matched through the source is %q, want approved", got.State)
		}
	})
}

// A finding holding no source withdraws nothing where the last run its build
// applied did not record sources, as every run before they were recorded did
// not: its match was never read. Once a run recording them applies, the same
// finding is a match on the package itself and withdraws the answer.
func TestAMatchNeverReadWithdrawsNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		_, rows := f.agreedPerf(t, "")
		older := f.build(t, f.product, "2026.10")
		f.throughSource(t, older, w.outside, w.perf, "place-of-linux-perf", "", access.Public)
		recorded := func(yes bool) {
			t.Helper()
			if _, err := f.db.DB.NewUpdate().Table("scan_run").Set(`"sources_recorded" = ?`, yes).
				Where(`"id" = ?`, older.run).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		recorded(false)
		pass, err := f.store.AnswerBySource(t.Context(), w.in.build)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Withdrawn.Rows != 0 {
			t.Errorf("a match never read withdrew %d answers, want none", pass.Withdrawn.Rows)
		}
		if got := f.rowOf(t, rows[w.outside].ID); got.State != triage.Approved {
			t.Errorf("the answer is %q beside a match never read, want approved", got.State)
		}

		recorded(true)
		if pass, err = f.store.AnswerBySource(t.Context(), w.in.build); err != nil {
			t.Fatal(err)
		}
		if pass.Withdrawn.Rows != 1 {
			t.Errorf("a match on the package itself withdrew %d answers, want one", pass.Withdrawn.Rows)
		}
		if got := f.rowOf(t, rows[w.outside].ID); got.State != triage.LapsedState {
			t.Errorf("the answer is %q beside a match on the package itself, want lapsed", got.State)
		}
	})
}

// An answer withdrawn for a match, which the correction answers again once the
// scan matches the occurrence through the source alone, leaves To reaffirm:
// the rule re-answered it, and re-affirming would write it twice.
func TestAnAnswerTheCorrectionGivesAgainLeavesToReaffirm(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		decision, rows := f.agreedPerf(t, "")
		later := f.build(t, f.product, "2026.12")
		own := f.throughSource(t, later, w.outside, w.perf, "place-of-linux-perf", "", access.Public)
		if pass, err := f.store.AnswerBySource(t.Context(), later.build); err != nil || pass.Withdrawn.Rows != 1 {
			t.Fatalf("the scan withdrew %d (%v), want one", pass.Withdrawn.Rows, err)
		}
		listed, _, err := f.store.ToReaffirm(t.Context(), f.triager, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 1 || listed[0].Rows != 1 {
			t.Fatalf("To reaffirm lists %+v, want the correction with its one withdrawn answer", listed)
		}

		if _, err := f.db.DB.NewUpdate().Table("finding").Set(`"matched_through" = ?`, "linux").
			Where(`"id" = ?`, own).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		pass, err := f.store.AnswerBySource(t.Context(), later.build)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Answered != 1 {
			t.Fatalf("the scan answered %d, want the occurrence matched through the source again", pass.Answered)
		}
		answered, _ := f.answeredIssues(t, decision)
		if row, ok := answered[w.outside]; !ok || row.ID == rows[w.outside].ID {
			t.Fatalf("the issue is answered as %+v, want a new row", row)
		}
		if got := f.rowOf(t, rows[w.outside].ID); got.State != triage.LapsedState {
			t.Errorf("the withdrawn answer is %q, want it kept lapsed", got.State)
		}
		if listed, _, err = f.store.ToReaffirm(t.Context(), f.triager, 0, 50, 0); err != nil || len(listed) != 0 {
			t.Errorf("To reaffirm lists %+v (%v) once the correction answered again, want nothing", listed, err)
		}
		if _, err := f.store.ReaffirmDecision(t.Context(), f.triager, triage.ReaffirmingDecision{
			PreviousDecisionID: decision, Reasoning: "Still not the kernel.", By: f.proposer,
		}); err == nil {
			t.Error("re-affirming the correction once it answered again was accepted, want refused")
		}
	})
}

// An occurrence an approver set aside stays out of the correction once the
// decision it was set aside into is withdrawn.
func TestAnOccurrenceSetAsideIsNotAnsweredAgain(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		rows, _ := f.answeredIssues(t, proposed.DecisionID)
		approved, err := f.store.ApproveDecision(t.Context(), f.reviewer, proposed.DecisionID, "",
			[]int64{rows[w.outside].ID}, "The PHY driver is in the board's image too.")
		if err != nil {
			t.Fatal(err)
		}
		if approved.Returned == nil {
			t.Fatal("nothing was set aside")
		}
		if _, err := f.store.Withdraw(t.Context(), f.triager, approved.Returned.ID); err != nil {
			t.Fatal(err)
		}
		pass, err := f.store.AnswerBySource(t.Context(), w.in.build)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Answered != 0 {
			t.Errorf("the scan answered %d occurrences, want the one set aside left alone", pass.Answered)
		}
	})
}

// What the correction's agreement stands in decides how a later issue is
// answered: an undone batch and a send-back leave it waiting, and a
// correction every row of which was set aside answers nothing.
func TestALaterIssueFollowsWhereTheAgreementStands(t *testing.T) {
	later := func(t *testing.T, f *fixture, w perfWorld) int64 {
		t.Helper()
		issue := f.kernelIssue(t, "CVE-2026-90700", "kernel/bpf/verifier.c")
		f.throughSource(t, w.in, issue, w.perf, "place-of-linux-perf", "linux", access.Public)
		return issue
	}
	t.Run("an undone batch", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			w := f.perfWorld(t)
			decision, _ := f.agreedPerf(t, "afternoon")
			if _, err := f.store.UndoBatch(t.Context(), f.reviewer, "afternoon"); err != nil {
				t.Fatal(err)
			}
			issue := later(t, f, w)
			if _, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil {
				t.Fatal(err)
			}
			rows, _ := f.answeredIssues(t, decision)
			if row, ok := rows[issue]; !ok || row.State != triage.Proposed {
				t.Errorf("a later issue after the batch was undone is %+v, want waiting", row)
			}
		})
	})
	t.Run("a send-back", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			w := f.perfWorld(t)
			proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.SendBackDecision(t.Context(), f.reviewer, proposed.DecisionID,
				"Say which Debian source package builds it."); err != nil {
				t.Fatal(err)
			}
			issue := later(t, f, w)
			if _, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil {
				t.Fatal(err)
			}
			rows, _ := f.answeredIssues(t, proposed.DecisionID)
			if row, ok := rows[issue]; !ok || row.SentBackAt == nil {
				t.Errorf("a later issue after a send-back is %+v, want sent back with the rest", row)
			}
		})
	})
	t.Run("every row set aside", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			w := f.perfWorld(t)
			proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
			if err != nil {
				t.Fatal(err)
			}
			_, ids := f.answeredIssues(t, proposed.DecisionID)
			if _, err := f.store.ApproveDecision(t.Context(), f.reviewer, proposed.DecisionID, "", ids,
				"None of these holds."); err != nil {
				t.Fatal(err)
			}
			later(t, f, w)
			pass, err := f.store.AnswerBySource(t.Context(), w.in.build)
			if err != nil {
				t.Fatal(err)
			}
			if pass.Answered != 0 {
				t.Errorf("a correction every row of which was set aside answered %d", pass.Answered)
			}
		})
	})
}

// linux-perf shipped at two versions in one product is one occurrence to a
// correction, which is keyed without versions: one row per issue.
func TestACorrectionAnswersAnOccurrenceAtTwoVersionsOnce(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		newer := f.build(t, f.product, "2026.12")
		bumped := f.component(t, "linux-perf", "6.12.120-1")
		f.throughSource(t, newer, w.outside, bumped, "place-of-linux-perf", "linux", access.Public)
		f.throughSource(t, newer, w.alsoOutside, bumped, "place-of-linux-perf", "linux", access.Public)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		if proposed.Answered != 2 {
			t.Errorf("the correction answered %d occurrences, want one per issue", proposed.Answered)
		}
	})
}

// A pass answering a later issue and a withdrawal of the correction committing
// at once: the pass that read the correction standing loses the race and,
// taken again, answers nothing under the withdrawn correction.
func TestAPassLosesARaceWithTheCorrectionsWithdrawal(t *testing.T) {
	servers(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		decision, _ := f.agreedPerf(t, "")
		issue := f.kernelIssue(t, "CVE-2026-90800", "kernel/sched/core.c")
		f.throughSource(t, w.in, issue, w.perf, "place-of-linux-perf", "linux", access.Public)

		hooked, rival := dbtest.RivalAfterRead(t, f.db, "source_correction", "decision_occurrence",
			5*time.Second, func() error {
				_, err := f.store.Withdraw(context.Background(), f.triager, decision)
				return err
			})
		if _, err := triage.NewStore(hooked).AnswerBySource(t.Context(), w.in.build); err != nil {
			t.Fatal(err)
		}
		if err := rival(); err != nil {
			t.Fatalf("the rival withdrawal: %v", err)
		}
		live, err := f.db.DB.NewSelect().Model((*triage.DecisionOccurrence)(nil)).
			Where(`"de"."decision_id" = ?`, decision).
			Where(`"de"."live_key" IS NOT NULL`).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if live != 0 {
			t.Errorf("%d answers stand under a withdrawn correction", live)
		}
	})
}

// An issue whose record again puts every file outside is answered again, as a
// new row; its withdrawn row stays as it was.
func TestARecordThatMovesBackIsAnsweredAgain(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		decision, rows := f.agreedPerf(t, "")
		f.setFiles(t, w.outside, "tools/perf/util/evsel.c")
		if _, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil {
			t.Fatal(err)
		}
		f.setFiles(t, w.outside, "drivers/phy/ti/phy-omap-usb2.c")
		pass, err := f.store.AnswerBySource(t.Context(), w.in.build)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Answered != 1 {
			t.Errorf("the scan answered %d, want the issue whose record moved back", pass.Answered)
		}
		answered, _ := f.answeredIssues(t, decision)
		if row, ok := answered[w.outside]; !ok || row.ID == rows[w.outside].ID || row.State != triage.Approved {
			t.Errorf("the issue is answered as %+v, want a new approved row", row)
		}
	})
}
