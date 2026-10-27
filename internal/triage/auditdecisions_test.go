// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// rowsOf is every row one decision wrote, oldest first.
func (f *fixture) rowsOf(t *testing.T, decisionID int64) []triage.DecisionOccurrence {
	t.Helper()
	var rows []triage.DecisionOccurrence
	if err := f.db.DB.NewSelect().Model(&rows).Where(`"de"."decision_id" = ?`, decisionID).
		Order("de.id ASC").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

// auditedDecisions reads the whole record a decision at a time.
func (f *fixture) auditedDecisions(t *testing.T, who access.Subject, filter triage.Filter) ([]triage.AuditedDecision, int) {
	t.Helper()
	rows, total, err := f.store.AuditDecisions(t.Context(), who, filter, time.Time{}, time.Time{}, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rows, total
}

func TestTheRecordListsADecisionOnceHoweverManyOccurrencesItCovers(t *testing.T) {
	// One argument by one person across several occurrences is one entry, counted
	// once in the total, and the entry says how much it covers. Only the rows
	// the reader may see are counted: a decision with an undisclosed row reads to
	// somebody holding public reading alone as the rows they may read, without
	// the reasoning written about all of them.
	each(t, func(t *testing.T, f *fixture) {
		in := f.build(t, f.product, "for-the-record")
		libfoo := f.component(t, "libfoo", "1.2.3")
		libbar := f.component(t, "libbar", "2.0.0")
		secret := f.component(t, "libsecret", "0.1.0")
		f.finds(t, in, libfoo, "place-a", access.Public)
		f.finds(t, in, libfoo, "place-b", access.Public)
		f.finds(t, in, libbar, "place-c", access.Public)
		f.finds(t, in, secret, "place-d", access.Private)
		// A disclosed occurrence that an undisclosed build also ships, under a
		// name only a reader of undisclosed findings may learn.
		f.finds(t, f.build(t, f.product, "embargoed"), f.component(t, "libhidden", "1.0.0"),
			"place-c", access.Private)

		insider := f.privately(t)
		bulk := f.proposes(t, insider,
			f.occurrenceIn(f.product, "place-a", access.Public),
			f.occurrenceIn(f.product, "place-b", access.Public),
			f.occurrenceIn(f.product, "place-c", access.Public),
			f.occurrenceIn(f.product, "place-d", access.Private))
		single := f.proposes(t, f.triager, f.occurrenceIn(f.product, "place-e", access.Public))

		rows, total := f.auditedDecisions(t, f.reviewer, triage.Filter{})
		if total != 2 || len(rows) != 2 {
			t.Fatalf("the record lists %d entries (%d on the page), want one per decision: 2", total, len(rows))
		}
		if rows[0].Decision.ID != single.DecisionID || rows[1].Decision.ID != bulk.DecisionID {
			t.Fatalf("the record lists decisions %d, %d; want the newest first: %d, %d",
				rows[0].Decision.ID, rows[1].Decision.ID, single.DecisionID, bulk.DecisionID)
		}
		got := rows[1]
		if got.Rows != 3 || got.Occurrences != 3 || got.Issues != 1 || got.Products != 1 {
			t.Errorf("a public reader is told the decision covers %d rows, %d occurrences, %d issues, "+
				"%d products; want the three public rows of one issue in one product",
				got.Rows, got.Occurrences, got.Issues, got.Products)
		}
		if got.Components != 2 {
			t.Errorf("a public reader is told of %d components, want libfoo and libbar alone", got.Components)
		}
		if got.Component != "libfoo" || got.Issue == "" || got.ProposedByName == "" {
			t.Errorf("the entry does not say what it was about, or who argued it: %+v", got)
		}
		// The reasoning is about every occurrence the decision was made at, the
		// undisclosed one included, so a reader of part of it is not shown it.
		if got.Reasoning != "" {
			t.Errorf("a public reader was shown the reasoning of a decision reaching an undisclosed occurrence: %q",
				got.Reasoning)
		}
		if got.State() != string(triage.Proposed) || got.Standing != 0 {
			t.Errorf("a decision waiting for agreement reads %q with %d standing", got.State(), got.Standing)
		}

		// The per-occurrence record and the list of decision occurrences hold to the same.
		judged, _, err := f.store.Audit(t.Context(), f.reviewer, triage.Filter{},
			time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		listed, reasoning, _, err := f.store.List(t.Context(), f.reviewer, triage.Filter{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range judged {
			if row.DecisionID == bulk.DecisionID && row.Reasoning != "" {
				t.Errorf("the record shows decision occurrence %d the reasoning of a decision reaching an undisclosed occurrence",
					row.ID)
			}
		}
		for _, row := range listed {
			if row.DecisionID == bulk.DecisionID && reasoning[row.ID] != "" {
				t.Errorf("the list shows decision occurrence %d the reasoning of a decision reaching an undisclosed occurrence",
					row.ID)
			}
		}
		// So does the reasoning a single occurrence's decision is shown with.
		var ofBulk []triage.DecisionOccurrence
		for _, row := range listed {
			if row.DecisionID == bulk.DecisionID {
				ofBulk = append(ofBulk, row)
			}
		}
		if len(ofBulk) == 0 {
			t.Fatal("the public reader lists no row of the decision, so this checked nothing")
		}
		shown, err := f.store.ReasoningFor(t.Context(), f.reviewer, ofBulk)
		if err != nil {
			t.Fatal(err)
		}
		for id, said := range shown {
			t.Errorf("decision occurrence %d is shown the reasoning of a decision reaching an undisclosed occurrence: %q", id, said)
		}
		whole, err := f.store.ReasoningFor(t.Context(), insider, ofBulk)
		if err != nil {
			t.Fatal(err)
		}
		if whole[ofBulk[0].ID] == "" {
			t.Error("a reader of every row of the decision is not shown its reasoning beside one occurrence")
		}

		// Its proposer reads every row, the undisclosed one included.
		rows, _ = f.auditedDecisions(t, insider, triage.Filter{})
		for _, row := range rows {
			if row.Decision.ID == bulk.DecisionID && (row.Rows != 4 || row.Components != 4) {
				t.Errorf("a reader of both visibilities is told of %d rows and %d components, want 4 and 4",
					row.Rows, row.Components)
			}
			if row.Reasoning == "" {
				t.Errorf("a reader of every row of decision %d is not shown its reasoning", row.Decision.ID)
			}
		}

		// Somebody who reads another product alone is told of nothing here,
		// the count included.
		stranger := f.holding(t, "stranger", map[int64][]access.Role{
			f.secondProduct(t): {access.PublicRead, access.PrivateRead},
		})
		if _, total := f.auditedDecisions(t, stranger, triage.Filter{}); total != 0 {
			t.Errorf("a reader of another product is told of %d decisions here", total)
		}
	})
}

func TestTheRecordCountsOnlyTheRowsTheFiltersMatch(t *testing.T) {
	// A decision is listed where any of its rows answer the question, and its
	// counts are of those rows alone. Asked for what lapsed, a decision with one
	// lapsed row of three reads as one lapsed row rather than as the whole
	// decision, which is what the reader did not ask for.
	each(t, func(t *testing.T, f *fixture) {
		bulk := f.proposes(t, f.triager,
			f.occurrenceIn(f.product, "place-a", access.Public),
			f.occurrenceIn(f.product, "place-b", access.Public),
			f.occurrenceIn(f.product, "place-c", access.Public))
		f.ends(t, f.rowsOf(t, bulk.DecisionID)[0].ID, time.Now().UTC())

		lapsed := triage.Filter{States: []triage.State{triage.LapsedState}}
		rows, total := f.auditedDecisions(t, f.reviewer, lapsed)
		if total != 1 || len(rows) != 1 {
			t.Fatalf("asked for what lapsed, the record lists %d decisions, want 1", total)
		}
		if rows[0].Rows != 1 || rows[0].States[triage.LapsedState] != 1 ||
			rows[0].States[triage.Proposed] != 0 || rows[0].State() != string(triage.LapsedState) {
			t.Errorf("asked for what lapsed, the decision reads %d rows in %v (%q), want the one lapsed row",
				rows[0].Rows, rows[0].States, rows[0].State())
		}

		rows, _ = f.auditedDecisions(t, f.reviewer, triage.Filter{})
		if len(rows) != 1 || rows[0].Rows != 3 || rows[0].State() != triage.SeveralStates {
			t.Errorf("asked for everything, the decision reads %+v, want three rows in more than one state", rows)
		}

		approved := triage.Filter{States: []triage.State{triage.Approved}}
		if _, total := f.auditedDecisions(t, f.reviewer, approved); total != 0 {
			t.Errorf("asked for what was agreed to, the record lists %d decisions nobody agreed to", total)
		}
	})
}

func TestTheRecordCountsWhatStillAppliesAndDatesTheRowsItMatched(t *testing.T) {
	// Standing is the matching rows that apply now: an agreed decision with one
	// row ended applies at the rest. The date is the earliest matching row's
	// proposal, which the period filter reads, never the decision's own stamp: a
	// decision made by setting rows aside is stamped later than the rows it took.
	each(t, func(t *testing.T, f *fixture) {
		bulk := f.proposes(t, f.triager,
			f.occurrenceIn(f.product, "place-a", access.Public),
			f.occurrenceIn(f.product, "place-b", access.Public),
			f.occurrenceIn(f.product, "place-c", access.Public))
		if err := agreeTo(t.Context(), f.store, f.reviewer, bulk.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		rows := f.rowsOf(t, bulk.DecisionID)
		f.ends(t, rows[0].ID, time.Now().UTC())
		later := rows[0].ProposedAt.Add(72 * time.Hour)
		if _, err := f.db.DB.NewUpdate().Table("decision").Set(`"proposed_at" = ?`, later).
			Where(`"id" = ?`, bulk.DecisionID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		got, _ := f.auditedDecisions(t, f.reviewer, triage.Filter{})
		if len(got) != 1 {
			t.Fatalf("the record lists %d decisions, want 1", len(got))
		}
		if got[0].Standing != 2 {
			t.Errorf("an agreed decision with one of three rows ended reads %d standing, want 2", got[0].Standing)
		}
		if !got[0].ProposedAt.Equal(rows[0].ProposedAt) {
			t.Errorf("the decision is dated %v, want its earliest row's proposal, %v",
				got[0].ProposedAt, rows[0].ProposedAt)
		}
	})
}

func TestTheRecordCountsNamesThatMergedAsOneIssue(t *testing.T) {
	// A decision stays filed under the name it was made against when two
	// names are later found to be one issue, so the count is of the issue
	// each row is read as.
	each(t, func(t *testing.T, f *fixture) {
		second := f.secondIssue(t)
		other := f.occurrenceIn(f.product, "place-b", access.Public)
		other.VulnerabilityID = second
		bulk := f.proposes(t, f.triager, f.occurrenceIn(f.product, "place-a", access.Public), other)

		issues := func() int {
			got, _ := f.auditedDecisions(t, f.reviewer, triage.Filter{})
			for _, row := range got {
				if row.Decision.ID == bulk.DecisionID {
					return row.Issues
				}
			}
			t.Fatalf("the decision is not in the record")
			return 0
		}
		if n := issues(); n != 2 {
			t.Fatalf("a decision over two issues reads %d issues", n)
		}
		if _, err := f.db.DB.NewUpdate().Table("vulnerability").Set(`"issue_id" = ?`, f.issue).
			Where(`"id" = ?`, second).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if n := issues(); n != 1 {
			t.Errorf("once the two names are one issue, the decision reads %d issues, want 1", n)
		}
	})
}
