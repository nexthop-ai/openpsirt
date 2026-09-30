// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// rowsOf is every decision one claim wrote, oldest first.
func (f *fixture) rowsOf(t *testing.T, claimID int64) []triage.Decision {
	t.Helper()
	var rows []triage.Decision
	if err := f.db.DB.NewSelect().Model(&rows).Where("de.claim_id = ?", claimID).
		Order("de.id ASC").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

// auditedClaims reads the whole record a claim at a time.
func (f *fixture) auditedClaims(t *testing.T, who access.Subject, filter triage.Filter) ([]triage.JudgedClaim, int) {
	t.Helper()
	rows, total, err := f.store.AuditClaims(t.Context(), who, filter, time.Time{}, time.Time{}, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rows, total
}

func TestTheRecordListsAClaimOnceHoweverManyPlacesItCovers(t *testing.T) {
	// One argument by one person across several places is one entry, counted
	// once in the total, and the entry says how much it covers. Only the rows
	// the reader may see are counted: a claim with an undisclosed row reads to
	// somebody holding public reading alone as the rows they may read.
	each(t, func(t *testing.T, f *fixture) {
		in := f.build(t, f.product, "for-the-record")
		libfoo := f.component(t, "libfoo", "1.2.3")
		libbar := f.component(t, "libbar", "2.0.0")
		secret := f.component(t, "libsecret", "0.1.0")
		f.finds(t, in, libfoo, "place-a", access.Public)
		f.finds(t, in, libfoo, "place-b", access.Public)
		f.finds(t, in, libbar, "place-c", access.Public)
		f.finds(t, in, secret, "place-d", access.Private)
		// A disclosed place that an undisclosed build also ships, under a
		// name only a reader of undisclosed findings may learn.
		f.finds(t, f.build(t, f.product, "embargoed"), f.component(t, "libhidden", "1.0.0"),
			"place-c", access.Private)

		insider := f.privately(t)
		bulk := f.proposes(t, insider,
			f.placeIn(f.product, "place-a", access.Public),
			f.placeIn(f.product, "place-b", access.Public),
			f.placeIn(f.product, "place-c", access.Public),
			f.placeIn(f.product, "place-d", access.Private))
		single := f.proposes(t, f.triager, f.placeIn(f.product, "place-e", access.Public))

		rows, total := f.auditedClaims(t, f.reviewer, triage.Filter{})
		if total != 2 || len(rows) != 2 {
			t.Fatalf("the record lists %d entries (%d on the page), want one per claim: 2", total, len(rows))
		}
		if rows[0].Claim.ID != single.ClaimID || rows[1].Claim.ID != bulk.ClaimID {
			t.Fatalf("the record lists claims %d, %d; want the newest first: %d, %d",
				rows[0].Claim.ID, rows[1].Claim.ID, single.ClaimID, bulk.ClaimID)
		}
		got := rows[1]
		if got.Decisions != 3 || got.Places != 3 || got.Issues != 1 || got.Products != 1 {
			t.Errorf("a public reader is told the claim covers %d decisions, %d places, %d issues, "+
				"%d products; want the three public rows of one issue in one product",
				got.Decisions, got.Places, got.Issues, got.Products)
		}
		if got.Components != 2 {
			t.Errorf("a public reader is told of %d components, want libfoo and libbar alone", got.Components)
		}
		if got.Component != "libfoo" || got.Issue == "" || got.Reasoning == "" || got.ProposedByName == "" {
			t.Errorf("the entry does not say what it was about, or who argued it: %+v", got)
		}
		if got.State() != string(triage.Proposed) || got.Standing != 0 {
			t.Errorf("a claim waiting for agreement reads %q with %d standing", got.State(), got.Standing)
		}

		// Its proposer reads every row, the undisclosed one included.
		rows, _ = f.auditedClaims(t, insider, triage.Filter{})
		for _, row := range rows {
			if row.Claim.ID == bulk.ClaimID && (row.Decisions != 4 || row.Components != 4) {
				t.Errorf("a reader of both visibilities is told of %d decisions and %d components, want 4 and 4",
					row.Decisions, row.Components)
			}
		}

		// Somebody who reads another product alone is told of nothing here,
		// the count included.
		stranger := f.holding(t, "stranger", map[int64][]access.Role{
			f.secondProduct(t): {access.PublicRead, access.PrivateRead},
		})
		if _, total := f.auditedClaims(t, stranger, triage.Filter{}); total != 0 {
			t.Errorf("a reader of another product is told of %d claims here", total)
		}
	})
}

func TestTheRecordCountsOnlyTheRowsTheFiltersMatch(t *testing.T) {
	// A claim is listed where any of its rows answer the question, and its
	// counts are of those rows alone. Asked for what lapsed, a claim with one
	// lapsed row of three reads as one lapsed row rather than as the whole
	// claim, which is what the reader did not ask for.
	each(t, func(t *testing.T, f *fixture) {
		bulk := f.proposes(t, f.triager,
			f.placeIn(f.product, "place-a", access.Public),
			f.placeIn(f.product, "place-b", access.Public),
			f.placeIn(f.product, "place-c", access.Public))
		f.ends(t, f.rowsOf(t, bulk.ClaimID)[0].ID, time.Now().UTC())

		lapsed := triage.Filter{States: []triage.State{triage.LapsedState}}
		rows, total := f.auditedClaims(t, f.reviewer, lapsed)
		if total != 1 || len(rows) != 1 {
			t.Fatalf("asked for what lapsed, the record lists %d claims, want 1", total)
		}
		if rows[0].Decisions != 1 || rows[0].States[triage.LapsedState] != 1 ||
			rows[0].States[triage.Proposed] != 0 || rows[0].State() != string(triage.LapsedState) {
			t.Errorf("asked for what lapsed, the claim reads %d decisions in %v (%q), want the one lapsed row",
				rows[0].Decisions, rows[0].States, rows[0].State())
		}

		rows, _ = f.auditedClaims(t, f.reviewer, triage.Filter{})
		if len(rows) != 1 || rows[0].Decisions != 3 || rows[0].State() != triage.SeveralStates {
			t.Errorf("asked for everything, the claim reads %+v, want three rows in more than one state", rows)
		}

		approved := triage.Filter{States: []triage.State{triage.Approved}}
		if _, total := f.auditedClaims(t, f.reviewer, approved); total != 0 {
			t.Errorf("asked for what was agreed to, the record lists %d claims nobody agreed to", total)
		}
	})
}
