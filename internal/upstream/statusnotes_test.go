// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// toldOfNotes records a supplier's statement in March with the notes first
// given, has a decision cite it, records it again in June with the notes then
// given, and answers how many alerts the decision's proposer holds.
func toldOfNotes(t *testing.T, w *world, first, then string) int {
	t.Helper()
	ctx := t.Context()
	claim := *w.statement(ownBuild, "")
	claim.Statement = "The vulnerable function is never called."
	if err := w.Access.GrantRole(ctx, w.proposer.ID, w.fork.ID, access.PublicTriage); err != nil {
		t.Fatal(err)
	}
	record := func(name string, month time.Month, notes string) {
		t.Helper()
		at := time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC)
		said := claim
		said.Notes = notes
		if _, _, err := w.findings.RecordStatements(ctx, w.admin, w.fork.ID, finding.Supplied{
			Source: finding.FromVex, Identifier: "https://supplier.test/vex/" + name,
			Publisher: "Supplier", Document: name + ".json", Digest: name + month.String(), SaidAt: &at,
		}, []finding.Statement{said}); err != nil {
			t.Fatal(err)
		}
	}
	record("march", time.March, first)
	var cited int64
	if err := w.DB.DB.NewSelect().TableExpr(`"received_vex_statement"`).ColumnExpr(`"id"`).
		Where(`"product_id" = ? AND "source" = ? AND "document" = ?`, w.fork.ID, finding.FromVex, "march.json").
		Scan(ctx, &cited); err != nil {
		t.Fatal(err)
	}
	w.decisionCiting(w.forkBuild, ownBuild, libnl.Name, triage.NotApplicable,
		triage.CodeNotInExecutePath, &cited)

	record("june", time.June, then)
	if _, _, err := notify.NewWatch(w.DB.DB, slog.New(slog.DiscardHandler)).Once(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _, err := notify.NewStore(w.DB.DB).Waiting(ctx, w.proposer, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	told := 0
	for _, row := range rows {
		if row.Kind == notify.StatementRevised && row.ClearedAt == nil {
			told++
		}
	}
	return told
}

func TestASupplierRevisingOnlyTheNotesOfACitedStatementTellsTheDecision(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.read()
		if told := toldOfNotes(t, w, "Checked against 4.2.", "Checked against 4.3."); told != 1 {
			t.Errorf("the supplier revising only the notes told the decision %d times, want once", told)
		}
	})
}

// A cited statement holding no notes, said again with notes, is the row stored
// before notes were kept: the evidence has not moved.
func TestACitedStatementGainingNotesTellsNobody(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.read()
		if told := toldOfNotes(t, w, "", "Checked against 4.2."); told != 0 {
			t.Errorf("the statement gaining notes told the decision %d times, want none", told)
		}
	})
}
