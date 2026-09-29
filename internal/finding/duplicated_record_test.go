// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestWithdrawingADuplicateKeepsAnExtensionAgreedAfterIt(t *testing.T) {
	// An extension asked for before a ruling and agreed to after it moved the
	// date when it was agreed. Withdrawing a later ruling puts the date back
	// on the extension, not on the ruling before it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		second := f.somebody(t, "second@example.com", access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{Received: "2026-06-01"})
		extended := f.windowAfter(t, "2026-06-01").Add(45 * 24 * time.Hour)

		asked, err := f.store.Extend(ctx, who, f.productID, issue, extended, "The fix slipped.")
		if err != nil {
			t.Fatal(err)
		}
		if !asked.NeedsApproval {
			t.Fatal("a forty-five day extension took effect with nobody agreeing")
		}
		// Everything after this is inside the threshold, so the rulings take
		// effect and only the extension waits.
		if err := setting.NewStore(f.db.DB).Set(ctx, setting.MovementThreshold, "87600h"); err != nil {
			t.Fatal(err)
		}
		f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-05-25"}))
		if _, err := f.store.AgreeToMovement(ctx, second, asked.ID); err != nil {
			t.Fatal(err)
		}
		later := f.duplicate(t, who, issue, f.claim(t, who, finding.Told{Received: "2026-05-28"}))
		if got, want := f.flawEnds(t, issue), f.windowAfter(t, "2026-05-28"); !isAt(got, want) {
			t.Fatalf("the later ruling left the flaw at %v, want %s", got, want)
		}

		if _, err := f.store.WithdrawRuling(ctx, who, f.productID, later.ID); err != nil {
			t.Fatal(err)
		}
		if got := f.flawEnds(t, issue); !isAt(got, extended) {
			t.Errorf("the flaw ends %v, want the %s two people agreed to", got, extended)
		}
	})
}

func TestARulingsReasoningIsReadOnlyUnderTheReportRule(t *testing.T) {
	// A disclosed embargo's history is public, and a ruling's reasoning is
	// about a stranger's report. Somebody who may not read the product's
	// reports reads the movement without it, and without the ruling or the
	// report it names.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.flaw(t, who, finding.Told{FoundHere: true})
		reference := f.claim(t, who, finding.Told{Received: "2025-01-01"})
		said := "The reporter's screenshot shows the same crash."
		if _, err := f.store.Rule(ctx, who, f.productID, finding.Ruled{
			References: []string{reference}, Disposition: finding.Duplicate,
			DuplicateOf: issue, Reasoning: said,
		}); err != nil {
			t.Fatal(err)
		}
		// The date is long past, so disclosing takes effect at once.
		if _, err := f.store.Disclose(ctx, who, f.productID, issue, "Fixed everywhere."); err != nil {
			t.Fatal(err)
		}

		ruled := func(rows []finding.Movement) finding.Movement {
			t.Helper()
			for _, row := range rows {
				if row.Act == finding.Duplicated {
					return row
				}
			}
			t.Fatalf("no movement a ruling recorded in %+v", rows)
			return finding.Movement{}
		}
		inside := ruled(f.movedBy(t, who, issue))
		if inside.Reason != said || inside.RulingID == nil || inside.Report != reference {
			t.Errorf("a reader of reports reads %+v, want the reasoning, ruling and report", inside)
		}

		public := f.somebody(t, "public@example.com", access.PublicRead)
		rows, err := f.store.Movements(ctx, public, f.productID, issue)
		if err != nil {
			t.Fatal(err)
		}
		outside := ruled(rows)
		if outside.Reason != "" || outside.RulingID != nil || outside.FlawReportID != nil ||
			outside.Report != "" {
			t.Errorf("a public reader reads %+v, want none of the ruling", outside)
		}
	})
}
