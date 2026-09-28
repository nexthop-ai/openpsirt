// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// What an act of assigning everything that matches could not move is said,
// including a place nobody holds. A caller who reads undisclosed work and
// triages only the disclosed kind moves the disclosed piece and leaves the
// other, and the answer names the one left.
func TestAssigningEverythingMatchingNamesAnUnheldPieceItCouldNotMove(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", swss), found("CVE-2026-2", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		undisclosed := f.issueID(t, "CVE-2026-2")
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Private).
			Where("vulnerability_id = ?", undisclosed).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PublicTriage, access.Assigner, access.PrivateRead)
		colleague, err := access.NewStore(f.db.DB).Ensure(ctx, "colleague@example.com", "Colleague", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		admits := func(context.Context, bun.IDB, access.Visibility) error { return nil }

		handed, err := f.store.AssignMatching(ctx, who, f.scope, finding.Filter{}, nil, &colleague.ID, admits)
		if err != nil {
			t.Fatal(err)
		}
		if handed.Pieces != 2 {
			t.Fatalf("the act saw %d pieces, want both", handed.Pieces)
		}
		left := map[int64]bool{}
		for _, piece := range handed.Left {
			left[piece.VulnerabilityID] = true
		}
		if !left[undisclosed] {
			t.Errorf("the undisclosed piece nobody holds was not moved and is not named as left: %+v", handed.Left)
		}
		if left[f.issueID(t, "CVE-2026-1")] {
			t.Error("the disclosed piece was moved and is named as left")
		}
	})
}
