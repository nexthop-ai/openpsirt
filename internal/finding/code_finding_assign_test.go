// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"slices"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// A code finding whose rows sit at two withheld visibilities asks its recipient about
// both. Undisclosed and internal work are read under separate grants, so
// neither one is the stricter, and a recipient cleared for one is not cleared
// for the other.
func TestACodeFindingOfTwoVisibilitiesAsksItsRecipientAboutBoth(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		var ids []int64
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).Column("id").
			Where(`"target_id" = ?`, f.target).Order("id").Scan(ctx, &ids); err != nil {
			t.Fatal(err)
		}
		if len(ids) < 2 {
			t.Fatalf("the build holds %d findings; want one at each of two occurrences", len(ids))
		}
		for i, id := range ids {
			visibility := access.Internal
			if i == 0 {
				visibility = access.Private
			}
			if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
				Set(`"kind" = ?`, "analysis").Set(`"visibility" = ?`, visibility).
				Set(`"occurrence_identity" = ?`, "code-finding-1").
				Where(`"id" = ?`, id).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		who := f.planner(t, access.InternalTriage, access.PrivateTriage, access.Assigner)
		colleague, err := access.NewStore(f.db.DB).Ensure(ctx, "colleague@example.com", "Colleague", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var asked []access.Visibility
		admits := func(_ context.Context, _ bun.IDB, withheld []access.Visibility) error {
			asked = withheld
			return nil
		}
		moved, withheld, err := f.store.AssignCodeFinding(ctx, who, f.target, "code-finding-1", &colleague.PartyID, admits)
		if err != nil {
			t.Fatal(err)
		}
		both := []access.Visibility{access.Private, access.Internal}
		if !slices.Equal(asked, both) {
			t.Errorf("the recipient was asked about %v; want both", asked)
		}
		if !slices.Equal(withheld, both) {
			t.Errorf("the act reports %v withheld; want both", withheld)
		}
		if moved != int64(len(ids)) {
			t.Errorf("%d rows moved; want the code finding's %d", moved, len(ids))
		}
	})
}
