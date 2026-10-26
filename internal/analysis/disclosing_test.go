// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestWhatAMoveDisclosesIsReadThroughTheCallersVisibility(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		ctx := t.Context()
		w.inventory(t, w.Target.ID)
		w.send(t, w.Target.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		lead := w.leads(t, w.Target.ID)[0]
		decided := w.dismissed(t, lead, time.Now().UTC())
		const said = "the attribute is bounded by its caller"
		if _, err := w.DB.DB.NewInsert().Model(&triage.Revision{ClaimID: decided.ClaimID, Ordinal: 1, Body: said,
			WrittenBy: decided.ProposedBy, WrittenAt: time.Now().UTC().Truncate(time.Microsecond)}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		places := []string{lead.PlaceIdentity}

		reads, err := disclosing(ctx, w.DB.DB, w.holding(t, "analyst", access.InternalRead), w.Product.ID, places)
		if err != nil {
			t.Fatal(err)
		}
		if len(reads.Authors) != 1 || len(reads.Authors[0].Notes) != 1 || reads.Authors[0].Notes[0].Body != said ||
			reads.Authors[0].Notes[0].Comment {
			t.Errorf("an internal reader is told a move discloses %+v; want the one revision of reasoning", reads.Authors)
		}
		if len(reads.Said) == 0 || len(reads.Paths) == 0 {
			t.Errorf("an internal reader is told a move discloses the paths %q and messages %+v; want the lead's",
				reads.Paths, reads.Said)
		}

		// The claim is internal, and reading undisclosed work does not read it.
		other, err := disclosing(ctx, w.DB.DB, w.holding(t, "embargo", access.PrivateRead), w.Product.ID, places)
		if err != nil {
			t.Fatal(err)
		}
		if len(other.Authors) != 0 {
			t.Errorf("a reader of undisclosed work alone is told a move discloses %+v; want no writing", other.Authors)
		}
	})
}
