// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestWhatAnInclusionDisclosesIsReadThroughTheCallersVisibility(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		ctx := t.Context()
		w.inventory(t, w.Build.ID)
		w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		codeFinding := w.codeFindings(t, w.Build.ID)[0]
		decided := w.dismissed(t, codeFinding, time.Now().UTC())
		const said = "the attribute is bounded by its caller"
		if _, err := w.DB.DB.NewInsert().Model(&triage.Revision{DecisionID: decided.DecisionID, Ordinal: 1, Body: said,
			WrittenBy: decided.ProposedBy, WrittenAt: time.Now().UTC().Truncate(time.Microsecond)}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		occurrences := []string{codeFinding.OccurrenceIdentity}

		reads, err := disclosing(ctx, w.DB.DB, w.holding(t, "analyst", access.InternalRead), w.Product.ID, occurrences)
		if err != nil {
			t.Fatal(err)
		}
		if len(reads.Authors) != 1 || len(reads.Authors[0].Notes) != 1 || reads.Authors[0].Notes[0].Body != said ||
			reads.Authors[0].Notes[0].Comment {
			t.Errorf("an internal reader is told an inclusion discloses %+v; want the one revision of reasoning", reads.Authors)
		}
		if len(reads.Said) == 0 || len(reads.Paths) == 0 {
			t.Errorf("an internal reader is told an inclusion discloses the paths %q and messages %+v; want the code finding's",
				reads.Paths, reads.Said)
		}

		// The decision is internal, and reading undisclosed work does not read it.
		other, err := disclosing(ctx, w.DB.DB, w.holding(t, "embargo", access.PrivateRead), w.Product.ID, occurrences)
		if err != nil {
			t.Fatal(err)
		}
		if len(other.Authors) != 0 {
			t.Errorf("a reader of undisclosed work alone is told an inclusion discloses %+v; want no writing", other.Authors)
		}
	})
}
