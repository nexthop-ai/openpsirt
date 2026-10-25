// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"context"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestAGroupedClaimReadsItsPlacesInTheTransactionItWritesIn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := triage.Proposal{
			Place: f.at(), Outcome: triage.NotApplicable, Justification: triage.CodeNotInExecutePath,
			Reasoning: "The parser is never reached: we only call the encoder.", By: f.proposer,
		}
		also := f.at()
		also.PlaceIdentity = "another-place-of-libfoo"
		asked := 0
		decided, err := f.store.ProposeGrouped(ctx, f.triager, first,
			func(_ context.Context, db bun.IDB) ([]triage.Place, error) {
				asked++
				if _, ok := db.(bun.Tx); !ok {
					t.Errorf("the places were read through %T, outside the transaction that writes", db)
				}
				return []triage.Place{also}, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if asked == 0 {
			t.Fatal("the places were never asked for")
		}
		var rows []triage.Decision
		if err := f.db.DB.NewSelect().Model(&rows).Where(`"claim_id" = ?`, decided.ClaimID).
			Order("place_identity").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 || rows[0].PlaceIdentity != also.PlaceIdentity || rows[1].PlaceIdentity != first.Place.PlaceIdentity {
			t.Errorf("the claim wrote %+v; want the first place and the one asked for", rows)
		}
	})
}
