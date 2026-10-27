// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"context"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestAGroupedDecisionReadsItsOccurrencesInTheTransactionItWritesIn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := triage.Proposal{
			Occurrence: f.at(), Outcome: triage.NotApplicable, Justification: triage.CodeNotInExecutePath,
			Reasoning: "The parser is never reached: we only call the encoder.", By: f.proposer,
		}
		also := f.at()
		also.OccurrenceIdentity = "another-place-of-libfoo"
		asked := 0
		decided, err := f.store.ProposeGrouped(ctx, f.triager, first,
			func(_ context.Context, db bun.IDB) ([]triage.Occurrence, error) {
				asked++
				if _, ok := db.(bun.Tx); !ok {
					t.Errorf("the occurrences were read through %T, outside the transaction that writes", db)
				}
				return []triage.Occurrence{also}, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if asked == 0 {
			t.Fatal("the occurrences were never asked for")
		}
		var rows []triage.DecisionOccurrence
		if err := f.db.DB.NewSelect().Model(&rows).Where(`"decision_id" = ?`, decided.DecisionID).
			Order("occurrence_identity").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 || rows[0].OccurrenceIdentity != also.OccurrenceIdentity || rows[1].OccurrenceIdentity != first.Occurrence.OccurrenceIdentity {
			t.Errorf("the decision wrote %+v; want the first occurrence and the one asked for", rows)
		}
	})
}
