// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// A kind whose working out fails is reported and left as it stands, and the
// kinds after it are still worked out.
func TestAFailingConditionSilencesNoOtherAndClearsNothing(t *testing.T) {
	eachWithDB(t, func(t *testing.T, db *database.DB, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		waiting := []notify.Holds{{About: "decision-waiting 7", Body: "A decision has waited.", Link: "/decisions/7"}}
		if _, _, err := s.Reconcile(ctx, me.ID, notify.DecisionWaiting, waiting); err != nil {
			t.Fatal(err)
		}
		broken := errors.New("the derivation failed")
		opened, cleared, err := notify.DeriveForTest(notify.NewWatch(db.DB, discard()), ctx,
			notify.DerivationForTest{Kind: notify.DecisionWaiting,
				Of: func(context.Context) (map[int64][]notify.Holds, error) { return nil, broken }},
			notify.DerivationForTest{Kind: notify.QueueUntaken,
				Of: func(context.Context) (map[int64][]notify.Holds, error) {
					return map[int64][]notify.Holds{me.ID: {{About: "queue 3", Body: "Work waits.", Link: "/assignments"}}}, nil
				}},
		)
		if !errors.Is(err, broken) {
			t.Errorf("the failure is reported as %v, want the derivation's", err)
		}
		if opened != 1 || cleared != 0 {
			t.Errorf("opened=%d cleared=%d, want the later kind opened and nothing cleared", opened, cleared)
		}
		rows, _, err := s.Waiting(ctx, me, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[notify.Kind]bool{}
		for _, row := range rows {
			kinds[row.Kind] = true
		}
		if !kinds[notify.DecisionWaiting] || !kinds[notify.QueueUntaken] {
			t.Errorf("open notices are %v, want the failing kind's left open and the later one opened", kinds)
		}
	})
}
