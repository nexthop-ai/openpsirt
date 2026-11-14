// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// TestAStoreAtAMomentReadsDatesAtIt pins the moment a file's pages read at: a
// deferral has run out or not as of the moment given, whatever the clock says.
func TestAStoreAtAMomentReadsDatesAtIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ships := f.shipping(t)
		// Ran out an hour ago.
		expired := f.datedPast(t, ships, "deferral-ran-out", triage.Deferred)
		ranOut := triage.QueueFilter{Reason: triage.DeferralExpired}
		for _, c := range []struct {
			name string
			at   time.Time
			want int
		}{
			// Two days before, because the server engines keep the date as a day.
			{"before the date", time.Now().Add(-48 * time.Hour), 0},
			{"after the date", time.Now(), 1},
		} {
			waiting, _, err := triage.NewStore(f.db.DB).At(c.at).Queue(t.Context(), f.reviewer, ranOut, 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(waiting) != c.want {
				t.Errorf("%s, %d deferrals have run out, want %d", c.name, len(waiting), c.want)
			}
			for _, one := range waiting {
				if one.Decision.ID != expired.DecisionID {
					t.Errorf("%s, the deferral %d has run out, want %d", c.name, one.Decision.ID, expired.DecisionID)
				}
			}
		}
	})
}
