// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// TestAStoreAtAMomentReadsDeadlinesAtIt pins the moment a file's pages read
// at: a deadline is passed or not as of the moment given, in a product's list
// and across products, whatever the clock says.
func TestAStoreAtAMomentReadsDeadlinesAtIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// Due a month from now, so the clock alone says it is not late.
		due := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
		if _, err := f.db.NewUpdate().Table("finding").Set(`"due_at" = ?`, due).
			Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		reader := f.holding(t, access.PublicRead)
		late := finding.Filter{Overdue: true}
		for _, c := range []struct {
			name string
			at   time.Time
			want bool
		}{
			{"before the deadline", due.Add(-time.Hour), false},
			{"after the deadline", due.Add(time.Hour), true},
		} {
			_, listed, err := finding.NewStore(f.db.DB).At(c.at).Groups(ctx, reader, f.wholeProduct(), 50, 0, late)
			if err != nil {
				t.Fatal(err)
			}
			if (listed > 0) != c.want {
				t.Errorf("%s, the product's list holds %d overdue", c.name, listed)
			}
			_, across, err := finding.NewStore(f.db.DB).At(c.at).Anywhere(ctx, reader, 50, 0, late)
			if err != nil {
				t.Fatal(err)
			}
			if (across > 0) != c.want {
				t.Errorf("%s, the list across products holds %d overdue", c.name, across)
			}
		}
	})
}
