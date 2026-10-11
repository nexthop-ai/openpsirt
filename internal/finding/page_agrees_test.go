// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAPageOfGroupsHoldsTheRowsItsTotalCounts(t *testing.T) {
	// Two variants of one product: CVE-2026-1 open in both, CVE-2026-2 in
	// the first alone and decided nowhere. Differing between the builds and
	// undecided is CVE-2026-2, so the page holds it and the total says one.
	// The page carries its total as a window count beside a HAVING that
	// counts distinct builds and holds a second condition, which is the
	// shape one engine answers with no rows.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		later := time.Now().Add(time.Hour)

		undecided := []finding.ClaimStanding{finding.StandingUndecided}
		for _, asked := range []struct {
			name   string
			filter finding.Filter
		}{
			{"differing", finding.Filter{DiffersBetweenBuilds: true}},
			{"differing and undecided", finding.Filter{DiffersBetweenBuilds: true, States: undecided}},
			{"differing and opened before", finding.Filter{DiffersBetweenBuilds: true, OpenedBefore: &later}},
			{"differing and undecided, by age", finding.Filter{
				DiffersBetweenBuilds: true, States: undecided, SortBy: finding.ByAge}},
			{"differing and undecided, by deadline", finding.Filter{
				DiffersBetweenBuilds: true, States: undecided, SortBy: finding.ByDeadline, Ascending: true}},
			{"differing and undecided, by severity", finding.Filter{
				DiffersBetweenBuilds: true, States: undecided, SortBy: finding.BySeverity}},
		} {
			groups, total, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0, asked.filter)
			if err != nil {
				t.Fatal(err)
			}
			if total != 1 || len(groups) != 1 || groups[0].Vulnerability != "CVE-2026-2" {
				t.Errorf("%s: total %d and a page of %d groups %+v, want CVE-2026-2 and a total of 1",
					asked.name, total, len(groups), groups)
			}
		}
	})
}
