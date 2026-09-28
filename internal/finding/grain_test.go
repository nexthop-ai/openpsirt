// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// The by-component view counts what the findings list holds under the same
// filter. A condition over a group is asked of one issue at one fold, as the
// list asks it, and never of a whole component: "exploited" does not keep a
// component's other issues, and "has a fix" does not drop a component because
// one of its issues has none.
func TestTheViewByComponentHoldsTheListsPopulationUnderAGroupFilter(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		used := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "critical", Exploited: true},
			Component: swss, FixState: finding.FixedUpstream, FixedIn: "1.0.1",
		}
		reported := []finding.Reported{used}
		for _, id := range []string{"CVE-2026-2", "CVE-2026-3"} {
			reported = append(reported, finding.Reported{
				Issue:     finding.Named{Identifier: id, Severity: "low"},
				Component: swss, FixState: finding.NoFix,
			})
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		for name, filter := range map[string]finding.Filter{
			"exploited":  {Exploited: true},
			"has a fix":  {HasFix: true},
			"fix states": {FixStates: []finding.FixState{finding.FixedUpstream}},
		} {
			_, listed, err := f.store.Groups(ctx, who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if listed != 1 {
				t.Fatalf("%s: the list holds %d rows, want the one exploited and fixable issue", name, listed)
			}
			components, total, err := f.store.ComponentGroups(ctx, who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if total != 1 || len(components) != 1 {
				t.Fatalf("%s: the view by component holds %d components (total %d), want the one the list's row is at",
					name, len(components), total)
			}
			row := components[0]
			if row.Issues != listed {
				t.Errorf("%s: the component contributes %d issues, and the list holds %d", name, row.Issues, listed)
			}
			sum := 0
			for _, n := range row.BySeverity {
				sum += n
			}
			if sum != row.Issues {
				t.Errorf("%s: by severity %v sums to %d of %d issues", name, row.BySeverity, sum, row.Issues)
			}
		}
	})
}
