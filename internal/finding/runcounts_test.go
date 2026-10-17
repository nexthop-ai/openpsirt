// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// What a run opened and closed is counted as issues at components, at the
// visibilities the reader may see, the same on a page of receipts as on the
// run's own screen. A run of another build counts nothing here. Runs on every engine, because each engine plans the
// count through the indexes on the run columns differently.
func TestARunsCountsAreIssuesAtComponentsTheReaderMaySee(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())

		// The first run opens an issue at a component sitting in two places,
		// and one at each of two components sitting in one.
		first := f.run(t)
		if _, err := f.store.Apply(ctx, f.target, first, []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss), found("CVE-2026-3", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		// One of them undisclosed.
		if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"visibility" = ?`, access.Private).
			Where(`"target_id" = ?`, f.target).
			Where(`"vulnerability_id" = ?`, f.issueID(t, "CVE-2026-2")).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// The second stops reporting both single-place issues and opens
		// another at the component in two places.
		second := f.run(t)
		if _, err := f.store.Apply(ctx, f.target, second, []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-4", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// A run that changed nothing.
		third := f.run(t)
		if _, err := f.store.Apply(ctx, f.target, third, []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-4", libnl),
		}); err != nil {
			t.Fatal(err)
		}

		// A run of another build of the product, which opened what the first
		// run here did.
		elsewhere := f.anotherBuild(t, "v1")
		f.shippedTo(t, elsewhere, twoConsumers())
		foreign := f.runOn(t, elsewhere)
		if _, err := f.store.Apply(ctx, elsewhere, foreign, []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss), found("CVE-2026-3", teamd),
		}); err != nil {
			t.Fatal(err)
		}

		for _, reader := range []struct {
			what  string
			who   access.Subject
			first finding.Change
			then  finding.Change
		}{
			{"a reader of disclosed findings", f.holding(t, access.PublicRead),
				finding.Change{Opened: 2}, finding.Change{Opened: 1, Closed: 1}},
			{"a reader of every finding", f.holding(t, access.PublicRead, access.PrivateRead),
				finding.Change{Opened: 3}, finding.Change{Opened: 1, Closed: 2}},
		} {
			t.Run(reader.what, func(t *testing.T) {
				changed, err := f.store.Changes(ctx, reader.who, f.target,
					[]int64{first, second, third, foreign})
				if err != nil {
					t.Fatal(err)
				}
				want := map[int64]finding.Change{
					first: reader.first, second: reader.then, third: {}, foreign: {},
				}
				if len(changed) != len(want) {
					t.Errorf("counted %d runs, want %d: %+v", len(changed), len(want), changed)
				}
				for run, change := range want {
					if got, ok := changed[run]; !ok || got != change {
						t.Errorf("run %d counted %+v (present %v), want %+v", run, got, ok, change)
					}
					if run == foreign {
						continue
					}
					ran, err := f.store.Ran(ctx, reader.who, f.target, run)
					if err != nil {
						t.Fatal(err)
					}
					if ran.Opened != change.Opened || ran.Closed != change.Closed {
						t.Errorf("run %d reads as opened %d and closed %d on its own screen, want %+v",
							run, ran.Opened, ran.Closed, change)
					}
				}
			})
		}
	})
}
