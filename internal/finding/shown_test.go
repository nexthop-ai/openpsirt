// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// TestABuildWithNoDisplayNamesIsShownByItsNames pins the fallback a list
// reads a build's labels with: a product, stream or variant with no display
// name is labeled by its name.
func TestABuildWithNoDisplayNamesIsShownByItsNames(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-100*24*time.Hour))
		mild := found("CVE-2026-1", libnl)
		mild.Issue.Severity = "low"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"product", "stream", "variant"} {
			if _, err := f.db.DB.NewUpdate().Table(table).
				Set("display_name = ?", "").Where("1 = 1").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}

		who := f.holding(t, access.PublicTriage)
		late, _, err := f.store.RunningOutPage(t.Context(), who, finding.Scope{},
			90*24*time.Hour, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(late) == 0 {
			t.Fatal("nothing is running out, so this checked nothing")
		}
		for _, row := range late {
			if row.Product == "" || row.ProductName != row.Product ||
				row.Stream == "" || row.StreamName != row.Stream ||
				row.Variant == "" || row.VariantName != row.Variant {
				t.Errorf("the row labels its build %q/%q, %q/%q, %q/%q; want each label to be its name",
					row.Product, row.ProductName, row.Stream, row.StreamName,
					row.Variant, row.VariantName)
			}
		}
	})
}
