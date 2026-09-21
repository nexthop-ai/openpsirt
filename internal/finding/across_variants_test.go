package finding_test

import (
	"slices"
	"sort"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestWhatIsSpecificToAVariantIsComparedWithinItsBranch(t *testing.T) {
	// "Specific to this variant" is a statement about the other variants of
	// the same branch. Compared across the product, a branch whose one
	// variant holds an issue would make that issue read as specific to a
	// variant on every other branch too.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		mellanox := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, mellanox, through(libnl))
		// The same variant as the fixture's own, on another branch.
		older := f.anotherBranch(t, "202411")
		f.shippedTo(t, older, through(libnl))

		// One issue on both variants of master, one on mellanox alone, and
		// the second also on broadcom of the other branch.
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(ctx, mellanox, f.runOn(t, mellanox), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(ctx, older, f.runOn(t, older), []finding.Reported{
			found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		listed := func(t *testing.T, scope finding.Scope, spread finding.VariantSpread) []string {
			t.Helper()
			rows, total, err := f.store.Groups(ctx, who, scope, 50, 0,
				finding.Filter{AcrossVariants: spread})
			if err != nil {
				t.Fatal(err)
			}
			if total != len(rows) {
				t.Errorf("%d rows listed and %d counted, which do not agree", len(rows), total)
			}
			names := make([]string, 0, len(rows))
			for _, row := range rows {
				names = append(names, row.Vulnerability)
			}
			sort.Strings(names)
			return names
		}
		same := func(t *testing.T, what string, got []string, want ...string) {
			t.Helper()
			if !slices.Equal(got, want) {
				t.Errorf("%s lists %v, want %v", what, got, want)
			}
		}
		master := finding.Scope{ProductID: &f.productID, StreamID: f.scope.StreamID}

		// The other branch's broadcom build holds CVE-2026-2, and it is
		// still specific to mellanox on master.
		same(t, "specific to mellanox on master",
			listed(t, f.scopeOf(t, mellanox), finding.OnlyThisVariant), "CVE-2026-2")
		same(t, "specific to broadcom on master",
			listed(t, f.scope, finding.OnlyThisVariant))
		// What every variant of master holds, asked with no variant named.
		same(t, "common to every variant of master",
			listed(t, master, finding.EveryVariant), "CVE-2026-1")
		same(t, "common to every variant of master, asked from mellanox",
			listed(t, f.scopeOf(t, mellanox), finding.EveryVariant), "CVE-2026-1")
		// Across the whole product the other branch's one build lacks
		// CVE-2026-1 and master's broadcom lacks CVE-2026-2.
		same(t, "common to every build of the product",
			listed(t, f.wholeProduct(), finding.EveryVariant))
		// Specific to a variant nobody named is nothing, rather than
		// everything or a fault.
		same(t, "specific to no variant",
			listed(t, f.wholeProduct(), finding.OnlyThisVariant))
		// And nothing narrowed lists all three on the product.
		same(t, "unnarrowed", listed(t, f.wholeProduct(), finding.AnyVariants),
			"CVE-2026-1", "CVE-2026-2")
	})
}
