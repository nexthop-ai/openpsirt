package finding_test

import (
	"slices"
	"sort"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// builtAs is one variant's build of one branch, for a pair the fixture's own
// helpers do not make: they each hold one of the two fixed.
func (f *fixture) builtAs(t *testing.T, streamID int64, variant string) int64 {
	t.Helper()
	cat := catalog.NewStore(f.db.DB)
	declared, err := cat.VariantByName(t.Context(), f.productID, variant)
	if err != nil {
		t.Fatalf("variant %s: %v", variant, err)
	}
	target, err := cat.TargetFor(t.Context(), streamID, declared.ID)
	if err != nil {
		t.Fatalf("build of %s: %v", variant, err)
	}
	return target.ID
}

// variantID is what a variant's name resolves to, for a selection naming one.
func (f *fixture) variantID(t *testing.T, name string) int64 {
	t.Helper()
	declared, err := catalog.NewStore(f.db.DB).VariantByName(t.Context(), f.productID, name)
	if err != nil {
		t.Fatalf("variant %s: %v", name, err)
	}
	return declared.ID
}

func TestWhatIsSpecificToAVariantIsComparedOnItsOwnBranch(t *testing.T) {
	// A row is specific to a variant when no other variant of the branch it
	// sits on holds the issue. Compared over the selection's branches
	// together, a selection naming a variant and leaving the branch at all
	// drops a row because a different variant of a different branch has it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()

		// Two branches, both built as both variants.
		older := f.anotherBranch(t, "202411")
		olderStream := f.scopeOf(t, older).StreamID
		builds := map[string]int64{
			"broadcom/master": f.target,
			"mellanox/master": f.anotherVariant(t, "mellanox"),
			"broadcom/202411": older,
			"mellanox/202411": f.builtAs(t, *olderStream, "mellanox"),
		}
		for name, target := range builds {
			if target == f.target {
				f.shipped(t, through(libnl))
				continue
			}
			f.shippedTo(t, target, through(libnl))
			_ = name
		}

		// CVE-2026-1 everywhere. CVE-2026-2 on mellanox of the newer branch
		// and on broadcom of the older one, which is the pair that answers
		// differently depending on what it is compared against. CVE-2026-3
		// on both variants of the newer branch and neither of the older,
		// which is the pair "every variant" answers differently.
		open := map[string][]string{
			"broadcom/master": {"CVE-2026-1", "CVE-2026-3"},
			"mellanox/master": {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"},
			"broadcom/202411": {"CVE-2026-1", "CVE-2026-2"},
			"mellanox/202411": {"CVE-2026-1"},
		}
		for name, target := range builds {
			reported := make([]finding.Reported, 0, len(open[name]))
			for _, issue := range open[name] {
				reported = append(reported, found(issue, libnl))
			}
			if _, err := f.store.Apply(ctx, target, f.runOn(t, target), reported); err != nil {
				t.Fatalf("scan %s: %v", name, err)
			}
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
		mellanox := f.variantID(t, "mellanox")
		broadcom := f.variantID(t, "broadcom")
		// One variant across every branch it is built on, which is the
		// selection a team asking "what is ours" makes.
		everywhere := func(variant int64) finding.Scope {
			return finding.Scope{ProductID: &f.productID, VariantID: &variant}
		}
		newer := finding.Scope{ProductID: &f.productID, StreamID: f.scope.StreamID}

		// On the newer branch alone, broadcom does not hold CVE-2026-2.
		same(t, "specific to mellanox on the newer branch",
			listed(t, f.scopeOf(t, builds["mellanox/master"]), finding.OnlyThisVariant),
			"CVE-2026-2")
		// And the same asked of mellanox across both branches: the older
		// branch's broadcom holds CVE-2026-2, and that is a fact about the
		// older branch rather than about mellanox on the newer one.
		same(t, "specific to mellanox on every branch it is built on",
			listed(t, everywhere(mellanox), finding.OnlyThisVariant), "CVE-2026-2")
		// It cuts the other way on the older branch, where mellanox is the
		// one without it.
		same(t, "specific to broadcom on the newer branch",
			listed(t, f.scopeOf(t, builds["broadcom/master"]), finding.OnlyThisVariant))
		same(t, "specific to broadcom on every branch it is built on",
			listed(t, everywhere(broadcom), finding.OnlyThisVariant), "CVE-2026-2")

		// What every variant of a branch holds, asked with no variant named
		// and from inside one.
		same(t, "common to every variant of the newer branch",
			listed(t, newer, finding.EveryVariant), "CVE-2026-1", "CVE-2026-3")
		same(t, "common to every variant, asked from mellanox",
			listed(t, f.scopeOf(t, builds["mellanox/master"]), finding.EveryVariant),
			"CVE-2026-1", "CVE-2026-3")
		// Over the whole product, a row survives where its own branch is
		// unanimous: CVE-2026-3 is on both variants of the newer branch and
		// on neither of the older, and the older branch does not answer for
		// it. No branch is unanimous about CVE-2026-2.
		same(t, "common to every variant of whichever branch it sits on",
			listed(t, f.wholeProduct(), finding.EveryVariant), "CVE-2026-1", "CVE-2026-3")

		// Specific to a variant nobody named is nothing, rather than
		// everything or a fault.
		same(t, "specific to no variant",
			listed(t, f.wholeProduct(), finding.OnlyThisVariant))
		same(t, "unnarrowed", listed(t, f.wholeProduct(), finding.AnyVariants),
			"CVE-2026-1", "CVE-2026-2", "CVE-2026-3")
	})
}
