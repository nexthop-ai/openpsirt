package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Everything open against a product, a branch or a variant — the numbers the
// catalog screens draw.
//
// Counting is reading, so these carry a subject like every other read, and the
// count has to agree with the list somebody opens next: issues at components,
// not places. Both are asserted here because they are the two ways this has
// gone wrong before.
func TestCountingWhatIsOpenAgreesWithTheListAndCarriesVisibility(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// libnl sits under two consumers, so it is one issue at one component
		// in two places — which is exactly where counting rows and counting
		// what somebody decides about diverge.
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		byProduct, err := f.store.OpenBy(ctx, who, finding.Scope{}, finding.ByProduct)
		if err != nil {
			t.Fatal(err)
		}
		// The findings list is the number this has to match.
		_, listed, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if got := byProduct[f.productID]; got != listed {
			t.Errorf("the catalog counts %d and the list shows %d; one of them is "+
				"counting places", got, listed)
		}

		// Somebody who holds nothing here counts nothing here — a count is a
		// disclosure with the details removed, not a different kind of answer.
		stranger := access.NewPerson(99, "stranger", false,
			map[int64][]access.Role{f.productID + 999: {access.PublicRead}}, 0)
		theirs, err := f.store.OpenBy(ctx, stranger, finding.Scope{}, finding.ByProduct)
		if err != nil {
			t.Fatal(err)
		}
		if n := theirs[f.productID]; n != 0 {
			t.Errorf("somebody holding nothing here was told %d are open", n)
		}

		// And a key is not a person, so it is told nothing at all.
		key := access.NewPipeline(1, "nightly", access.Scope{ProductID: f.productID})
		asKey, err := f.store.OpenBy(ctx, key, finding.Scope{}, finding.ByProduct)
		if err != nil {
			t.Fatal(err)
		}
		if len(asKey) != 0 {
			t.Errorf("a pipeline key was given %d counts", len(asKey))
		}
	})
}

func TestCountingNarrowsToWhatWasAskedFor(t *testing.T) {
	// The three levels answer different questions and must not answer each
	// other's: a grouping that ignored its level would still look right on a
	// fixture with one product, one branch and one variant.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		for _, level := range []finding.Level{
			finding.ByProduct, finding.ByStream, finding.ByVariant,
		} {
			counts, err := f.store.OpenBy(ctx, who, finding.Scope{}, level)
			if err != nil {
				t.Fatalf("level %d: %v", level, err)
			}
			if len(counts) != 1 {
				t.Errorf("level %d grouped into %d buckets, want 1", level, len(counts))
			}
			for _, n := range counts {
				if n != 1 {
					t.Errorf("level %d counted %d, want the one issue at one component", level, n)
				}
			}
		}

		// A scope naming a product nothing was filed against answers nothing,
		// rather than everything.
		absent := f.productID + 999
		counts, err := f.store.OpenBy(ctx, who, finding.Scope{ProductID: &absent}, finding.ByProduct)
		if err != nil {
			t.Fatal(err)
		}
		if len(counts) != 0 {
			t.Errorf("a scope nothing matches counted %d buckets", len(counts))
		}
	})
}
