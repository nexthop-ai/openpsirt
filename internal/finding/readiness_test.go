package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// cutFrom declares a release cut from this fixture's branch and returns its
// build. The link is what makes it a release *of* this branch rather than a
// separate line that happens to be beside it.
func (f *fixture) cutFrom(t *testing.T, name string) int64 {
	t.Helper()
	cat := catalog.NewStore(f.db.DB)
	branch, err := cat.StreamByName(t.Context(), f.productID, "master")
	if err != nil {
		t.Fatal(err)
	}
	declared, err := cat.DeclareStream(t.Context(), f.productID, name, catalog.Tag, &branch.ID)
	if err != nil {
		t.Fatalf("declare %s: %v", name, err)
	}
	variant, err := cat.VariantByName(t.Context(), f.productID, "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := cat.TargetFor(t.Context(), declared.ID, variant.ID)
	if err != nil {
		t.Fatal(err)
	}
	return target.ID
}

// critical is one reported issue rated critical, so the bands can be told
// apart in a count.
func critical(id string, component graph.Described) finding.Reported {
	reported := found(id, component)
	reported.Issue.Severity = "critical"
	return reported
}

func TestABranchIsComparedAgainstWhatWasLastShippedFromIt(t *testing.T) {
	// The pre-release question, and the reason a branch trend is worth
	// having at all: is what we are about to ship better or worse than
	// what we last shipped. Both halves come from scans already collected.
	each(t, func(t *testing.T, f *fixture) {
		release := f.cutFrom(t, "v2.4.1")
		f.shippedTo(t, release, twoConsumers())
		shippedRun := f.runOn(t, release)
		if _, err := f.store.Apply(t.Context(), release, shippedRun,
			[]finding.Reported{critical("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), shippedRun, "0.100.0", "2026-09-01", "", nil); err != nil {
			t.Fatal(err)
		}

		// The branch has picked up a second critical since.
		f.shipped(t, twoConsumers())
		here := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, here, []finding.Reported{
			critical("CVE-2026-1", libnl), critical("CVE-2026-2", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), here, "0.100.0", "2026-09-03", "", nil); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		branch, err := catalog.NewStore(f.db.DB).StreamByName(t.Context(), f.productID, "master")
		if err != nil {
			t.Fatal(err)
		}
		variant, err := catalog.NewStore(f.db.DB).VariantByName(t.Context(), f.productID, "broadcom")
		if err != nil {
			t.Fatal(err)
		}

		ready, err := f.store.ReadyFor(t.Context(), who, f.productID, branch.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ready.Shipped == nil {
			t.Fatalf("nothing to compare against, though a release was cut and scanned: %q",
				ready.Why)
		}
		if ready.Shipped.Stream != "v2.4.1" {
			t.Errorf("compared against %q, want the release cut from this branch",
				ready.Shipped.Stream)
		}
		// Two criticals now against one shipped, counted as issues at
		// components rather than as places — libnl sits under two consumers,
		// so counting rows would say four and two.
		if ready.Now.ByBand["critical"] != 2 {
			t.Errorf("the branch reads as %d criticals, want 2 (%v)",
				ready.Now.ByBand["critical"], ready.Now.ByBand)
		}
		if ready.Shipped.ByBand["critical"] != 1 {
			t.Errorf("the release reads as %d criticals, want 1 (%v)",
				ready.Shipped.ByBand["critical"], ready.Shipped.ByBand)
		}
		if ready.Now.LastScanned == nil || ready.Shipped.LastScanned == nil {
			t.Errorf("a count that does not say how old it is: now=%v shipped=%v",
				ready.Now.LastScanned, ready.Shipped.LastScanned)
		}
	})
}

func TestAReleaseNobodyScannedIsNotComparedAgainstAsZero(t *testing.T) {
	// "We shipped with none" and "we do not know what we shipped with" are
	// answers a person acts on differently. Reporting the second as the first
	// says a release was clean when nothing ever looked at it.
	each(t, func(t *testing.T, f *fixture) {
		// Declared and never built, which is the ordinary state of a tag
		// between being cut and its pipeline running.
		f.cutFrom(t, "v2.5.0")
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{critical("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		cat := catalog.NewStore(f.db.DB)
		branch, err := cat.StreamByName(t.Context(), f.productID, "master")
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.VariantByName(t.Context(), f.productID, "broadcom")
		if err != nil {
			t.Fatal(err)
		}

		ready, err := f.store.ReadyFor(t.Context(), f.holding(t, access.PublicRead),
			f.productID, branch.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ready.Shipped != nil {
			t.Errorf("a release nothing has scanned was compared against as %+v",
				ready.Shipped.ByBand)
		}
		if ready.Why == "" {
			t.Error("nothing to compare against, and nothing said about why")
		}
		if ready.Now.ByBand["critical"] != 1 {
			t.Errorf("the branch's own count is %v", ready.Now.ByBand)
		}
	})
}

func TestAReleaseBuiltAnotherWayIsNotTheComparison(t *testing.T) {
	// A branch built for one chip beside a release built for another compares
	// two different pieces of software, and the difference reads as a
	// regression somebody then goes looking for.
	each(t, func(t *testing.T, f *fixture) {
		cat := catalog.NewStore(f.db.DB)
		branch, err := cat.StreamByName(t.Context(), f.productID, "master")
		if err != nil {
			t.Fatal(err)
		}
		other, err := cat.DeclareVariant(t.Context(), f.productID, "mellanox", true)
		if err != nil {
			t.Fatal(err)
		}
		release, err := cat.DeclareStream(t.Context(), f.productID, "v2.4.2", catalog.Tag, &branch.ID)
		if err != nil {
			t.Fatal(err)
		}
		// The release exists, is scanned, and is built the other way.
		built, err := cat.TargetFor(t.Context(), release.ID, other.ID)
		if err != nil {
			t.Fatal(err)
		}
		f.shippedTo(t, built.ID, twoConsumers())
		run := f.runOn(t, built.ID)
		if _, err := f.store.Apply(t.Context(), built.ID, run,
			[]finding.Reported{critical("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), run, "0.100.0", "2026-09-01", "", nil); err != nil {
			t.Fatal(err)
		}

		broadcom, err := cat.VariantByName(t.Context(), f.productID, "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		ready, err := f.store.ReadyFor(t.Context(), f.holding(t, access.PublicRead),
			f.productID, branch.ID, broadcom.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ready.Shipped != nil {
			t.Errorf("a release built another way was used as the comparison: %+v",
				ready.Shipped)
		}
	})
}

func TestAReleaseIsNotComparedAgainstItself(t *testing.T) {
	// A tag is one frozen point and was not cut into anything, so "since we
	// shipped" has no meaning for it. Said rather than answered with an empty
	// comparison, which reads as a branch that has released nothing.
	each(t, func(t *testing.T, f *fixture) {
		release := f.cutFrom(t, "v2.4.3")
		f.shippedTo(t, release, twoConsumers())
		run := f.runOn(t, release)
		if _, err := f.store.Apply(t.Context(), release, run,
			[]finding.Reported{critical("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), run, "0.100.0", "2026-09-01", "", nil); err != nil {
			t.Fatal(err)
		}

		cat := catalog.NewStore(f.db.DB)
		tag, err := cat.StreamByName(t.Context(), f.productID, "v2.4.3")
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.VariantByName(t.Context(), f.productID, "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		ready, err := f.store.ReadyFor(t.Context(), f.holding(t, access.PublicRead),
			f.productID, tag.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ready.Now.Kind != string(catalog.Tag) {
			t.Errorf("the build reads as kind %q, want a tag", ready.Now.Kind)
		}
		if ready.Shipped != nil {
			t.Errorf("a release was compared against something: %+v", ready.Shipped)
		}
		if ready.Why == "" {
			t.Error("no comparison and nothing said about why")
		}
		// Its own count is still answered — the panel may be hidden, and the
		// number is not wrong.
		if ready.Now.ByBand["critical"] != 1 {
			t.Errorf("the release's own count is %v", ready.Now.ByBand)
		}
	})
}
