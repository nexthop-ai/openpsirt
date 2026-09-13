package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestAComponentCarriesWhereItCouldGoAndWhatThatWouldClose(t *testing.T) {
	// The version bump belongs on the package it is a bump of. It sat on a
	// list of its own, which put the thing somebody acts on — move this to
	// that version — on a different screen from the package it belongs to.
	//
	// Ordered by what each closes rather than by version: comparing two
	// versions needs a per-ecosystem ordering this does not have, so
	// "which of these is nearest" is a question this cannot answer and
	// does not pretend to.
	each(t, func(t *testing.T, f *fixture) {
		moves := func(id, to string) finding.Reported {
			return finding.Reported{
				Issue:     finding.Named{Identifier: id, Severity: "high"},
				Component: libnl,
				FixState:  finding.FixedUpstream, FixedIn: to,
			}
		}
		f.shipped(t, twoConsumers())
		run := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, run, []finding.Reported{
			moves("CVE-2026-1", "3.9.0"),
			moves("CVE-2026-2", "3.9.0"),
			moves("CVE-2026-3", "3.8.0"),
			// Nothing to move to: it needs a judgment rather than a bump, and
			// contributes no upgrade at all.
			{Issue: finding.Named{Identifier: "CVE-2026-4", Severity: "high"}, Component: libnl},
		}); err != nil {
			t.Fatal(err)
		}

		groups, _, err := f.store.ComponentGroups(t.Context(), f.holding(t, access.PublicTriage),
			f.wholeProduct(), 50, 0, finding.Filter{Planned: finding.NotPlanned})
		if err != nil {
			t.Fatal(err)
		}
		var here *finding.ComponentGroup
		for i := range groups {
			if groups[i].Component == libnl.Name {
				here = &groups[i]
			}
		}
		if here == nil {
			t.Fatal("the component is not in the by-component view at all")
		}
		if len(here.Upgrades) != 2 {
			t.Fatalf("%d upgrades, want the two versions that fix something", len(here.Upgrades))
		}
		// Furthest along first, which is what somebody choosing between them is
		// actually asking — and both counts, because they differ: 3.9.0 is
		// named by two and reaching it also closes the one 3.8.0 fixed.
		if here.Upgrades[0].To != "3.9.0" || here.Upgrades[0].FixedHere != 2 {
			t.Errorf("first upgrade is %+v, want 3.9.0 fixing two of its own", here.Upgrades[0])
		}
		if here.Upgrades[0].Reached != 3 || !here.Upgrades[0].Ordered {
			t.Errorf("moving to 3.9.0 reaches %d of 3 (ordered %t), want all three",
				here.Upgrades[0].Reached, here.Upgrades[0].Ordered)
		}
		if here.Upgrades[1].To != "3.8.0" || here.Upgrades[1].FixedHere != 1 {
			t.Errorf("second upgrade is %+v, want 3.8.0 fixing one of its own", here.Upgrades[1])
		}
		if here.Upgrades[1].Reached != 1 {
			t.Errorf("moving to 3.8.0 reaches %d, want only what it fixed itself",
				here.Upgrades[1].Reached)
		}
	})
}

func TestAComponentIsAnsweredPerBuildBecauseTheAnswerDiffers(t *testing.T) {
	// The whole difficulty of upgrading a shared component: one stream stays
	// on a maintained older line and another moves on, so the version shipped
	// and the version to move to are both per build. A single answer for the
	// product would be wrong for one of them.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, run, []finding.Reported{
			{
				Issue: finding.Named{Identifier: "CVE-2026-1", Severity: "high"}, Component: libnl,
				FixState: finding.FixedUpstream, FixedIn: "3.9.0",
			},
		}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage)
		builds, err := f.store.AcrossBuilds(t.Context(), who, f.wholeProduct(), libnl.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 {
			t.Fatalf("%d builds carry it, want the one it was scanned into", len(builds))
		}
		if builds[0].Version != libnl.Version {
			t.Errorf("the build ships %q, want %q", builds[0].Version, libnl.Version)
		}
		if builds[0].Issues != 1 {
			t.Errorf("%d issues open there, want one", builds[0].Issues)
		}
		if len(builds[0].Upgrades) != 1 || builds[0].Upgrades[0].To != "3.9.0" {
			t.Errorf("where it could go is %+v", builds[0].Upgrades)
		}
		// Nothing has been promised yet, so nothing is reported as promised.
		if builds[0].UpgradeTo != "" || builds[0].CommittedTo != nil {
			t.Errorf("a promise appeared before one was made: %+v", builds[0])
		}

		// A component this product does not carry answers nothing rather than
		// answering emptily about every build.
		none, err := f.store.AcrossBuilds(t.Context(), who, f.wholeProduct(), "not-a-component")
		if err != nil {
			t.Fatal(err)
		}
		if len(none) != 0 {
			t.Errorf("a component nothing carries returned %d builds", len(none))
		}
	})
}

func TestWhatAPromisedUpgradeCoversIsDerivedRatherThanMarked(t *testing.T) {
	// The mark on a covered finding is a join, not a tag written across every
	// row an upgrade touches. A tag is per product and could not say "planned
	// on master, not on 2.4", which is the case the per-build target exists
	// for — and it would go stale the moment the promise was withdrawn.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, through(libnl))
		run := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, run, []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		// Nothing promised: everything is unplanned and nothing is planned.
		open, _, err := f.store.Groups(t.Context(), who, f.wholeProduct(), 50, 0,
			finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(open) != 1 {
			t.Fatalf("%d unplanned before anything was promised, want the one", len(open))
		}
		planned, _, err := f.store.Groups(t.Context(), who, f.wholeProduct(), 50, 0,
			finding.Filter{Planned: finding.PlannedOnly})
		if err != nil {
			t.Fatal(err)
		}
		if len(planned) != 0 {
			t.Fatalf("%d planned before anything was promised", len(planned))
		}
	})
}

func TestAComponentAnswersWhetherOrNotAnythingIsOpenAgainstIt(t *testing.T) {
	// A component is in the inventory because the build ships it. Answered off
	// the findings instead, anything carrying its risk underneath rather than
	// on itself returned no builds at all — which reads as a name the product
	// does not ship, and is the ordinary state of every pre-built binary
	// vendored in whole.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		// Against libnl alone, so its two consumers carry nothing of their own.
		if _, err := f.store.Apply(t.Context(), f.target, run, []finding.Reported{
			{
				Issue: finding.Named{Identifier: "CVE-2026-1", Severity: "high"}, Component: libnl,
				FixState: finding.FixedUpstream, FixedIn: "3.9.0",
			},
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		builds, err := f.store.AcrossBuilds(t.Context(), who, f.wholeProduct(), swss.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 {
			t.Fatalf("%d builds carry a component with nothing open, want the one shipping it",
				len(builds))
		}
		clean := builds[0]
		if clean.Version != swss.Version {
			t.Errorf("it ships %q, want %q", clean.Version, swss.Version)
		}
		if clean.Issues != 0 || clean.Places != 0 {
			t.Errorf("%d issues at %d places against something nothing was reported on",
				clean.Issues, clean.Places)
		}
		// A deadline is the earliest among what is open, so it is absent
		// rather than zero where nothing is.
		if clean.DueAt != nil {
			t.Errorf("a deadline appeared with nothing open: %v", clean.DueAt)
		}
		// The identifier travels, because the ecosystem and an upstream
		// address are both read out of it and neither is stored.
		if clean.Purl != swss.Purl {
			t.Errorf("the identifier is %q, want %q", clean.Purl, swss.Purl)
		}
		// Nothing pulls swss in, so the build itself is what carries it.
		if clean.Consumers != 1 {
			t.Errorf("%d things pull in a component the build contains directly, want one",
				clean.Consumers)
		}
	})
}

func TestTheVersionWorthTakingLeadsRatherThanTheOneThatFixedMost(t *testing.T) {
	// Measured on the demo's kernel: of 168 open, the 6.12.100-1 release fixed
	// 49 and the newest named, 6.12.107-1, fixed 2 — so ranked on what each
	// release fixed, the version that closes everything sorts near the bottom
	// and the picker recommends against itself.
	//
	// What each release fixed and what reaching it closes are two counts. The
	// second needs the ecosystem's ordering, which is why it is answered here
	// rather than left for somebody to work out from a list.
	each(t, func(t *testing.T, f *fixture) {
		fixedIn := func(id, to string) finding.Reported {
			return finding.Reported{
				Issue:     finding.Named{Identifier: id, Severity: "high"},
				Component: libnl,
				FixState:  finding.FixedUpstream, FixedIn: to,
			}
		}
		f.shipped(t, twoConsumers())
		run := f.run(t)
		// Three fixed in an earlier release, one in the newest: the shape that
		// reads backwards when the count is what sorts.
		if _, err := f.store.Apply(t.Context(), f.target, run, []finding.Reported{
			fixedIn("CVE-2026-1", "3.8.0"),
			fixedIn("CVE-2026-2", "3.8.0"),
			fixedIn("CVE-2026-3", "3.8.0"),
			fixedIn("CVE-2026-4", "3.9.0"),
		}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage)
		builds, err := f.store.AcrossBuilds(t.Context(), who, f.wholeProduct(), libnl.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 {
			t.Fatalf("%d builds carry it", len(builds))
		}
		up := builds[0].Upgrades
		if len(up) != 2 {
			t.Fatalf("%d versions to move to, want the two named: %+v", len(up), up)
		}
		// Furthest along first, though it fixed the fewest of its own.
		if up[0].To != "3.9.0" {
			t.Errorf("the list leads with %q, want the newest version named", up[0].To)
		}
		if up[0].FixedHere != 1 {
			t.Errorf("3.9.0 fixed %d of its own, want one", up[0].FixedHere)
		}
		if up[0].Reached != 4 {
			t.Errorf("moving to 3.9.0 reaches %d, want all four", up[0].Reached)
		}
		// And the earlier one reaches only what it fixed.
		if up[1].To != "3.8.0" || up[1].Reached != 3 {
			t.Errorf("second is %+v, want 3.8.0 reaching three", up[1])
		}
	})
}

func TestVersionsNobodyCanOrderAreNotRanked(t *testing.T) {
	// A runtime naming itself after its own toolchain is the case in the demo:
	// "go1.26.3" is not a version this orders, so reaching one says nothing
	// about the others. Counted by exact match and reported as unranked, rather
	// than ranked by a comparison that was refused.
	each(t, func(t *testing.T, f *fixture) {
		runtime := graph.Described{
			Purl: "pkg:golang/stdlib@go1.26.3", Name: "stdlib", Version: "go1.26.3",
		}
		f.shipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{root, runtime},
			Dependencies: []graph.Dependency{{Parent: root, Child: runtime}},
		})
		run := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, run, []finding.Reported{
			{
				Issue: finding.Named{Identifier: "CVE-2026-10", Severity: "high"}, Component: runtime,
				FixState: finding.FixedUpstream, FixedIn: "go1.26.5",
			},
			{
				Issue: finding.Named{Identifier: "CVE-2026-11", Severity: "high"}, Component: runtime,
				FixState: finding.FixedUpstream, FixedIn: "go1.26.6",
			},
		}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage)
		builds, err := f.store.AcrossBuilds(t.Context(), who, f.wholeProduct(), runtime.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 {
			t.Fatalf("%d builds carry it", len(builds))
		}
		for _, up := range builds[0].Upgrades {
			if up.Ordered {
				t.Errorf("%q was reported as ordered", up.To)
			}
			// Reaching one says nothing about the other, so both counts are
			// what named it exactly.
			if up.Reached != up.FixedHere || up.FixedHere != 1 {
				t.Errorf("%q fixed %d and reaches %d, want one and one",
					up.To, up.FixedHere, up.Reached)
			}
		}
	})
}
