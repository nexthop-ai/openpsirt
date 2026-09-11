package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
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
		// Most-closing first, which is what somebody choosing between them is
		// actually asking.
		if here.Upgrades[0].To != "3.9.0" || here.Upgrades[0].Issues != 2 {
			t.Errorf("first upgrade is %+v, want 3.9.0 closing two", here.Upgrades[0])
		}
		if here.Upgrades[1].To != "3.8.0" || here.Upgrades[1].Issues != 1 {
			t.Errorf("second upgrade is %+v, want 3.8.0 closing one", here.Upgrades[1])
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
