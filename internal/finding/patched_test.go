// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// A patch the build declares has the effect a version bump has: the code no
// longer carries the flaw, so the finding closes. A claim that the flaw does
// not apply is an argument, and suppressed_test.go holds what that does.

// claimed records what the build argues, on a scan of its own.
func (f *fixture) claimed(t *testing.T, claims ...sbom.Suppression) {
	t.Helper()
	f.shipped(t, twoConsumers())
	if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, claims, everyOrigin); err != nil {
		t.Fatal(err)
	}
}

// scanned applies a run that reports the one issue at libnl.
func (f *fixture) scanned(t *testing.T) (finding.Applied, int64) {
	t.Helper()
	runID := f.run(t)
	applied, err := f.store.Apply(t.Context(), f.target, runID,
		[]finding.Reported{found("CVE-2026-1", libnl)})
	if err != nil {
		t.Fatal(err)
	}
	return applied, runID
}

var aPatch = aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)

func TestAnOpenFindingClosesOnTheScanThatFirstDeclaresItsPatch(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if applied, _ := f.scanned(t); applied.Opened != 2 {
			t.Fatalf("opened %d, want one per consumer", applied.Opened)
		}

		f.claimed(t, aPatch)
		applied, runID := f.scanned(t)
		if applied.Closed != 2 || applied.Patched != 2 {
			t.Errorf("closed %d and patched %d, want 2 of each", applied.Closed, applied.Patched)
		}
		if open := f.open(t); len(open) != 0 {
			t.Errorf("%d findings a declared patch fixes are still open", len(open))
		}
		rows := f.every(t)
		if len(rows) != 2 {
			t.Fatalf("%d rows, want the two that closed and no others", len(rows))
		}
		for _, row := range rows {
			if row.ClosedBecause != finding.Patched {
				t.Errorf("closed as %q, want %q", row.ClosedBecause, finding.Patched)
			}
			if row.ClosedRunID == nil || *row.ClosedRunID != runID {
				t.Error("the patched finding is not closed by the run that saw the patch")
			}
			if row.SuppressedBy == nil {
				t.Error("the patched finding does not name the claim that closed it")
			}
		}
	})
}

func TestAFindingFirstSeenAlreadyPatchedIsRecordedClosed(t *testing.T) {
	// Recorded rather than never opened: a release comparison against a build
	// that lacked the patch reads why the finding went from this row, and the
	// document saying this build is fixed is written from it.
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aPatch)
		applied, _ := f.scanned(t)
		if applied.Opened != 0 {
			t.Errorf("opened %d findings a declared patch already fixes", applied.Opened)
		}
		if applied.Patched != 2 {
			t.Errorf("patched %d, want 2", applied.Patched)
		}
		if applied.Unchanged() {
			t.Error("a run that recorded two patched findings reads as having changed nothing")
		}
		rows := f.every(t)
		if len(rows) != 2 {
			t.Fatalf("%d rows, want one per consumer", len(rows))
		}
		for _, row := range rows {
			if row.ClosedAt == nil || row.ClosedBecause != finding.Patched {
				t.Errorf("recorded as closed %v because %q, want closed as patched",
					row.ClosedAt, row.ClosedBecause)
			}
		}
	})
}

func TestRescanningAPatchedBuildWritesNothing(t *testing.T) {
	// A nightly re-scan still matches the component. It is the same answer,
	// and recording it again would stack a closed row per night.
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aPatch)
		f.scanned(t)
		applied, _ := f.scanned(t)
		if !applied.Unchanged() {
			t.Errorf("re-scanning a patched build wrote %+v", applied)
		}
		if rows := f.every(t); len(rows) != 2 {
			t.Errorf("%d rows after a second scan, want the same 2", len(rows))
		}
	})
}

func TestAFindingOpensAgainWhenTheBuildDropsThePatch(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aPatch)
		f.scanned(t)

		f.claimed(t)
		applied, _ := f.scanned(t)
		if applied.Opened != 2 {
			t.Errorf("opened %d once the patch was dropped, want 2", applied.Opened)
		}
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("%d open, want 2", len(open))
		}
		for _, row := range open {
			if row.SuppressedBy != nil {
				t.Error("a reopened finding still names the patch the build dropped")
			}
		}

		// And declared again, it closes again.
		f.claimed(t, aPatch)
		if applied, _ := f.scanned(t); applied.Closed != 2 || applied.Patched != 2 {
			t.Errorf("closed %d and patched %d when the patch came back, want 2 of each",
				applied.Closed, applied.Patched)
		}
	})
}

func TestAPatchedFindingStandsOnTheClaimTheBuildMakesNow(t *testing.T) {
	// A claim argued on different grounds is a new claim and the old one is
	// closed. The finding is still patched, and what it points at is the
	// claim still standing.
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aPatch)
		f.scanned(t)

		reargued := aPatch
		reargued.Justification = "inline_mitigations_already_exist"
		f.claimed(t, reargued)
		applied, _ := f.scanned(t)
		if applied.Patched != 0 || applied.Opened != 0 {
			t.Errorf("a patch argued again wrote %+v, want no new rows", applied)
		}

		standing := f.openClaims(t)
		if len(standing) != 1 {
			t.Fatalf("%d claims standing, want the one argued last", len(standing))
		}
		rows := f.every(t)
		if len(rows) != 2 {
			t.Fatalf("%d rows, want the same 2", len(rows))
		}
		for _, row := range rows {
			if row.SuppressedBy == nil || *row.SuppressedBy != standing[0].ID {
				t.Error("a patched finding points at a claim the build withdrew")
			}
		}
	})
}

func TestAClaimThatItDoesNotApplyLeavesTheFindingOpen(t *testing.T) {
	// An argument rather than a patch. It is marked and stays open, and only a
	// person here closes it, by agreeing to a dismissal.
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aClaim("CVE-2026-1", sbom.NotAffected, libnl, sbom.FromStatement))
		applied, _ := f.scanned(t)
		if applied.Patched != 0 || applied.Opened != 2 {
			t.Errorf("a not-affected claim wrote %+v, want two open and none patched", applied)
		}
	})
}

func TestABuildThatCarriesAPatchComparesAsFixedByIt(t *testing.T) {
	// The release comparison reads why a finding went from the later build's
	// closed rows. The later build here was patched on its first scan, so the
	// row it reads is the one recorded closed on first sight.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		earlier := f.anotherBuild(t, "v1")
		f.shippedTo(t, earlier, twoConsumers())
		if _, err := f.store.Apply(ctx, earlier, f.runOn(t, earlier),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		f.claimed(t, aPatch)
		f.scanned(t)

		who := f.holding(t, access.PublicRead)
		comparison, err := f.store.Compare(ctx, who, earlier, f.target, false)
		if err != nil {
			t.Fatal(err)
		}
		row, ok := entries(comparison.Fixed)["CVE-2026-1"]
		if !ok {
			t.Fatalf("the patched issue is not among the fixed: %+v", comparison)
		}
		if row.Because != finding.Patched {
			t.Errorf("it went because %q, want %q", row.Because, finding.Patched)
		}
		if notes := finding.Notes(about("master"), comparison); !strings.Contains(notes,
			"a patch the build declares") {
			t.Errorf("the note does not say the build's patch fixed it:\n%s", notes)
		}
	})
}

func TestAFindingRecordedClosedOnArrivalIsNeitherOpenedNorFixed(t *testing.T) {
	// A finding first seen already patched was never open. Counted, every
	// weekly tag carrying the same patch would add a fix done in no time and
	// a run that opened and closed the same things.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.claimed(t, aPatch)
		applied, runID := f.scanned(t)
		if applied.Patched != 2 {
			t.Fatalf("patched %d, want 2 recorded closed on arrival", applied.Patched)
		}
		who := f.holding(t, access.PublicRead)

		changes, err := f.store.Changes(ctx, who, f.target, []int64{runID})
		if err != nil {
			t.Fatal(err)
		}
		if got := changes[runID]; got.Opened != 0 || got.Closed != 0 {
			t.Errorf("the receipt says the run opened %d and closed %d", got.Opened, got.Closed)
		}
		ran, err := f.store.Ran(ctx, who, f.target, runID)
		if err != nil {
			t.Fatal(err)
		}
		if ran.Opened != 0 || ran.Closed != 0 {
			t.Errorf("the run's detail says it opened %d and closed %d", ran.Opened, ran.Closed)
		}
		rate, err := f.store.Remediation(ctx, who, f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if rate.Fixed != 0 || rate.Opened != 0 {
			t.Errorf("the remediation rate counts %d fixed and %d opened", rate.Fixed, rate.Opened)
		}
		rates, err := f.store.Compliance(ctx, who, f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rates {
			if r.Closed != 0 {
				t.Errorf("%d closed against a deadline, and none was ever due", r.Closed)
			}
		}
	})
}

func TestTwoReportsOfOneIssueAgreeOnWhetherItIsPatched(t *testing.T) {
	// One issue reported under two names reaches the same place twice. The
	// claim names only one of them, so the second report is not covered, and
	// what decides the finding is the report that stands.
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aClaim("GHSA-aaaa-bbbb-cccc", sbom.AlreadyFixed, libnl, sbom.FromPedigree))
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("GHSA-aaaa-bbbb-cccc", libnl, "CVE-2026-1"),
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		rows := f.every(t)
		if len(rows) == 0 {
			t.Fatal("nothing was recorded, so this checked nothing")
		}
		for _, row := range rows {
			if row.ClosedBecause == finding.Patched && row.SuppressedBy == nil {
				t.Error("a row closed as patched names no claim")
			}
		}
	})
}

func TestAFindingWhosePatchWasDroppedInABumpSaysWhereItCameFrom(t *testing.T) {
	// The detail screen's upgraded-from line explains a patch lost when the
	// version moved. The patched row is closed, and the version it held is
	// still what the new finding arrived from.
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aPatch)
		f.scanned(t)

		f.shipped(t, movedTo(libnlNew))
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, nil, everyOrigin); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnlNew)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("%d open at the new version, want 2", len(open))
		}
		for _, row := range open {
			if row.ArrivedFrom != libnl.Version {
				t.Errorf("arrived from %q, want %q", row.ArrivedFrom, libnl.Version)
			}
		}
	})
}

func TestABumpOntoAPatchedVersionClosesAsPatched(t *testing.T) {
	// The version moved and the issue did not come with it: the new version
	// carries the patch. Superseded would say it is open at the new version.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		f.scanned(t)

		f.shipped(t, movedTo(libnlNew))
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, []sbom.Suppression{
			aClaim("CVE-2026-1", sbom.AlreadyFixed, libnlNew, sbom.FromPedigree),
		}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnlNew)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 0 {
			t.Errorf("opened %d at a version the build patched", applied.Opened)
		}
		rows := f.every(t)
		if len(rows) != 4 {
			t.Fatalf("%d rows, want the two that closed and the two recorded patched", len(rows))
		}
		for _, row := range rows {
			if row.ClosedBecause != finding.Patched || row.SuppressedBy == nil {
				t.Errorf("closed as %q naming %v, want patched and the claim",
					row.ClosedBecause, row.SuppressedBy)
			}
		}
	})
}

func TestAPatchReturningAfterTheComponentLeftIsRecordedAgain(t *testing.T) {
	// What is already recorded is the latest row at a place, never any row.
	// Patched, then dropped, then removed, then back with the patch: the
	// latest row says removed, so the patch is recorded again.
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aPatch)
		f.scanned(t)
		f.claimed(t)
		f.scanned(t)
		f.shipped(t, withoutLibnl())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), nil); err != nil {
			t.Fatal(err)
		}

		f.claimed(t, aPatch)
		applied, _ := f.scanned(t)
		if applied.Patched != 2 {
			t.Errorf("patched %d when the component came back patched, want 2", applied.Patched)
		}
		rows := f.every(t)
		if len(rows) != 6 {
			t.Fatalf("%d rows, want two patched, two removed and two patched again", len(rows))
		}
		for _, row := range rows[4:] {
			if row.ClosedBecause != finding.Patched {
				t.Errorf("the latest rows closed as %q, want %q", row.ClosedBecause, finding.Patched)
			}
		}
	})
}
