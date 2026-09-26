// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"

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
