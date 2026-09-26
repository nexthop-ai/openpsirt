// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// The build's own argument about its findings.
//
// A claim in a scan file is the producer's judgment, applied here rather than
// upstream: what it covers is marked and kept rather than dropped, and a claim
// that reached nothing is reported rather than thrown away.

func TestAFindingTheBuildArguesDoesNotApplyIsMarkedNotDropped(t *testing.T) {
	// The whole reason the claims are applied here rather than upstream. A
	// finding a build has argued about stays visible and says what was
	// argued; one that simply never arrived is indistinguishable from a
	// scanner that failed, and lands in the bucket nothing may explain away.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		scanID := f.lastScan
		if _, err := f.store.RecordClaims(t.Context(), f.target, scanID,
			[]sbom.Suppression{aClaim("CVE-2026-1", sbom.NotAffected, libnl, sbom.FromStatement)}, everyOrigin); err != nil {
			t.Fatal(err)
		}

		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 2 {
			t.Fatalf("opened %d findings, want one per consumer even though the build answered them", applied.Opened)
		}
		if applied.Suppressed != 2 {
			t.Errorf("%d findings carry what the build argued, want 2", applied.Suppressed)
		}
		for _, row := range f.open(t) {
			if row.SuppressedBy == nil {
				t.Error("a finding the build answered does not say so")
			}
		}
	})
}

func TestAClaimAboutSomethingElseLeavesAFindingAlone(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{
				// Right component, different issue.
				aClaim("CVE-2026-9", sbom.NotAffected, libnl, sbom.FromStatement),
				// Right issue, different component.
				aClaim("CVE-2026-1", sbom.NotAffected, swss, sbom.FromStatement),
			}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Suppressed != 0 {
			t.Errorf("%d findings were marked by a claim about something else", applied.Suppressed)
		}
	})
}

func TestSayingItIsAffectedSuppressesNothing(t *testing.T) {
	// A build saying it is affected, or that it has not decided, is telling us
	// it looked. That is information, not an answer.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{aClaim("CVE-2026-1", sbom.Affected, libnl, sbom.FromStatement)}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Suppressed != 0 {
			t.Errorf("a build saying it is affected suppressed %d findings", applied.Suppressed)
		}
	})
}

func TestArguingTheSameThingAgainWritesNothing(t *testing.T) {
	// A build argues the same things night after night.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		claims := []sbom.Suppression{aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)}

		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, claims, everyOrigin); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, twoConsumers())
		applied, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, claims, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("re-arguing the same claims wrote %+v", applied)
		}

		// Withdrawing one closes it rather than deleting it: what a release
		// argued is a question asked years later.
		applied, err = f.store.RecordClaims(t.Context(), f.target, f.lastScan, nil, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 1 {
			t.Errorf("withdrawing a claim closed %d", applied.Closed)
		}
		if open := f.openClaims(t); len(open) != 0 {
			t.Errorf("%d claims still open", len(open))
		}
	})
}

func TestAClaimAttachedToItsComponentWinsOverOneThatNamedIt(t *testing.T) {
	// A claim that arrived on the component knows exactly what it is about. A
	// claim in a document may name a whole source tree and match by name, so
	// where both cover a finding the precise one is the one recorded.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		// Recorded in two steps so the vaguer claim is the older one. If
		// preferring the precise one were removed, the older would win, and a
		// test that relied on insertion order within a single call would pass
		// or fail depending on what a map felt like doing.
		vague := aClaim("CVE-2026-1", sbom.NotAffected, libnl, sbom.FromStatement)
		precise := aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{vague}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{vague, precise}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		open := f.openClaims(t)
		attached := map[int64]bool{}
		for _, claim := range open {
			if claim.Origin == string(sbom.FromPedigree) {
				attached[claim.ID] = true
			}
		}
		rows := f.every(t)
		if len(rows) == 0 {
			t.Fatal("nothing was recorded, so this checked nothing")
		}
		for _, row := range rows {
			if row.SuppressedBy == nil || !attached[*row.SuppressedBy] {
				t.Error("a finding recorded the vaguer of two claims that covered it")
			}
		}
	})
}

func TestEveryStatusTheFormatDefinesCanBeStored(t *testing.T) {
	// The vocabulary belongs to the exchange format rather than to us, and its
	// longest word is longer than a short identifier column allows. A claim
	// that cannot be stored fails the whole scan that carried it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		var claims []sbom.Suppression
		for _, status := range []sbom.Status{
			sbom.NotAffected, sbom.Affected, sbom.AlreadyFixed, sbom.UnderInvestigation,
		} {
			claim := aClaim("CVE-2026-1", status, libnl, sbom.FromStatement)
			claim.Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
			claims = append(claims, claim)
		}
		applied, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, claims, everyOrigin)
		if err != nil {
			t.Fatalf("recording every status the format defines: %v", err)
		}
		if applied.Opened != 4 {
			t.Errorf("stored %d claims, want one per status", applied.Opened)
		}
	})
}

func TestAClaimThatReachedNothingIsCounted(t *testing.T) {
	// The ordinary case, not the exceptional one: a producer's
	// automatically-extracted claims name source trees rather than packages,
	// so they land on nothing. A finding the build believes it answered then
	// comes back as noise, and nothing distinguishes that from a finding
	// nobody has looked at.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		reaches := aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)
		misses := aClaim("CVE-2026-2", sbom.NotAffected,
			graph.Described{Purl: "pkg:generic/libnl3", Name: "libnl3"}, sbom.FromStatement)

		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{reaches, misses}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.ClaimsReaching != 1 {
			t.Errorf("%d claims reached something, want 1", applied.ClaimsReaching)
		}
		if applied.ClaimsReachingNothing != 1 {
			t.Errorf("%d claims reached nothing, want 1", applied.ClaimsReachingNothing)
		}
	})
}

// everyOrigin is what a scan in a format that can state every kind of claim
// passes. Where a format cannot state one, a claim of that origin is carried
// forward rather than read as withdrawn.
var everyOrigin = map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: true}

func TestAFormatThatCannotStateAClaimDoesNotWithdrawOne(t *testing.T) {
	// Closing works by difference: a claim the build no longer argues is a
	// claim the build withdrew. That reading only holds where the build had
	// somewhere to argue it.
	//
	// An inventory in a format that cannot attach a claim to a component says
	// nothing about carried patches whether or not they are still carried, so
	// a product's first scan in that format would otherwise close every claim
	// it had at once — and every finding they suppressed comes back, with
	// nothing saying why.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		carried := []sbom.Suppression{
			aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree),
		}
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, carried, everyOrigin); err != nil {
			t.Fatal(err)
		}

		// The next scan arrives in a format with nowhere to say it.
		stated := map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: false}
		applied, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, nil, stated)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 0 {
			t.Errorf("%d claims closed, want 0 — the build did not withdraw them", applied.Closed)
		}
		if applied.Unstated != 1 {
			t.Errorf("%d claims carried forward unstated, want 1", applied.Unstated)
		}

		// And a claim the scan *could* have stated is still closed by not
		// stating it, or the difference stops meaning anything at all.
		spoken := []sbom.Suppression{
			aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree),
			aClaim("CVE-2026-2", sbom.NotAffected, libnl, sbom.FromStatement),
		}
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, spoken, everyOrigin); err != nil {
			t.Fatal(err)
		}
		applied, err = f.store.RecordClaims(t.Context(), f.target, f.lastScan, nil, stated)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 1 {
			t.Errorf("%d claims closed, want 1 — that one the scan could have restated", applied.Closed)
		}
		if applied.Unstated != 1 {
			t.Errorf("%d claims carried forward unstated, want 1", applied.Unstated)
		}
	})
}
