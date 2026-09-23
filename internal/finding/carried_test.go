// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

func TestWhatABuildCarriesReadsBackAsAHistory(t *testing.T) {
	// A distribution carries a fix into a package without moving its
	// version, and the only evidence is the build saying so in its own
	// inventory. That was stored and read by nothing, so "when did we
	// start carrying this, and are we still" had an answer only in the
	// database.
	//
	// A history rather than a list of what is true tonight: a claim that
	// stopped is the interesting row — somebody dropped a patch, and the
	// finding it answered is back — and it is the one a list of what
	// stands would not have at all.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{
				aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree),
				aClaim("CVE-2026-2", sbom.Affected, libnl, sbom.FromStatement),
			}, everyOrigin); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		rows, total, err := f.store.CarriedPatches(t.Context(), who, f.target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("%d of %d rows came back, want the two the build sent", len(rows), total)
		}
		// The two kinds are told apart, because they are different claims: a
		// carried patch declaring what it fixes, and a statement naming
		// something that has to be matched.
		var patch, statement int
		for _, row := range rows {
			if row.Pedigree {
				patch++
				if !row.Suppresses {
					t.Errorf("a carried fix answers nothing: %+v", row)
				}
				if row.Since.IsZero() {
					t.Errorf("a claim with no beginning is not a history: %+v", row)
				}
				if row.Until != nil {
					t.Errorf("a claim the build is still making has an end: %+v", row)
				}
			} else {
				statement++
				// A claim of affected is information rather than an answer,
				// and the row says which it is.
				if row.Suppresses {
					t.Errorf("a build saying it is affected suppressed something: %+v", row)
				}
			}
		}
		if patch != 1 || statement != 1 {
			t.Errorf("%d patches and %d statements, want one of each", patch, statement)
		}

		// Narrowed on what the claim says it is about, not on a component the
		// build still carries: a claim naming something that has gone is
		// exactly the row somebody asking why a patch stopped working wants.
		if got, _, err := f.store.CarriedPatches(t.Context(), who, f.target,
			libnl.Name, 50, 0); err != nil || len(got) != 2 {
			t.Errorf("narrowing to the package found %d rows (%v)", len(got), err)
		}
		if got, _, err := f.store.CarriedPatches(t.Context(), who, f.target,
			"nothing-called-this", 50, 0); err != nil || len(got) != 0 {
			t.Errorf("a package nothing was claimed about found %d rows (%v)", len(got), err)
		}

		// The build stops saying it, and the row stays — with an end on it.
		// That is the whole point: what a build no longer claims is what
		// somebody has to notice.
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{
				aClaim("CVE-2026-2", sbom.Affected, libnl, sbom.FromStatement),
			}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		after, _, err := f.store.CarriedPatches(t.Context(), who, f.target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var ended int
		for _, row := range after {
			if row.Pedigree && row.Until != nil {
				ended++
			}
		}
		if ended != 1 {
			t.Errorf("a patch the build stopped declaring reads as %+v", after)
		}
		// And what it is still saying sorts above what it has stopped saying:
		// one is the estate and the other is history.
		if len(after) > 0 && after[0].Until != nil {
			t.Errorf("a claim that ended sorts above one that stands: %+v", after)
		}
	})
}
