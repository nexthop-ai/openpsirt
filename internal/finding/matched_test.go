// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestHowAMatchWasMadeIsKeptAndCanBeAskedFor(t *testing.T) {
	// A distribution backports fixes without moving the upstream version:
	// busybox 1.37.0-r14 and 1.37.0-r15 are the same upstream release and one
	// of them may carry the patch. So an advisory for the package in its own
	// ecosystem is the authority, and a comparison against a published
	// identifier and an upstream range cannot see the difference.
	//
	// That is the question somebody asks about a distribution's packages, and
	// the scanner answers it in every result.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		byAdvisory := found("CVE-2026-CONFIRMED", teamd)
		byAdvisory.Matched = finding.ByAdvisory
		byAdvisory.MatchedFrom = "https://secdb.alpinelinux.org/"

		byIdentifier := found("CVE-2026-UNCONFIRMED", swss)
		byIdentifier.Matched = finding.ByIdentifier
		byIdentifier.MatchedFrom = "https://nvd.nist.gov/vuln/detail/CVE-2026-UNCONFIRMED"

		// And one the scanner said nothing about. Unknown is not unconfirmed:
		// a list of "somebody has to look at this" that quietly includes
		// everything nobody has classified is a list nobody can work down.
		saidNothing := found("CVE-2026-UNKNOWN", libnl)

		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{byAdvisory, byIdentifier, saidNothing}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		groups, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if total != 3 {
			t.Fatalf("%d groups, want the three reported", total)
		}
		how := map[string]finding.Matched{}
		for _, g := range groups {
			how[g.Vulnerability] = g.Matched
		}
		if how["CVE-2026-CONFIRMED"] != finding.ByAdvisory {
			t.Errorf("a match against an advisory reads as %q", how["CVE-2026-CONFIRMED"])
		}
		if how["CVE-2026-UNCONFIRMED"] != finding.ByIdentifier {
			t.Errorf("a match against an upstream range reads as %q", how["CVE-2026-UNCONFIRMED"])
		}
		if how["CVE-2026-UNKNOWN"] != "" {
			t.Errorf("a match nothing was said about reads as %q", how["CVE-2026-UNKNOWN"])
		}

		// And asked for at scale, which is the point: finding these one at a
		// time is not a thing anybody does.
		only, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Unconfirmed: true})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(only) != 1 {
			t.Fatalf("%d groups are unconfirmed, want the one — not the confirmed one, and "+
				"not the one nobody classified", total)
		}
		if only[0].Vulnerability != "CVE-2026-UNCONFIRMED" {
			t.Errorf("the unconfirmed list holds %q", only[0].Vulnerability)
		}

		// The place carries where its own match came from, which the issue
		// cannot: one issue reached through two ecosystems has two answers.
		at, err := f.store.Detail(t.Context(), who, f.target,
			f.issue(t, "CVE-2026-UNCONFIRMED"), f.componentID(t, swss.Name))
		if err != nil {
			t.Fatal(err)
		}
		if at.Matched != finding.ByIdentifier {
			t.Errorf("the finding reads as matched %q", at.Matched)
		}
		if at.MatchedFrom != byIdentifier.MatchedFrom {
			t.Errorf("the finding says it was matched from %q, want %q",
				at.MatchedFrom, byIdentifier.MatchedFrom)
		}
	})
}
