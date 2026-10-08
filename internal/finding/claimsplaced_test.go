// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// A build's claim is placed by the product it names. One whose product is the
// build's root speaks for the whole build, whichever way it arrived; one whose
// product is a component of the build applies beneath that component and
// nowhere else.

// rootPurl is the fixture's root as an inventory names it.
const rootPurl = "pkg:deb/debian/sonic@1.0"

// insideOf is a claim about zlib inside the product given.
func insideOf(status sbom.Status, product graph.Described, statement string) sbom.Suppression {
	return sbom.Suppression{
		Vulnerability: inside, Status: status,
		Justification: "vulnerable_code_not_in_execute_path", Statement: statement,
		Targets: []sbom.Target{{Purl: zlib.Purl, Name: zlib.Name,
			Within: &sbom.Target{Purl: product.Purl, Name: product.Name}}},
		Origin: sbom.FromStatement,
	}
}

// argues records claims the build sent with its inventory on the last scan.
func (f *fixture) argues(t *testing.T, claims ...sbom.Suppression) {
	t.Helper()
	if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, claims, everyOrigin); err != nil {
		t.Fatal(err)
	}
}

// rooted says the last scan's inventory named its root as given.
func (f *fixture) rooted(t *testing.T, identifier string) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Table("scan").Set("root_identifier = ?", identifier).
		Where("id = ?", f.lastScan).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// vendorSays records a document uploaded on its own, its statements naming
// the product given as what zlib ships inside.
func (f *fixture) vendorSays(t *testing.T, product string, status sbom.Status, digest string) {
	t.Helper()
	claim := sbom.Suppression{
		Vulnerability: inside, Status: status,
		Justification: "vulnerable_code_not_in_execute_path",
		Statement:     "zlib's inflate is never reached",
	}
	target := sbom.Target{Purl: zlib.Purl, Name: zlib.Name,
		Within: &sbom.Target{Purl: product, Name: "sonic"}}
	f.publishes(t, []finding.Statement{finding.StatementOf(claim, target)}, digest)
}

func TestAClaimAboutAComponentInsideAProductReachesOnlyThePlacesBeneathIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.argues(t, insideOf(sbom.NotAffected, acmeY, "never called"))
		f.reported(t, found(inside, zlib))

		rows := placedAt(t, f, f.every(t))
		inY, underCurl := rows["zlib under acme-y"], rows["zlib under curl"]
		if inY.ClosedAt != nil || inY.SuppressedBy == nil || inY.ClaimedBy == nil {
			t.Errorf("the zlib inside Y is closed %v, suppressed by %v, claimed by %v; want "+
				"open and answered by the build", inY.ClosedAt, inY.SuppressedBy, inY.ClaimedBy)
		}
		if underCurl.SuppressedBy != nil || underCurl.ClaimedBy != nil {
			t.Errorf("the zlib under curl is answered by %v and %v; the claim is about the one "+
				"inside Y", underCurl.SuppressedBy, underCurl.ClaimedBy)
		}
	})
}

func TestAClaimAboutAComponentInsideAProductReachesItHoweverDeep(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, deep())
		f.argues(t, insideOf(sbom.NotAffected, acmeY, "never called"))
		f.reported(t, found(inside, zlib))
		if rows := f.every(t); len(rows) != 1 || rows[0].SuppressedBy == nil {
			t.Errorf("%d rows, want the zlib two steps under Y answered by the build", len(rows))
		}
	})
}

func TestAClaimAboutAComponentInsideAProductLeavesAPlaceReachedOutsideIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, shared())
		f.argues(t, insideOf(sbom.NotAffected, acmeY, "never called"))
		f.reported(t, found(inside, zlib))
		if rows := f.every(t); len(rows) != 1 || rows[0].SuppressedBy != nil {
			t.Error("the zlib Y and another product both reach is answered by a claim about Y")
		}
	})
}

func TestAClaimAboutAnotherReleaseOfTheProductReachesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeYNew))
		f.argues(t, insideOf(sbom.NotAffected, acmeY, "never called"))
		f.reported(t, found(inside, zlib))
		for _, row := range f.every(t) {
			if row.SuppressedBy != nil || row.ClaimedBy != nil {
				t.Error("a claim about zlib inside Y 4.2 answers a build shipping Y 4.3")
			}
		}
	})
}

func TestAClaimAboutTheBuildsRootReachesEveryPlace(t *testing.T) {
	sonic := graph.Described{Purl: rootPurl, Name: "sonic"}
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.argues(t, insideOf(sbom.NotAffected, sonic, "never called"))
		f.reported(t, found(inside, zlib))
		rows := f.every(t)
		if len(rows) != 2 {
			t.Fatalf("%d rows, want one per consumer", len(rows))
		}
		for _, row := range rows {
			if row.ClosedAt != nil || row.SuppressedBy == nil {
				t.Error("a claim about zlib inside the build does not answer every zlib in it")
			}
		}
	})
}

func TestAClaimThatTheFlawAppliesNamesTheFindingAndLeavesItWork(t *testing.T) {
	sonic := graph.Described{Purl: rootPurl, Name: "sonic"}
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.argues(t, insideOf(sbom.Affected, sonic, "turn compression off"))
		f.reported(t, found(inside, zlib))
		claims := f.openClaims(t)
		if len(claims) != 1 {
			t.Fatalf("%d claims, want the one", len(claims))
		}
		for _, row := range f.every(t) {
			if row.SuppressedBy != nil || row.ClaimedBy == nil || *row.ClaimedBy != claims[0].ID {
				t.Errorf("suppressed by %v and claimed by %v, want the workaround named and "+
					"nothing suppressed", row.SuppressedBy, row.ClaimedBy)
			}
		}
		// The claim is only information, so nothing moves on a re-scan.
		if again, _ := f.reported(t, found(inside, zlib)); !again.Unchanged() {
			t.Errorf("re-scanning wrote %+v", again)
		}
	})
}

func TestAStatementUploadedOnItsOwnAboutTheBuildsRootIsTheBuildsClaim(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.vendorSays(t, rootPurl, sbom.NotAffected, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))

		claims := f.openClaims(t)
		if len(claims) != 1 || claims[0].Origin != finding.Published || claims[0].StatedBy == nil {
			t.Fatalf("%d claims, want one taken from the published statement", len(claims))
		}
		for _, row := range f.every(t) {
			if row.ClosedAt != nil || row.SuppressedBy == nil || *row.SuppressedBy != claims[0].ID {
				t.Error("a finding the vendor's statement about the build covers is not open " +
					"and answered by the build")
			}
		}
		if again, _ := f.reported(t, found(inside, zlib)); !again.Unchanged() {
			t.Errorf("re-scanning wrote %+v", again)
		}
	})
}

func TestAFixUploadedOnItsOwnAboutTheBuildsRootClosesAsPatched(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.vendorSays(t, rootPurl, sbom.AlreadyFixed, "sha256:vendor-1")
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Patched != 2 || applied.Opened != 0 {
			t.Errorf("patched %d and opened %d, want both places recorded patched",
				applied.Patched, applied.Opened)
		}
	})
}

func TestAStatementAboutAnotherReleaseOfTheBuildsRootIsNoClaim(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.vendorSays(t, "pkg:deb/debian/sonic@2.0", sbom.NotAffected, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		if claims := f.openClaims(t); len(claims) != 0 {
			t.Errorf("%d claims taken from a statement about another release", len(claims))
		}
	})
}

func TestAStatementSetAsideTakesItsClaimFromTheBuild(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.vendorSays(t, rootPurl, sbom.NotAffected, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		// The next document from the vendor says nothing about this issue.
		f.publishes(t, nil, "sha256:vendor-2")
		f.reported(t, found(inside, zlib))
		if claims := f.openClaims(t); len(claims) != 0 {
			t.Errorf("%d claims still open after the statement was set aside", len(claims))
		}
		for _, row := range f.open(t) {
			if row.SuppressedBy != nil {
				t.Error("a finding is still answered by a statement set aside")
			}
		}
	})
}

func TestAScanDoesNotWithdrawAClaimTakenFromAPublishedStatement(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.vendorSays(t, rootPurl, sbom.NotAffected, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		// The build's own document, stating nothing.
		applied, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, nil, everyOrigin)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 0 || applied.Unstated != 0 {
			t.Errorf("recording the build's own claims closed %d and carried %d of the "+
				"published one", applied.Closed, applied.Unstated)
		}
	})
}

func TestTheListFindsWhatTheBuildSaysAndNothingElse(t *testing.T) {
	// The build says the flaw applies inside Y and gives a workaround; the
	// zlib under curl is answered by nothing.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.argues(t, insideOf(sbom.Affected, acmeY, "turn compression off"))
		f.reported(t, found(inside, zlib))
		who := f.holding(t, access.PublicTriage)
		places := func(filter finding.Filter) int {
			t.Helper()
			groups, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			total := 0
			for _, g := range groups {
				total += g.Places
			}
			return total
		}
		if got := places(finding.Filter{}); got != 2 {
			t.Fatalf("the list holds %d places, want the two zlib places", got)
		}
		if got := places(finding.Filter{BuildSays: []string{"affected"}}); got != 1 {
			t.Errorf("what the build says is affected is %d places, want the one inside Y", got)
		}
		if got := places(finding.Filter{BuildSays: []string{"not_affected"}}); got != 0 {
			t.Errorf("what the build says is not affected is %d places, want none", got)
		}
	})
}

func TestAFindingShowsTheBuildsClaimInItsOwnWords(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.vendorSays(t, rootPurl, sbom.NotAffected, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		who := f.holding(t, access.PublicTriage)
		open := f.open(t)
		evidence, err := f.store.Detail(t.Context(), who, f.target, open[0].VulnerabilityID,
			open[0].ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence.Claimed) != 1 {
			t.Fatalf("%d claims shown, want the vendor's one", len(evidence.Claimed))
		}
		got := evidence.Claimed[0]
		if got.Status != "not_affected" || got.Justification != "vulnerable_code_not_in_execute_path" ||
			got.Statement != "zlib's inflate is never reached" || got.Publisher != "acme security" ||
			got.Document != "acme-y.openvex.json" {
			t.Errorf("shown %+v, want the vendor's status, justification and words, and whose", got)
		}
	})
}
