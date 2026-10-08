// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"
	"time"

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
		applied, _ := f.reported(t, found(inside, zlib))
		for _, row := range f.every(t) {
			if row.SuppressedBy != nil || row.ClaimedBy != nil {
				t.Error("a claim about zlib inside Y 4.2 answers a build shipping Y 4.3")
			}
		}
		if applied.ClaimsReachingNothing != 1 {
			t.Errorf("%d claims reached nothing, want the one about another release",
				applied.ClaimsReachingNothing)
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

// sonicRoot is the fixture's root named the way a vendor's VEX names it.
var sonicRoot = graph.Described{Purl: rootPurl, Name: "sonic"}

func TestARevisionUploadedOnItsOwnReplacesTheClaimSentWithTheInventory(t *testing.T) {
	// The vendor said not affected with the release and revised it to affected
	// afterwards. The revision is the vendor's word now.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.argues(t, insideOf(sbom.NotAffected, sonicRoot, "never called"))
		time.Sleep(5 * time.Millisecond)
		f.vendorSays(t, rootPurl, sbom.Affected, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		for _, row := range f.every(t) {
			if row.SuppressedBy != nil || row.ClaimedBy == nil {
				t.Fatalf("suppressed by %v, claimed by %v: the revision saying affected "+
					"does not stand", row.SuppressedBy, row.ClaimedBy)
			}
		}
		var origin string
		if err := f.db.DB.NewSelect().Table("suppression").Column("origin").
			Where("id = ?", *f.every(t)[0].ClaimedBy).Scan(t.Context(), &origin); err != nil {
			t.Fatal(err)
		}
		if origin != finding.Published {
			t.Errorf("the finding names a claim of origin %q, want the revision", origin)
		}
	})
}

func TestALaterUploadWithTheInventoryReplacesARevisionUploadedOnItsOwn(t *testing.T) {
	// The earlier word suppresses and the later one does not, so only the
	// rule that the later word stands keeps the finding work.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.vendorSays(t, rootPurl, sbom.NotAffected, "sha256:vendor-1")
		time.Sleep(5 * time.Millisecond)
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.argues(t, insideOf(sbom.Affected, sonicRoot, "turn compression off"))
		f.reported(t, found(inside, zlib))
		for _, row := range f.every(t) {
			if row.SuppressedBy != nil || row.ClaimedBy == nil {
				t.Errorf("suppressed by %v, claimed by %v: the release's later word, affected, "+
					"does not stand over the earlier revision", row.SuppressedBy, row.ClaimedBy)
			}
		}
	})
}

func TestAStatementSaidAgainInALaterDocumentIsTheNewerWord(t *testing.T) {
	// The vendor says affected, the release's upload says not affected, and the
	// vendor's next document says affected again, word for word.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.vendorSays(t, rootPurl, sbom.Affected, "sha256:vendor-1")
		time.Sleep(5 * time.Millisecond)
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.argues(t, insideOf(sbom.NotAffected, sonicRoot, "never called"))
		time.Sleep(5 * time.Millisecond)
		f.vendorSays(t, rootPurl, sbom.Affected, "sha256:vendor-2")
		f.reported(t, found(inside, zlib))
		for _, row := range f.every(t) {
			if row.SuppressedBy != nil {
				t.Error("the vendor's word said again after the release's upload does not stand")
			}
		}
	})
}

func TestARootTwoBuildsHoldNamesNeither(t *testing.T) {
	// Two variants of one release whose inventories name the root alike.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		other := f.anotherBranch(t, "release")
		f.shippedTo(t, other, beside(acmeY))
		if _, err := f.db.DB.NewUpdate().Table("scan").Set("root_identifier = ?", rootPurl).
			Where("target_id = ?", other).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.vendorSays(t, rootPurl, sbom.NotAffected, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		if claims := f.openClaims(t); len(claims) != 0 {
			t.Errorf("%d claims taken from a statement about a root two builds hold", len(claims))
		}
	})
}

func TestAStatementAboutAGenericProductIsPlacedByItsIdentifier(t *testing.T) {
	// The exported document names the consumer by the identifier the
	// inventory gave it, which the name beside it does not repeat. Read back,
	// the statement applies beneath that product and nowhere else.
	utilities := graph.Described{Purl: "pkg:generic/sonic-utilities@1.0",
		Name: "SONiC utilities", Version: "1.0"}
	const document = `{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "https://example.com/vex/sonic",
	  "author": "Vendor",
	  "timestamp": "2026-10-08T00:00:00Z",
	  "version": 1,
	  "statements": [{
	    "vulnerability": {"name": "` + inside + `"},
	    "products": [{"@id": "pkg:generic/sonic-utilities@1.0",
	      "subcomponents": [{"@id": "pkg:generic/zlib@1.2.11"}]}],
	    "status": "not_affected",
	    "justification": "vulnerable_code_not_in_execute_path"
	  }]
	}`
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(utilities))
		claims, err := sbom.ReadSuppressions(strings.NewReader(document), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		f.argues(t, claims...)
		f.reported(t, found(inside, zlib))
		rows := placedAt(t, f, f.every(t))
		if rows["zlib under SONiC utilities"].SuppressedBy == nil {
			t.Error("the zlib inside the product the statement names is not answered")
		}
		if rows["zlib under curl"].SuppressedBy != nil {
			t.Error("the statement about the zlib inside one product answers the zlib under curl")
		}
	})
}

func TestAClaimAboutAGenericRootReachesEveryPlace(t *testing.T) {
	// A root is stored by its name alone, which a generic identifier is
	// matched against. It is the build, and never a product inside it.
	generic := graph.Described{Purl: "pkg:generic/sonic@1.0", Name: "sonic", Version: "1.0"}
	each(t, func(t *testing.T, f *fixture) {
		snap := beside(acmeY)
		snap.Root = generic
		for i := range snap.Dependencies {
			if snap.Dependencies[i].Parent == root {
				snap.Dependencies[i].Parent = generic
			}
		}
		f.shipped(t, snap)
		f.argues(t, insideOf(sbom.NotAffected, generic, "never called"))
		f.reported(t, found(inside, zlib))
		rows := f.every(t)
		if len(rows) != 2 {
			t.Fatalf("%d rows, want one per consumer", len(rows))
		}
		for _, row := range rows {
			if row.SuppressedBy == nil {
				t.Error("a claim about zlib inside a generic root does not answer every zlib")
			}
		}
	})
}

func TestAFindingShowsNoClaimTheBuildHasWithdrawn(t *testing.T) {
	// The zlib inside Y is closed by Acme's statement and named the build's
	// claim when it closed. The build then stops making the claim.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.acmeSays(t)
		f.argues(t, insideOf(sbom.Affected, sonicRoot, "turn compression off"))
		f.reported(t, found(inside, zlib))
		f.argues(t)
		f.reported(t, found(inside, zlib))
		who := f.holding(t, access.PublicTriage)
		rows := placedAt(t, f, f.every(t))
		inY := rows["zlib under acme-y"]
		if inY.ClosedBecause != finding.Disclaimed || inY.ClaimedBy == nil {
			t.Fatalf("the zlib inside Y is closed as %q naming %v, want disclaimed naming the "+
				"withdrawn claim", inY.ClosedBecause, inY.ClaimedBy)
		}
		evidence, err := f.store.Detail(t.Context(), who, f.target, inY.VulnerabilityID, inY.ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence.Claimed) != 0 {
			t.Errorf("shown %+v, a claim the build has withdrawn", evidence.Claimed)
		}
	})
}

func TestCarriedPatchesNameTheProductAndLeaveOutWhatWasUploadedOnItsOwn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		f.argues(t, insideOf(sbom.NotAffected, acmeY, "never called"))
		f.vendorSays(t, rootPurl, sbom.NotAffected, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		who := f.holding(t, access.PublicTriage)
		rows, total, err := f.store.CarriedPatches(t.Context(), who, f.target, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(rows) != 1 {
			t.Fatalf("%d rows of %d, want the claim sent with the inventory alone", len(rows), total)
		}
		if rows[0].Within != "acme-y" || rows[0].WithinVersion != "4.2" {
			t.Errorf("the claim names it inside %q %q, want acme-y 4.2", rows[0].Within,
				rows[0].WithinVersion)
		}
	})
}

func TestAClaimTakenFromAStatementIsSpelledAsItsPublisherSpelledIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.rooted(t, rootPurl)
		claim := sbom.Suppression{Vulnerability: inside, Status: sbom.NotAffected}
		target := sbom.Target{Purl: "pkg:pypi/PyYAML@6.0", Name: "PyYAML",
			Within: &sbom.Target{Purl: rootPurl, Name: "sonic"}}
		f.publishes(t, []finding.Statement{finding.StatementOf(claim, target)}, "sha256:vendor-1")
		f.reported(t, found(inside, zlib))
		claims := f.openClaims(t)
		if len(claims) != 1 || claims[0].SubjectName != "PyYAML" {
			t.Errorf("claims %+v, want one naming PyYAML as its publisher spelled it", claims)
		}
	})
}
