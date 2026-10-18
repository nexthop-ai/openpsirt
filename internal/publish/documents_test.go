// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// sonicRoot is the build's own root, as its inventory names it.
var sonicRoot = graph.Described{Purl: "pkg:generic/sonic@master.42", Name: "sonic", Version: "master.42"}

// shipped is the default build: openssl straight under the root, libnl under
// swss.
func (w *world) shipped() {
	w.t.Helper()
	w.ship(w.Target, sonicRoot,
		edge{sonicRoot, openssl}, edge{sonicRoot, swss}, edge{swss, libnl})
}

// buildID is how a CSAF document names a build of the default product.
func buildID(stream, variant string) string {
	return fixture.ProductName + ":" + stream + ":" + variant
}

// A statement whose reason holds for anybody shipping the component names the
// component alone; one whose reason is this build's own names the component as
// part of the build. CSAF says it through the component's own product entry
// against a relationship, and OpenVEX through a product alone against one with
// subcomponents.
func TestAStatementHoldingForAnybodyNamesTheComponentAlone(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Target, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		w.decide(w.Target, "CVE-2026-1001", openssl,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.decide(w.Target, "CVE-2026-1002", libnl,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotInExecutePath})
		w.publishes(w.Product, true)
		w.write()

		portable := w.csafAbout(w.Product, "CVE-2026-1001")
		if portable == nil {
			t.Fatal("no CSAF document about CVE-2026-1001")
		}
		if got := portable.Vulnerabilities[0].Status.KnownNotAffected; !slices.Equal(got, []string{openssl.Purl}) {
			t.Errorf("known not affected %v, want the component alone %s", got, openssl.Purl)
		}
		if len(portable.ProductTree.Relationships) != 0 {
			t.Errorf("a statement holding for anybody is stated through %d relationships",
				len(portable.ProductTree.Relationships))
		}
		if flags := portable.Vulnerabilities[0].Flags; len(flags) != 1 ||
			flags[0].Label != string(triage.CodeNotPresent) {
			t.Errorf("flags %+v, want the reason", flags)
		}

		ours := w.csafAbout(w.Product, "CVE-2026-1002")
		if ours == nil {
			t.Fatal("no CSAF document about CVE-2026-1002")
		}
		part := libnl.Purl + "|" + buildID(fixture.BranchName, fixture.CustomerVariant)
		if got := ours.Vulnerabilities[0].Status.KnownNotAffected; !slices.Equal(got, []string{part}) {
			t.Errorf("known not affected %v, want the component as part of the build %s", got, part)
		}
		if len(ours.ProductTree.Relationships) != 1 ||
			ours.ProductTree.Relationships[0].Reference != libnl.Purl ||
			ours.ProductTree.Relationships[0].Within != buildID(fixture.BranchName, fixture.CustomerVariant) {
			t.Errorf("relationships %+v, want libnl as part of the build", ours.ProductTree.Relationships)
		}
		if leaf := buildLeaf(ours); leaf == nil || leaf.Helper == nil || leaf.Helper.Purl != sonicRoot.Purl {
			t.Errorf("the build is named %+v, want it by the package identifier its inventory gave it", leaf)
		}

		stream := w.openVEXAbout(w.Product, fixture.BranchName)
		if stream == nil {
			t.Fatal("no OpenVEX document about the branch")
		}
		saw := 0
		for _, statement := range stream.Statements {
			switch statement.Vulnerability.Name {
			case "CVE-2026-1001":
				saw++
				if statement.Products[0].ID != openssl.Purl || len(statement.Products[0].Subcomponents) != 0 {
					t.Errorf("a statement holding for anybody names %+v, want the component alone",
						statement.Products)
				}
			case "CVE-2026-1002":
				saw++
				if statement.Products[0].ID != sonicRoot.Purl || len(statement.Products[0].Subcomponents) != 1 ||
					statement.Products[0].Subcomponents[0].ID != libnl.Purl {
					t.Errorf("a statement holding for this build names %+v, want the build with "+
						"the component beneath it", statement.Products)
				}
			}
		}
		if saw != 2 {
			t.Errorf("%d of the two statements were in the OpenVEX document", saw)
		}
	})
}

// buildLeaf is the build a CSAF document names, where it names one.
func buildLeaf(doc *advisory.Document) *advisory.Named {
	for _, vendor := range doc.ProductTree.Branches {
		for _, product := range vendor.Branches {
			for _, version := range product.Branches {
				return version.Product
			}
		}
	}
	return nil
}

// Whom a statement holds for is what the claim states where it states it,
// either way.
func TestAClaimStatesWhomItsStatementHoldsFor(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Target, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		// The reason says anybody, and the claim says this build only.
		w.decide(w.Target, "CVE-2026-1001", openssl, claim{outcome: triage.NotApplicable,
			justification: triage.CodeNotPresent, scope: triage.BuildSpecific})
		// The reason says this build, and the claim says anybody.
		w.decide(w.Target, "CVE-2026-1002", libnl, claim{outcome: triage.NotApplicable,
			justification: triage.CodeNotInExecutePath, scope: triage.Portable})
		w.publishes(w.Product, true)
		w.write()

		narrowed := w.csafAbout(w.Product, "CVE-2026-1001")
		part := openssl.Purl + "|" + buildID(fixture.BranchName, fixture.CustomerVariant)
		if got := narrowed.Vulnerabilities[0].Status.KnownNotAffected; !slices.Equal(got, []string{part}) {
			t.Errorf("known not affected %v, want %s: the claim said this build only", got, part)
		}
		widened := w.csafAbout(w.Product, "CVE-2026-1002")
		if got := widened.Vulnerabilities[0].Status.KnownNotAffected; !slices.Equal(got, []string{libnl.Purl}) {
			t.Errorf("known not affected %v, want %s: the claim said anybody", got, libnl.Purl)
		}
	})
}

// A statement the builds of one product disagree on is not stated about the
// component alone: one build saying the component is not affected while
// another has the same component open and undecided would contradict it.
func TestAStatementTheBuildsDisagreeOnIsStatedPerBuild(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		// The lab build ships the same openssl beneath swss, a place the
		// claim below does not reach.
		lab := w.TargetFor(w.Branch, w.Internal)
		labRoot := graph.Described{Purl: "pkg:generic/sonic@lab.7", Name: "sonic", Version: "lab.7"}
		w.ship(lab, labRoot, edge{labRoot, swss}, edge{swss, openssl})
		w.report(w.Target, reported{"CVE-2026-1001", openssl})
		w.report(lab, reported{"CVE-2026-1001", openssl})
		w.decide(w.Target, "CVE-2026-1001", openssl,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.publishes(w.Product, true)
		w.write()

		doc := w.csafAbout(w.Product, "CVE-2026-1001")
		status := doc.Vulnerabilities[0].Status
		ours := openssl.Purl + "|" + buildID(fixture.BranchName, fixture.CustomerVariant)
		theirs := openssl.Purl + "|" + buildID(fixture.BranchName, fixture.InternalVariant)
		if !slices.Equal(status.KnownNotAffected, []string{ours}) {
			t.Errorf("known not affected %v, want %s alone", status.KnownNotAffected, ours)
		}
		if !slices.Equal(status.UnderInvestigation, []string{theirs}) {
			t.Errorf("under investigation %v, want %s", status.UnderInvestigation, theirs)
		}
		if slices.Contains(status.KnownNotAffected, openssl.Purl) {
			t.Error("the component is stated not affected alone while a build of it is open")
		}
	})
}

// Every status is published, until the deployment limits it to statements
// that something is not affected or is fixed; a document left with nothing
// is withdrawn, and one written under the wider setting is not served once
// the setting narrows, before anything is written again.
func TestEveryStatusIsPublishedUnlessLimited(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Target, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1003", zlibUnder(w)},
			reported{"CVE-2026-1004", libnl})
		w.decide(w.Target, "CVE-2026-1001", openssl,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.decide(w.Target, "CVE-2026-1004", libnl, claim{outcome: triage.Affected})
		w.publishes(w.Product, true)
		w.write()

		if doc := w.csafAbout(w.Product, "CVE-2026-1003"); doc == nil ||
			len(doc.Vulnerabilities[0].Status.UnderInvestigation) != 1 {
			t.Errorf("an issue nobody decided is not published as under investigation: %+v", doc)
		}
		affected := w.csafAbout(w.Product, "CVE-2026-1004")
		if affected == nil || len(affected.Vulnerabilities[0].Status.KnownAffected) != 1 {
			t.Fatalf("an issue that applies is not published as affected: %+v", affected)
		}
		if r := affected.Vulnerabilities[0].Remediations; len(r) != 1 || r[0].Category != "none_available" ||
			r[0].Details != vex.NoFixYet {
			t.Errorf("an affected component carries %+v, want that no fix is available yet", r)
		}

		if _, _, err := setting.NewStore(w.DB.DB).Change(t.Context(), setting.PublishedStatuses,
			setting.SettledStatuses); err != nil {
			t.Fatal(err)
		}
		// Narrowed, and nothing written since: what was written under every
		// status is not handed over.
		if listed := w.listed(setting.SettledStatuses); len(listed) != 0 {
			t.Errorf("%d documents written under every status are served under the narrower "+
				"setting", len(listed))
		}
		w.write()
		var issues []string
		for _, one := range w.listed(setting.SettledStatuses) {
			if one.Kind == publish.CSAFVEX {
				issues = append(issues, strings.TrimPrefix(one.TrackingID, "VEX-"+w.Product.Name+"-"))
			}
		}
		if !slices.Equal(issues, []string{"CVE-2026-1001"}) {
			t.Errorf("published %v under the narrower setting, want the one not affected", issues)
		}
		stream := w.openVEXAbout(w.Product, fixture.BranchName)
		for _, statement := range stream.Statements {
			if statement.Status != vex.NotAffected && statement.Status != vex.Fixed {
				t.Errorf("the OpenVEX document states %s under the narrower setting", statement.Status)
			}
		}
	})
}

// zlibUnder ships zlib in the default build beneath swss, and answers it.
func zlibUnder(w *world) graph.Described {
	w.t.Helper()
	w.ship(w.Target, sonicRoot,
		edge{sonicRoot, openssl}, edge{sonicRoot, swss}, edge{swss, libnl}, edge{swss, zlib})
	return zlib
}

// A document is revised only where what it states moved: the same answer
// again is the same revision, and a changed one is the next, keeping its
// identifier, its path, its first release and every revision before it.
func TestADocumentIsRevisedOnlyWhenItsAnswerMoves(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Target, reported{"CVE-2026-1001", openssl})
		w.publishes(w.Product, true)
		first := w.write()
		if first.Revised == 0 {
			t.Fatal("the first pass wrote nothing")
		}
		before := w.csafAbout(w.Product, "CVE-2026-1001")
		if again := w.write(); again.Revised != 0 || again.Withdrawn != 0 {
			t.Errorf("a pass over nothing that moved revised %d and withdrew %d",
				again.Revised, again.Withdrawn)
		}

		w.decide(w.Target, "CVE-2026-1001", openssl,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		if moved := w.write(); moved.Revised != 2 {
			t.Errorf("a decision revised %d documents, want the CSAF and the OpenVEX one", moved.Revised)
		}
		after := w.csafAbout(w.Product, "CVE-2026-1001")
		was, now := before.Document.Tracking, after.Document.Tracking
		if was.ID != now.ID || now.Version != "2" || len(now.RevisionHistory) != 2 {
			t.Errorf("revised as %s version %s with %d revisions, want %s version 2 with two",
				now.ID, now.Version, len(now.RevisionHistory), was.ID)
		}
		if !now.InitialReleaseDate.Equal(was.InitialReleaseDate) ||
			!now.RevisionHistory[0].Date.Equal(was.RevisionHistory[0].Date) {
			t.Error("a revision moved when the document was first released")
		}
		if advisory.PathFor(before) != advisory.PathFor(after) {
			t.Errorf("a revision moved the document from %s to %s", advisory.PathFor(before),
				advisory.PathFor(after))
		}
	})
}

// A document about an issue the product has nothing to say about any more is
// withdrawn and not served, and served again as the revision it was when the
// issue comes back saying the same thing.
func TestADocumentWithNothingToSayIsWithdrawn(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Target, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		w.publishes(w.Product, true)
		w.write()
		before := w.csafAbout(w.Product, "CVE-2026-1002")
		if before == nil {
			t.Fatal("no document about CVE-2026-1002")
		}

		// The scanner stops reporting it.
		w.report(w.Target, reported{"CVE-2026-1001", openssl})
		if wrote := w.write(); wrote.Withdrawn != 1 {
			t.Errorf("withdrew %d documents, want the one about CVE-2026-1002", wrote.Withdrawn)
		}
		if doc := w.csafAbout(w.Product, "CVE-2026-1002"); doc != nil {
			t.Error("a withdrawn document is served")
		}
		path := publish.DirectoryPath + advisory.PathFor(before)
		if _, err := w.documents.At(t.Context(), w.anybody(), path, "all"); err == nil {
			t.Errorf("a withdrawn document is served at %s", path)
		}

		w.report(w.Target, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		w.write()
		after := w.csafAbout(w.Product, "CVE-2026-1002")
		if after == nil || after.Document.Tracking.Version != before.Document.Tracking.Version {
			t.Errorf("the document came back as %+v, want the revision it was", after)
		}
	})
}
