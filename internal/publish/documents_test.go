// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish_test

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
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
	w.ship(w.Build, sonicRoot,
		edge{sonicRoot, openssl}, edge{sonicRoot, swss}, edge{swss, libnl})
}

// buildID is how a CSAF document names a build of the default product.
func buildID(branchOrTag, variant string) string {
	return fixture.ProductName + ":" + branchOrTag + ":" + variant
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
		w.report(w.Build, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		w.decide(w.Build, "CVE-2026-1001", openssl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.decide(w.Build, "CVE-2026-1002", libnl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotInExecutePath})
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

		branchOrTag := w.openVEXAbout(w.Product, fixture.BranchName)
		if branchOrTag == nil {
			t.Fatal("no OpenVEX document about the branch")
		}
		saw := 0
		for _, statement := range branchOrTag.Statements {
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

// Whom a statement holds for is what the decision states where it states it,
// either way.
func TestADecisionStatesWhomItsStatementHoldsFor(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Build, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		// The reason says anybody, and the decision says this build only.
		w.decide(w.Build, "CVE-2026-1001", openssl, decision{outcome: triage.NotApplicable,
			justification: triage.CodeNotPresent, scope: triage.BuildSpecific})
		// The reason says this build, and the decision says anybody.
		w.decide(w.Build, "CVE-2026-1002", libnl, decision{outcome: triage.NotApplicable,
			justification: triage.CodeNotInExecutePath, scope: triage.Portable})
		w.publishes(w.Product, true)
		w.write()

		narrowed := w.csafAbout(w.Product, "CVE-2026-1001")
		part := openssl.Purl + "|" + buildID(fixture.BranchName, fixture.CustomerVariant)
		if got := narrowed.Vulnerabilities[0].Status.KnownNotAffected; !slices.Equal(got, []string{part}) {
			t.Errorf("known not affected %v, want %s: the decision said this build only", got, part)
		}
		widened := w.csafAbout(w.Product, "CVE-2026-1002")
		if got := widened.Vulnerabilities[0].Status.KnownNotAffected; !slices.Equal(got, []string{libnl.Purl}) {
			t.Errorf("known not affected %v, want %s: the decision said anybody", got, libnl.Purl)
		}
	})
}

// A statement the builds of one product disagree on is not stated about the
// component alone: one build saying the component is not affected while
// another says it is affected would contradict it.
func TestAStatementTheBuildsDisagreeOnIsStatedPerBuild(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		// The lab build ships the same openssl beneath swss, an occurrence the
		// decision below does not reach.
		lab := w.BuildFor(w.Branch, w.Internal)
		labRoot := graph.Described{Purl: "pkg:generic/sonic@lab.7", Name: "sonic", Version: "lab.7"}
		w.ship(lab, labRoot, edge{labRoot, swss}, edge{swss, openssl})
		w.report(w.Build, reported{"CVE-2026-1001", openssl})
		w.report(lab, reported{"CVE-2026-1001", openssl})
		w.decide(w.Build, "CVE-2026-1001", openssl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.decide(lab, "CVE-2026-1001", openssl, decision{outcome: triage.Affected})
		w.publishes(w.Product, true)
		w.write()

		doc := w.csafAbout(w.Product, "CVE-2026-1001")
		status := doc.Vulnerabilities[0].Status
		ours := openssl.Purl + "|" + buildID(fixture.BranchName, fixture.CustomerVariant)
		theirs := openssl.Purl + "|" + buildID(fixture.BranchName, fixture.InternalVariant)
		if !slices.Equal(status.KnownNotAffected, []string{ours}) {
			t.Errorf("known not affected %v, want %s alone", status.KnownNotAffected, ours)
		}
		if !slices.Equal(status.KnownAffected, []string{theirs}) {
			t.Errorf("known affected %v, want %s", status.KnownAffected, theirs)
		}
		if slices.Contains(status.KnownNotAffected, openssl.Purl) {
			t.Error("the component is stated not affected alone while a build of it is affected")
		}
	})
}

// What somebody decided is published, every status of it, until the
// deployment limits it to statements that something is not affected or is
// fixed; a document left with nothing is withdrawn, and one written under the
// wider setting is not served once the setting narrows, before anything is
// written again. An issue nobody decided about has no document at all.
func TestEveryStatusIsPublishedUnlessLimited(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Build, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1003", zlibUnder(w)},
			reported{"CVE-2026-1004", libnl}, reported{"CVE-2026-1005", openssl},
			reported{"CVE-2026-1006", libnl})
		w.decide(w.Build, "CVE-2026-1001", openssl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.decide(w.Build, "CVE-2026-1004", libnl, decision{outcome: triage.Affected})
		// A dismissal nobody has agreed to yet, and a deferral: neither is a
		// decision that the issue applies, and neither is published.
		w.decide(w.Build, "CVE-2026-1005", openssl, decision{outcome: triage.NotApplicable,
			justification: triage.CodeNotPresent, waiting: true})
		later := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(24 * time.Hour)
		w.decide(w.Build, "CVE-2026-1006", libnl, decision{outcome: triage.Deferred, deferredUntil: &later})
		w.publishes(w.Product, true)
		w.write()

		for _, undecided := range []string{"CVE-2026-1003", "CVE-2026-1005", "CVE-2026-1006"} {
			if doc := w.csafAbout(w.Product, undecided); doc != nil {
				t.Errorf("%s, which nobody decided, is published: %+v", undecided,
					doc.Vulnerabilities[0].Status)
			}
			for _, statement := range w.openVEXAbout(w.Product, fixture.BranchName).Statements {
				if statement.Vulnerability.Name == undecided {
					t.Errorf("%s, which nobody decided, is stated as %s", undecided, statement.Status)
				}
			}
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
				issues = append(issues, strings.TrimPrefix(one.TrackingID, "VEX-"+strconv.FormatInt(w.Product.ID, 10)+"-"+w.Product.Name+"-"))
			}
		}
		if !slices.Equal(issues, []string{"CVE-2026-1001"}) {
			t.Errorf("published %v under the narrower setting, want the one not affected", issues)
		}
		branchOrTag := w.openVEXAbout(w.Product, fixture.BranchName)
		for _, statement := range branchOrTag.Statements {
			if statement.Status != vex.NotAffected && statement.Status != vex.Fixed {
				t.Errorf("the OpenVEX document states %s under the narrower setting", statement.Status)
			}
		}
	})
}

// zlibUnder ships zlib in the default build beneath swss, and answers it.
func zlibUnder(w *world) graph.Described {
	w.t.Helper()
	w.ship(w.Build, sonicRoot,
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
		w.report(w.Build, reported{"CVE-2026-1001", openssl})
		// The build's own reason, so the document names each build it holds
		// for.
		w.decide(w.Build, "CVE-2026-1001", openssl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotInExecutePath})
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

		// The lab build ships the same openssl at the same occurrence, and the
		// decision reaches it: the document now speaks for a second build.
		lab := w.BuildFor(w.Branch, w.Internal)
		labRoot := graph.Described{Purl: "pkg:generic/sonic@lab.7", Name: "sonic", Version: "lab.7"}
		w.ship(lab, labRoot, edge{labRoot, openssl})
		w.report(lab, reported{"CVE-2026-1001", openssl})
		if moved := w.write(); moved.Revised != 2 {
			t.Errorf("a second build revised %d documents, want the CSAF and the OpenVEX one", moved.Revised)
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
		w.report(w.Build, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		w.decide(w.Build, "CVE-2026-1002", libnl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.publishes(w.Product, true)
		w.write()
		before := w.csafAbout(w.Product, "CVE-2026-1002")
		if before == nil {
			t.Fatal("no document about CVE-2026-1002")
		}

		// The scanner stops reporting it.
		w.report(w.Build, reported{"CVE-2026-1001", openssl})
		// The branch's OpenVEX document said nothing else, so it goes too.
		if wrote := w.write(); wrote.Withdrawn != 2 {
			t.Errorf("withdrew %d documents, want the CSAF and the OpenVEX one", wrote.Withdrawn)
		}
		if doc := w.csafAbout(w.Product, "CVE-2026-1002"); doc != nil {
			t.Error("a withdrawn document is served")
		}
		path := publish.DirectoryPath + advisory.PathFor(before)
		if _, err := w.documents.At(t.Context(), w.anybody(), path, "all"); err == nil {
			t.Errorf("a withdrawn document is served at %s", path)
		}

		w.report(w.Build, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		w.write()
		after := w.csafAbout(w.Product, "CVE-2026-1002")
		if after == nil || after.Document.Tracking.Version != before.Document.Tracking.Version {
			t.Errorf("the document came back as %+v, want the revision it was", after)
		}
	})
}

// Two products publish a CSAF VEX document each at a path of its own, whether
// their names fold alike under the standard's filename rule or one product's
// name and issue fold like the other's across the boundary between them: a
// tracking identifier opens on its product's identifier.
func TestTwoProductsNeverShareACSAFPath(t *testing.T) {
	for _, pair := range [][2][2]string{
		{{"edge.os", "CVE-2026-1001"}, {"edge os", "CVE-2026-1001"}},
		{{"acme", "GHSA-x-y"}, {"acme-ghsa", "x-y"}},
	} {
		t.Run(pair[0][0]+" beside "+pair[1][0], func(t *testing.T) {
			fixture.Each(t, func(t *testing.T, f *fixture.World) {
				w := newWorld(t, f)
				for i, one := range pair {
					product := w.DeclareProduct(one[0], one[0])
					w.hold(product)
					build := w.BuildFor(w.DeclareBranchOrTag(product, "main", catalog.Branch, nil),
						w.DeclareVariant(product, "x86", true))
					root := graph.Described{Purl: "pkg:generic/edge@1." + fmt.Sprint(i), Name: "edge",
						Version: "1." + fmt.Sprint(i)}
					w.ship(build, root, edge{root, openssl})
					w.report(build, reported{one[1], openssl})
					w.decide(build, one[1], openssl,
						decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
					w.publishes(product, true)
				}
				wrote, err := w.pass.Once(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if wrote.Skipped != 0 {
					t.Errorf("%d products were not worked out, want none", wrote.Skipped)
				}
				paths := map[string]bool{}
				for _, one := range w.listed("all") {
					if one.Kind == publish.CSAFVEX {
						paths[one.Path] = true
					}
				}
				if len(paths) != 2 {
					t.Errorf("the two products published CSAF VEX documents at %v, want two paths", paths)
				}
			})
		})
	}
}

// A CSAF VEX document held at a path its tracking identifier no longer gives
// is published at the new one as a new document, its first version, and the
// old path serves nothing.
func TestADocumentWhosePathMovedStartsAgainAtTheNewOne(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		ctx := t.Context()
		root := graph.Described{Purl: "pkg:generic/sonic@1.0", Name: "sonic", Version: "1.0"}
		w.ship(w.Build, root, edge{root, openssl})
		w.report(w.Build, reported{"CVE-2026-1001", openssl})
		w.decide(w.Build, "CVE-2026-1001", openssl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.publishes(w.Product, true)
		if _, err := w.pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		var now publish.Document
		if err := w.DB.DB.NewSelect().Model(&now).ExcludeColumn("document").
			Where(`"pub"."kind" = ?`, publish.CSAFVEX).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		// Held where an earlier shape of the tracking identifier put it.
		old := publish.DirectoryPath + "2025/vex-sonic-cve-2026-1001.json"
		if _, err := w.DB.DB.NewUpdate().TableExpr(`"published_document"`).
			Set(`"path" = ?`, old).Set(`"path_digest" = ?`, strings.Repeat("c", 64)).
			Set(`"tracking_id" = ?`, "VEX-sonic-CVE-2026-1001").Set(`"version" = ?`, 3).
			Set(`"first_at" = ?`, now.FirstAt.AddDate(-1, 0, 0)).
			Where(`"id" = ?`, now.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		wrote, err := w.pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if wrote.Revised != 1 {
			t.Errorf("the pass revised %d documents, want the one that moved", wrote.Revised)
		}
		var moved publish.Document
		if err := w.DB.DB.NewSelect().Model(&moved).ExcludeColumn("document").
			Where(`"pub"."id" = ?`, now.ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if moved.Path != now.Path || moved.TrackingID != now.TrackingID || moved.Version != 1 {
			t.Errorf("the moved document is at %s as %s version %d, want %s as %s version 1",
				moved.Path, moved.TrackingID, moved.Version, now.Path, now.TrackingID)
		}
		if _, err := w.documents.At(ctx, w.anybody(), old, "all"); !errors.Is(err, publish.ErrNotPublished) {
			t.Errorf("the old path answered %v, want nothing published there", err)
		}
	})
}

// Two issues of one product whose names fold alike under the standard's
// filename rule cannot both be published at the one path they fold to. The
// second is refused in words naming the first, and everything else the
// product publishes is still written.
func TestTwoIssuesFoldedAlikeDoNotStopEachOther(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		root := graph.Described{Purl: "pkg:generic/sonic@1.0", Name: "sonic", Version: "1.0"}
		w.ship(w.Build, root, edge{root, openssl})
		w.report(w.Build, reported{"GHSA-a.b", openssl}, reported{"GHSA-a_b", openssl})
		for _, issue := range []string{"GHSA-a.b", "GHSA-a_b"} {
			w.decide(w.Build, issue, openssl,
				decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		}
		w.publishes(w.Product, true)
		wrote, err := w.pass.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if wrote.Skipped != 1 {
			t.Errorf("%d products were not worked out, want this one", wrote.Skipped)
		}
		openvex, csafCount := 0, 0
		for _, one := range w.listed("all") {
			switch one.Kind {
			case publish.OpenVEX:
				openvex++
			case publish.CSAFVEX:
				csafCount++
			}
		}
		if openvex != 1 || csafCount != 1 {
			t.Errorf("published %d OpenVEX and %d CSAF documents, want one of each", openvex, csafCount)
		}
		_, err = w.pass.Product(t.Context(), w.anybody(), w.Product, "all")
		if !errors.Is(err, publish.ErrPathTaken) || !strings.Contains(strings.ToLower(err.Error()), "the document about ghsa-a") {
			t.Errorf("the second issue's document was refused as %v, want the path taken by the first", err)
		}
	})
}

// A document names the address it is served at and its publisher, so moving
// either revises every document rather than leaving the old ones saying what
// the feed no longer does.
func TestMovingTheAddressRevisesEveryDocument(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Build, reported{"CVE-2026-1001", openssl})
		w.decide(w.Build, "CVE-2026-1001", openssl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.publishes(w.Product, true)
		w.write()
		moved := publish.NewPass(w.DB.DB, publish.NewGenerator(w.DB.DB, who, "https://elsewhere.example.test"),
			"test", slog.New(slog.DiscardHandler))
		wrote, err := moved.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if wrote.Revised != 2 {
			t.Errorf("moving the address revised %d documents, want both", wrote.Revised)
		}
	})
}

// A decision that it will not be fixed is stated affected with what to do
// instead where the decision named it, and that no fix is planned where it
// named nothing: both formats require an action on an affected statement, and
// an empty one fails a reader's validator for the whole document.
func TestAWontFixNamingNothingToDoStatesThatNoFixIsPlanned(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Build, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		w.decide(w.Build, "CVE-2026-1001", openssl, decision{outcome: triage.WontFix})
		w.decide(w.Build, "CVE-2026-1002", libnl,
			decision{outcome: triage.WontFix, mitigation: "Turn the netlink listener off."})
		w.publishes(w.Product, true)
		w.write()

		type said struct{ category, details string }
		for issue, want := range map[string][]said{
			"CVE-2026-1001": {{"no_fix_planned", vex.NoFixPlanned}},
			"CVE-2026-1002": {{"mitigation", "Turn the netlink listener off."},
				{"no_fix_planned", vex.NoFixPlanned}},
		} {
			doc := w.csafAbout(w.Product, issue)
			if doc == nil {
				t.Fatalf("no CSAF document about %s", issue)
			}
			var got []said
			for _, one := range doc.Vulnerabilities[0].Remediations {
				if one.Details == "" {
					t.Errorf("%s: a %s remediation has no details", issue, one.Category)
				}
				got = append(got, said{one.Category, one.Details})
			}
			if !slices.Equal(got, want) {
				t.Errorf("%s: remediations %v, want %v", issue, got, want)
			}
		}

		branchOrTag := w.openVEXAbout(w.Product, fixture.BranchName)
		if branchOrTag == nil {
			t.Fatal("no OpenVEX document about the branch")
		}
		want := map[string]string{
			"CVE-2026-1001": vex.NoFixPlanned, "CVE-2026-1002": "Turn the netlink listener off.",
		}
		for _, statement := range branchOrTag.Statements {
			if statement.Status != vex.Affected {
				t.Errorf("%s is stated %s", statement.Vulnerability.Name, statement.Status)
			}
			if statement.ActionStatement != want[statement.Vulnerability.Name] {
				t.Errorf("%s: action %q, want %q", statement.Vulnerability.Name,
					statement.ActionStatement, want[statement.Vulnerability.Name])
			}
			delete(want, statement.Vulnerability.Name)
		}
		if len(want) != 0 {
			t.Errorf("no OpenVEX statement about %v", want)
		}
	})
}

// A pass that generated a product's documents before publishing was turned
// off writes none of them after it: neither the document stating again what
// it stated, nor a revision, nor a new one. Turned on again, the product
// serves nothing until a pass works its documents out again.
func TestAPassRacingATurnOffServesNothingWhenTurnedOnAgain(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Build, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
		w.decide(w.Build, "CVE-2026-1001", openssl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.publishes(w.Product, true)
		w.write()
		// Who the pass generates for, read as the pass reads it before
		// publishing is turned off.
		subject := w.anybody()
		statuses, err := publish.Statuses(t.Context(), w.DB.DB)
		if err != nil {
			t.Fatal(err)
		}

		// Something new to say, so the late write would be a new document
		// and a revision as well as one stated again.
		w.decide(w.Build, "CVE-2026-1002", libnl,
			decision{outcome: triage.NotApplicable, justification: triage.CodeNotInExecutePath})
		// Turned off as an administrator turns it off.
		w.publishes(w.Product, false)
		if err := w.documents.WithdrawProduct(t.Context(), w.Product.ID); err != nil {
			t.Fatal(err)
		}

		wrote, err := w.pass.Product(t.Context(), subject, w.Product, statuses)
		if err != nil {
			t.Fatal(err)
		}
		if wrote.Revised != 0 {
			t.Errorf("a pass generated before the turn-off wrote %d documents after it", wrote.Revised)
		}
		w.publishes(w.Product, true)
		if listed := w.listed("all"); len(listed) != 0 {
			t.Errorf("turned on again, the product serves %d documents no pass worked out since: %+v",
				len(listed), listed)
		}
	})
}
