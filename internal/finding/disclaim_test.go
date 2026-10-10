// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// A supplier's statement that its own product is not affected closes the
// finding at the places that product occupies (REQ-31). The fixture is the
// issue's own example: Acme's product Y, at 4.2, bundles zlib, and Acme says Y
// never calls the function CVE-2022-37434 is in.

var (
	acmeY    = graph.Described{Purl: "pkg:generic/acme-y@4.2", Name: "acme-y", Version: "4.2"}
	acmeYNew = graph.Described{Purl: "pkg:generic/acme-y@4.3", Name: "acme-y", Version: "4.3"}
	zlib     = graph.Described{Purl: "pkg:generic/zlib@1.2.11", Name: "zlib", Version: "1.2.11"}
	curl     = at("curl", "8.5.0")
	libpng   = at("libpng16-16", "1.6.43")
	other    = at("other-product", "2.0")
)

// The three issues the fixture's statements are about, one per shape.
const (
	inside      = "CVE-2022-37434" // zlib inside Y 4.2
	productOnly = "CVE-2023-45853" // Y 4.2 alone
	noVersion   = "CVE-2018-25032" // zlib inside Y, no version
)

// acmeSays records the fixture document as an upload of Acme's statement set.
func (f *fixture) acmeSays(t *testing.T) {
	t.Helper()
	file, err := os.Open("../sbom/testdata/supplier-product-inside.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	claims, err := sbom.ReadSuppressions(file, sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var said []finding.Statement
	for _, claim := range claims {
		for _, target := range claim.Targets {
			said = append(said, finding.StatementOf(claim, target))
		}
	}
	f.publishes(t, said, "sha256:acme-1")
}

// publishes records a statement set from Acme in place of the one before it.
func (f *fixture) publishes(t *testing.T, said []finding.Statement, digest string) {
	t.Helper()
	who := f.planner(t, access.PublicTriage)
	if _, _, err := f.store.RecordStatements(t.Context(), who, f.productID, finding.Supplied{
		Source: finding.FromVex, Publisher: "Acme Security",
		Document: "acme-y.openvex.json", Digest: digest,
	}, said); err != nil {
		t.Fatal(err)
	}
}

// placedAt is each row the target holds, by the name of what pulls it in.
func placedAt(t *testing.T, f *fixture, rows []finding.Finding) map[string]finding.Finding {
	t.Helper()
	names := map[int64]string{}
	var components []graph.Component
	if err := f.db.DB.NewSelect().Model(&components).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, c := range components {
		names[c.ID] = c.Name
	}
	out := map[string]finding.Finding{}
	for _, row := range rows {
		consumer := ""
		if row.ConsumerID != nil {
			consumer = names[*row.ConsumerID]
		}
		out[names[row.ComponentID]+" under "+consumer] = row
	}
	return out
}

// beside is zlib inside Y, and the same zlib pulled in by curl outside it.
func beside(product graph.Described) graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{product, curl, zlib},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: product},
			{Parent: root, Child: curl},
			{Parent: product, Child: zlib},
			{Parent: curl, Child: zlib},
		},
	}
}

// shared is zlib under a libpng that Y pulls in and another product pulls in
// too: one place, reached through Y and outside it.
func shared() graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{acmeY, other, libpng, zlib},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: acmeY},
			{Parent: root, Child: other},
			{Parent: acmeY, Child: libpng},
			{Parent: other, Child: libpng},
			{Parent: libpng, Child: zlib},
		},
	}
}

// deep is zlib under a libpng only Y pulls in.
func deep() graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{acmeY, libpng, zlib},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: acmeY},
			{Parent: acmeY, Child: libpng},
			{Parent: libpng, Child: zlib},
		},
	}
}

func TestASuppliersStatementClosesTheFindingInsideItsProductAndNoOther(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.acmeSays(t)

		applied, runID := f.reported(t, found(inside, zlib))
		if applied.Disclaimed != 1 || applied.Opened != 1 {
			t.Errorf("disclaimed %d and opened %d, want the zlib inside Y closed and the one "+
				"under curl open", applied.Disclaimed, applied.Opened)
		}
		rows := placedAt(t, f, f.every(t))
		inY, underCurl := rows["zlib under acme-y"], rows["zlib under curl"]
		if inY.ClosedAt == nil || inY.ClosedBecause != finding.Disclaimed || inY.StatedBy == nil {
			t.Errorf("the zlib inside Y is closed %v because %q by %v, want disclaimed by the statement",
				inY.ClosedAt, inY.ClosedBecause, inY.StatedBy)
		}
		if inY.ClosedRunID == nil || *inY.ClosedRunID != runID || inY.DueAt != nil {
			t.Error("the zlib inside Y is not recorded closed by the run, with no deadline")
		}
		if underCurl.ClosedAt != nil || underCurl.StatedBy != nil {
			t.Errorf("the zlib under curl is closed %v, answered by %v; nothing answers it",
				underCurl.ClosedAt, underCurl.StatedBy)
		}

		again, _ := f.reported(t, found(inside, zlib))
		if !again.Unchanged() {
			t.Errorf("re-scanning wrote %+v", again)
		}
	})
}

func TestAnOpenFindingInsideTheProductClosesOnTheNextScan(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		if applied, _ := f.reported(t, found(inside, zlib)); applied.Opened != 2 {
			t.Fatalf("opened %d, want one per consumer", applied.Opened)
		}
		f.acmeSays(t)
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Closed != 1 || applied.Disclaimed != 1 {
			t.Errorf("closed %d and disclaimed %d, want the one inside Y", applied.Closed, applied.Disclaimed)
		}
		if open := f.open(t); len(open) != 1 {
			t.Errorf("%d open, want the one under curl", len(open))
		}
	})
}

func TestAPlaceReachedOnlyThroughTheProductClosesHoweverDeep(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, deep())
		f.acmeSays(t)
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Disclaimed != 1 || applied.Opened != 0 {
			t.Errorf("disclaimed %d and opened %d, want the zlib two steps under Y closed",
				applied.Disclaimed, applied.Opened)
		}
	})
}

func TestAPlaceReachedThroughTheProductAndOutsideItStaysOpenAnswered(t *testing.T) {
	// One row stands for both routes. Closed, it hides the route nobody
	// answered; open with nothing on it, it hides that the supplier answered
	// the other.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, shared())
		f.acmeSays(t)
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Disclaimed != 0 || applied.Opened != 1 {
			t.Errorf("disclaimed %d and opened %d, want the shared place open", applied.Disclaimed,
				applied.Opened)
		}
		open := f.open(t)
		if len(open) != 1 || open[0].StatedBy == nil {
			t.Fatalf("the shared place is %+v, want it open and answered through Y", open)
		}

		// Y stops pulling in the shared libpng, so every route runs through
		// nothing but the other product, and the answer goes.
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{acmeY, other, libpng, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: acmeY},
				{Parent: root, Child: other},
				{Parent: other, Child: libpng},
				{Parent: libpng, Child: zlib},
			},
		})
		moved, _ := f.reported(t, found(inside, zlib))
		if moved.Updated != 1 {
			t.Errorf("updated %d, want the answer taken off the row", moved.Updated)
		}
		if open := f.open(t); len(open) != 1 || open[0].StatedBy != nil {
			t.Errorf("a place no longer under Y is %+v, want it open with nothing answering it", open)
		}
	})
}

func TestAStatementAboutAnotherReleaseOfTheProductClosesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeYNew))
		f.acmeSays(t)
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Disclaimed != 0 || applied.Opened != 2 {
			t.Errorf("disclaimed %d and opened %d; a statement about Y 4.2 says nothing about 4.3",
				applied.Disclaimed, applied.Opened)
		}
	})
}

func TestTheFindingOpensAgainWhenTheProductMovesToAnotherRelease(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))

		f.shipped(t, beside(acmeYNew))
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Opened != 1 {
			t.Errorf("opened %d once Y moved to 4.3, want the zlib inside it", applied.Opened)
		}
		if open := f.open(t); len(open) != 2 {
			t.Errorf("%d open, want both zlib places", len(open))
		}
	})
}

func TestAStatementNamingNoReleaseOfTheProductClosesNothing(t *testing.T) {
	// A product named with no version is every release of it, past and
	// future, and a supplier rarely means that.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.acmeSays(t)
		applied, _ := f.reported(t, found(noVersion, zlib))
		if applied.Disclaimed != 0 || applied.Opened != 2 {
			t.Errorf("disclaimed %d and opened %d from a statement naming no version",
				applied.Disclaimed, applied.Opened)
		}
		for _, row := range f.open(t) {
			if row.StatedBy != nil {
				t.Error("a statement naming no version answers a place")
			}
		}
	})
}

func TestAStatementNamingTheProductAloneClosesWhatSitsBeneathIt(t *testing.T) {
	// "Y 4.2 is not affected by this CVE" is the supplier speaking about
	// everything they shipped. A finding on Y itself stays open: a statement
	// naming a package alone cannot tell the supplier's own build from a
	// rebuild of its source, so it stays evidence.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.acmeSays(t)
		applied, _ := f.reported(t, found(productOnly, zlib), found(productOnly, acmeY))
		if applied.Disclaimed != 1 {
			t.Errorf("disclaimed %d, want the zlib inside Y", applied.Disclaimed)
		}
		rows := placedAt(t, f, f.every(t))
		if row := rows["zlib under acme-y"]; row.ClosedBecause != finding.Disclaimed {
			t.Errorf("the zlib inside Y closed as %q", row.ClosedBecause)
		}
		if row := rows["acme-y under "]; row.ClosedAt != nil {
			t.Errorf("the finding on Y itself closed as %q", row.ClosedBecause)
		}
		if row := rows["zlib under curl"]; row.ClosedAt != nil {
			t.Errorf("the zlib under curl closed as %q", row.ClosedBecause)
		}
	})
}

func TestTheFindingOpensAgainWhenTheSupplierWithdrawsTheStatement(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))

		// Acme's next statement set says nothing about it.
		f.publishes(t, []finding.Statement{{
			Vulnerability: productOnly, Purl: acmeY.Purl, Component: "acme-y", About: "4.2",
			Status: "not_affected", Justification: "vulnerable_code_not_present",
		}}, "sha256:acme-2")
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Opened != 1 {
			t.Errorf("opened %d once the statement was set aside, want the zlib inside Y", applied.Opened)
		}
	})
}

func TestAFindingClosedByAStatementPointsAtItsRevision(t *testing.T) {
	// A revision that still says the same thing moves the evidence and writes
	// no new row.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))
		before := placedAt(t, f, f.every(t))["zlib under acme-y"]

		f.publishes(t, []finding.Statement{{
			Vulnerability: inside, Purl: zlib.Purl, Component: "zlib", About: "1.2.11",
			WithinPurl: acmeY.Purl, Within: "acme-y", WithinAbout: "4.2",
			Placement: finding.PlacedInside,
			Status:    "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			Statement: "Acme Y does not link inflateGetHeader at all.",
		}}, "sha256:acme-3")
		f.reported(t, found(inside, zlib))
		rows := f.every(t)
		if len(rows) != 2 {
			t.Fatalf("%d rows, want the same 2", len(rows))
		}
		after := placedAt(t, f, rows)["zlib under acme-y"]
		if after.ID != before.ID || after.StatedBy == nil || before.StatedBy == nil ||
			*after.StatedBy == *before.StatedBy {
			t.Errorf("the closed row is %d answered by %v, was %d answered by %v; want the same row "+
				"pointing at the revision", after.ID, after.StatedBy, before.ID, before.StatedBy)
		}
	})
}

func TestAPlaceSomebodyMarkedAffectedStaysOpen(t *testing.T) {
	// A disagreement with the supplier goes through the ordinary route.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, beside(acmeY))
		f.reported(t, found(inside, zlib))

		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "somebody@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var issueID int64
		if err := f.db.DB.NewSelect().TableExpr(`"vulnerability" AS "v"`).Column("v.id").
			Where("v.identifier = ?", inside).Scan(ctx, &issueID); err != nil {
			t.Fatal(err)
		}
		row := map[string]any{
			"claim_id":   claimSaying(t, f.db, somebody.ID, finding.AffectedOutcome),
			"product_id": f.productID, "vulnerability_id": issueID,
			"place_identity": finding.PlaceIdentity(zlib.Name, acmeY.Name), "visibility": "public",
			"state": "proposed", "needs_approval": false, "proposed_by": somebody.ID,
			"proposed_at":                time.Now().UTC(),
			"component_upstream_version": zlib.Version,
			"consumer_upstream_version":  acmeY.Version,
			"live_key":                   "affected-here",
		}
		if _, err := f.db.DB.NewInsert().Model(&row).TableExpr(`"decision"`).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		f.acmeSays(t)
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Disclaimed != 0 {
			t.Errorf("disclaimed %d where somebody said the issue applies", applied.Disclaimed)
		}
		if open := f.open(t); len(open) != 2 {
			t.Errorf("%d open, want both places", len(open))
		}
	})
}

func TestAStatementTheBuildsOwnPatchAlreadyAnswersClosesNothing(t *testing.T) {
	// The build's word about its own code is asked first.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, []sbom.Suppression{{
			Vulnerability: inside, Status: sbom.AlreadyFixed, Origin: sbom.FromStatement,
			Targets: []sbom.Target{{Purl: zlib.Purl}},
		}}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		f.acmeSays(t)
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Patched != 2 || applied.Disclaimed != 0 {
			t.Errorf("patched %d and disclaimed %d, want both places patched",
				applied.Patched, applied.Disclaimed)
		}
	})
}

func TestAStatementAboutOneComponentInsideTheProductClosesNoOther(t *testing.T) {
	// Acme spoke about the zlib inside Y. A scanner reporting the same issue
	// against another component under Y has not been answered.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, deep())
		f.acmeSays(t)
		applied, _ := f.reported(t, found(inside, zlib), found(inside, libpng))
		if applied.Disclaimed != 1 || applied.Opened != 1 {
			t.Errorf("disclaimed %d and opened %d, want the zlib closed and the libpng open",
				applied.Disclaimed, applied.Opened)
		}
		open := placedAt(t, f, f.open(t))
		if _, held := open["libpng16-16 under acme-y"]; !held {
			t.Errorf("open is %v, want the libpng under Y", open)
		}
	})
}

func TestAPlaceTheSupplierAnswersOnSomeRoutesIsNotRunningOut(t *testing.T) {
	// Open, for the route nobody answered, and not work while it is.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, shared())
		long := func() []finding.Late {
			t.Helper()
			run := f.run(t)
			f.seenAt(t, run, time.Now().UTC().Add(-60*24*time.Hour))
			if _, err := f.store.Apply(t.Context(), f.target, run,
				[]finding.Reported{found(inside, zlib)}); err != nil {
				t.Fatal(err)
			}
			late, _, err := f.store.RunningOutPage(t.Context(), f.holding(t, access.PublicTriage),
				finding.Scope{}, 14*24*time.Hour, 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return late
		}
		if late := long(); len(late) != 1 {
			t.Fatalf("with nothing answering it, %d rows are running out, want 1", len(late))
		}
		f.acmeSays(t)
		if late := long(); len(late) != 0 {
			t.Errorf("answered through Y, %d rows are still running out", len(late))
		}
	})
}

func TestAStatementAboutAComponentInsideAProductIsEvidenceOnlyBeneathIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage)
		said := func(issue string) []finding.Statement {
			t.Helper()
			interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
				[]finding.Named{{Identifier: issue, Severity: "high"}})
			if err != nil {
				t.Fatal(err)
			}
			var componentID int64
			if err := f.db.DB.NewSelect().TableExpr(`"component" AS "c"`).Column("c.id").
				Where("c.purl = ?", zlib.Purl).Scan(ctx, &componentID); err != nil {
				t.Fatal(err)
			}
			got, err := f.store.SaidAbout(ctx, who, f.productID, interned[issue],
				[]string{issue}, "zlib", zlib.Purl, f.target, componentID)
			if err != nil {
				t.Fatal(err)
			}
			return got
		}

		// Y in the build, and zlib pulled in only by curl.
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{acmeY, curl, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: acmeY},
				{Parent: root, Child: curl},
				{Parent: curl, Child: zlib},
			},
		})
		f.acmeSays(t)
		if got := said(inside); len(got) != 0 {
			t.Errorf("a statement about the zlib inside Y is evidence on a zlib outside it: %+v", got)
		}
		if got := said(productOnly); len(got) != 0 {
			t.Errorf("a statement about Y alone is evidence on a zlib outside it: %+v", got)
		}

		// And now inside Y as well.
		f.shipped(t, beside(acmeY))
		if got := said(inside); len(got) != 1 || got[0].Within != "acme-y" {
			t.Errorf("the statement about the zlib inside Y reads %+v on the zlib inside it", got)
		}
		if got := said(productOnly); len(got) != 1 || got[0].Component != "acme-y" {
			t.Errorf("the statement about Y alone reads %+v on the zlib inside it", got)
		}
	})
}

func TestTheListFindsWhatASupplierAnsweredAndNothingElse(t *testing.T) {
	// A statement about the zlib inside Y reaches the list through the place
	// the run answered with it, and not through every zlib in the build.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{acmeY, other, libpng, curl, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: acmeY},
				{Parent: root, Child: other},
				{Parent: root, Child: curl},
				{Parent: acmeY, Child: libpng},
				{Parent: other, Child: libpng},
				{Parent: libpng, Child: zlib},
				{Parent: curl, Child: zlib},
			},
		})
		f.acmeSays(t)
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
		if got := places(finding.Filter{Publishers: []string{"Acme Security"}}); got != 1 {
			t.Errorf("what Acme spoke about is %d places, want the one under the shared libpng", got)
		}
		if got := places(finding.Filter{VexStatus: []string{"not_affected"}}); got != 1 {
			t.Errorf("what a supplier called not affected is %d places, want 1", got)
		}
	})
}

func TestTheRegisterListsWhatASupplierClosedWithTheirWords(t *testing.T) {
	// A closure nobody here decided is checked against the statement, so the
	// statement is beside it, and the closures of this kind are found together.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.reported(t, found(inside, zlib))
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))
		who := f.holding(t, access.PublicTriage)

		rows, total, err := f.store.Register(t.Context(), who, f.target, finding.Registering{
			Because: []finding.Closure{finding.Disclaimed},
		}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(rows) != 1 {
			t.Fatalf("closed by a supplier: %d rows, want the zlib inside Y", total)
		}
		row := rows[0]
		if row.DueAt == nil {
			t.Fatal("the row carried no deadline, so whether it met one checks nothing")
		}
		if row.ClosedBecause != finding.Disclaimed || row.Met != nil {
			t.Errorf("the row closed as %q, met %v; a supplier's closure meets no deadline",
				row.ClosedBecause, row.Met)
		}
		if row.Stated == nil || row.Stated.Publisher != "acme security" || row.Stated.Product != "acme-y" ||
			row.Stated.Statement != "Acme Y never calls inflateGetHeader()." {
			t.Errorf("the statement beside it is %+v", row.Stated)
		}
	})
}

func TestAStatementAboutAPlatformNothingHereShipsIsEvidenceByPackage(t *testing.T) {
	// A distribution composes its packages into a platform, and the platform
	// is no component of any build here. Its statement places nothing and
	// closes nothing, and is evidence wherever the package is, as it always
	// was.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, beside(acmeY))
		f.publishes(t, []finding.Statement{{
			Vulnerability: inside, Purl: zlib.Purl, Component: "zlib", About: "1.2.11",
			Within: "Example Platform 9", WithinAbout: "9",
			Status: "not_affected", Justification: "vulnerable_code_not_present",
		}}, "sha256:platform")
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Disclaimed != 0 || applied.Opened != 2 {
			t.Errorf("disclaimed %d and opened %d from a platform nothing here ships",
				applied.Disclaimed, applied.Opened)
		}

		who := f.planner(t, access.PublicTriage)
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: inside, Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		var componentID int64
		if err := f.db.DB.NewSelect().TableExpr(`"component" AS "c"`).Column("c.id").
			Where("c.purl = ?", zlib.Purl).Scan(ctx, &componentID); err != nil {
			t.Fatal(err)
		}
		said, err := f.store.SaidAbout(ctx, who, f.productID, interned[inside],
			[]string{inside}, "zlib", zlib.Purl, f.target, componentID)
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 1 {
			t.Errorf("the platform's statement is evidence %d times, want once", len(said))
		}
		groups, _, err := f.store.Groups(ctx, f.holding(t, access.PublicTriage), f.scope, 50, 0,
			finding.Filter{Publishers: []string{"Acme Security"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 || groups[0].Places != 2 {
			t.Errorf("the list finds %+v by the platform's publisher, want both zlib places", groups)
		}
	})
}

func TestAStatementRecordedBeforeItsProductWasReadClosesNothing(t *testing.T) {
	// Every statement recorded before the product was read names no
	// placement, a versioned package among them. Read as a product named
	// alone, Debian's word about one package closes the issue on everything
	// beneath it at the first scan after the upgrade.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.publishes(t, []finding.Statement{{
			Vulnerability: productOnly, Purl: acmeY.Purl, Component: "acme-y", About: "4.2",
			Status: "not_affected", Justification: "vulnerable_code_not_present",
		}}, "sha256:legacy")
		if applied, _ := f.reported(t, found(productOnly, zlib)); applied.Disclaimed != 0 {
			t.Errorf("a statement with no placement disclaimed %d", applied.Disclaimed)
		}
	})
}

func TestAPackageNamedAloneClosesNothing(t *testing.T) {
	// A distribution's package identifier is shared by its own build and by a
	// rebuild of its source, so a statement naming one alone stays evidence.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{libnl, libpng},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: libnl},
				{Parent: libnl, Child: libpng},
			},
		})
		claim := sbom.Suppression{Vulnerability: inside, Status: sbom.NotAffected,
			Justification: "vulnerable_code_not_present"}
		said := finding.StatementOf(claim, sbom.Target{Purl: libnl.Purl})
		if said.Placement != "" {
			t.Fatalf("a package named alone is placed as %q", said.Placement)
		}
		f.publishes(t, []finding.Statement{said}, "sha256:package")
		if applied, _ := f.reported(t, found(inside, libpng)); applied.Disclaimed != 0 {
			t.Errorf("a package named alone disclaimed %d beneath it", applied.Disclaimed)
		}
	})
}

func TestTheSameDocumentReadAgainIsPlacedWhereItStands(t *testing.T) {
	// Set aside and written again, every approved decision citing one of
	// these statements would be told the publisher changed what they said.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		file, err := os.Open("../sbom/testdata/supplier-product-inside.openvex.json")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = file.Close() }()
		claims, err := sbom.ReadSuppressions(file, sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		var placed, unplaced []finding.Statement
		for _, claim := range claims {
			for _, target := range claim.Targets {
				one := finding.StatementOf(claim, target)
				placed = append(placed, one)
				one.WithinPurl, one.Within, one.WithinAbout, one.Placement = "", "", "", ""
				unplaced = append(unplaced, one)
			}
		}
		who := f.planner(t, access.PublicTriage)
		from := finding.Supplied{Source: finding.FromVex, Publisher: "Acme Security",
			Document: "acme-y.openvex.json", Digest: "sha256:same"}
		if _, _, err := f.store.RecordStatements(ctx, who, f.productID, from, unplaced); err != nil {
			t.Fatal(err)
		}
		var before []int64
		if err := f.db.DB.NewSelect().TableExpr(`"vex_statement"`).Column("id").Order("id").
			Scan(ctx, &before); err != nil {
			t.Fatal(err)
		}
		recorded, superseded, err := f.store.RecordStatements(ctx, who, f.productID, from, placed)
		if err != nil {
			t.Fatal(err)
		}
		if superseded != 0 || recorded != len(placed) {
			t.Errorf("reading it again recorded %d and set aside %d", recorded, superseded)
		}
		var rows []finding.Statement
		if err := f.db.DB.NewSelect().Model(&rows).Order("id").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(before) {
			t.Fatalf("%d statements, were %d", len(rows), len(before))
		}
		for i, row := range rows {
			if row.ID != before[i] || row.Superseded != nil {
				t.Errorf("statement %d is %d, superseded %v; want the same row standing", i, row.ID, row.Superseded)
			}
		}
		if rows[0].Placement == "" && rows[1].Placement == "" && rows[2].Placement == "" {
			t.Error("nothing was placed")
		}
	})
}

func TestAForkOfTheProductIsNotTheProduct(t *testing.T) {
	// Built from Acme's source and patched here, it carries Acme's name as
	// what it was built from. Acme spoke for its own build.
	each(t, func(t *testing.T, f *fixture) {
		fork := graph.Described{Purl: "pkg:generic/nh-acme-y@4.2-nh1", Name: "nh-acme-y",
			Version: "4.2-nh1", UpstreamName: "acme-y", UpstreamVersion: "4.2"}
		f.shipped(t, beside(fork))
		f.acmeSays(t)
		if applied, _ := f.reported(t, found(inside, zlib)); applied.Disclaimed != 0 {
			t.Errorf("a fork of Y disclaimed %d", applied.Disclaimed)
		}
	})
}

func TestAStatementAboutOneReleaseOfTheProductIsEvidenceOnAnother(t *testing.T) {
	// It closes nothing at 4.3, and it is still what Acme said.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, beside(acmeYNew))
		f.acmeSays(t)
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: inside, Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		var componentID int64
		if err := f.db.DB.NewSelect().TableExpr(`"component" AS "c"`).Column("c.id").
			Where("c.purl = ?", zlib.Purl).Scan(ctx, &componentID); err != nil {
			t.Fatal(err)
		}
		said, err := f.store.SaidAbout(ctx, f.planner(t, access.PublicTriage), f.productID,
			interned[inside], []string{inside}, "zlib", zlib.Purl, f.target, componentID)
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 1 {
			t.Errorf("Acme's statement about Y 4.2 is evidence %d times on the zlib inside Y 4.3", len(said))
		}
	})
}

func TestAFindingOnTheProductStaysOpenInACycle(t *testing.T) {
	// Two packages depending on each other is ordinary, and puts the product
	// beneath itself.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{acmeY, libpng},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: acmeY},
				{Parent: acmeY, Child: libpng},
				{Parent: libpng, Child: acmeY},
			},
		})
		f.acmeSays(t)
		applied, _ := f.reported(t, found(productOnly, acmeY))
		if applied.Disclaimed != 0 {
			t.Errorf("a finding on Y itself disclaimed %d", applied.Disclaimed)
		}
	})
}

func TestAVersionMovingToOneTheSupplierSpeaksForClosesAsDisclaimed(t *testing.T) {
	// The row before closes for the supplier's word, not as an upgrade: no fix
	// was made.
	each(t, func(t *testing.T, f *fixture) {
		zlibNew := graph.Described{Purl: "pkg:generic/zlib@1.2.12", Name: "zlib", Version: "1.2.12"}
		f.shipped(t, deep())
		f.reported(t, found(inside, zlib))
		f.publishes(t, []finding.Statement{{
			Vulnerability: inside, Purl: zlibNew.Purl, Component: "zlib", About: "1.2.12",
			WithinPurl: acmeY.Purl, Within: "acme-y", WithinAbout: "4.2", Placement: finding.PlacedInside,
			Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
		}}, "sha256:newer-zlib")
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{acmeY, libpng, zlibNew},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: acmeY},
				{Parent: acmeY, Child: libpng},
				{Parent: libpng, Child: zlibNew},
			},
		})
		f.reported(t, found(inside, zlibNew))
		for _, row := range f.every(t) {
			if row.ClosedBecause == finding.Upgraded {
				t.Error("the row before closed as upgraded; nothing was fixed")
			}
		}
		closed := 0
		for _, row := range f.every(t) {
			if row.ClosedBecause == finding.Disclaimed {
				closed++
			}
		}
		if closed != 2 {
			t.Errorf("%d rows closed as disclaimed, want the old version's and the new one's", closed)
		}
	})
}

func TestRescanningADisclaimedBuildTouchesNoRow(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeY))
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))
		before := placedAt(t, f, f.every(t))["zlib under acme-y"]
		f.reported(t, found(inside, zlib))
		after := placedAt(t, f, f.every(t))["zlib under acme-y"]
		if !after.LastChangedAt.Equal(before.LastChangedAt) {
			t.Errorf("a rescan rewrote the closed row: changed %v, was %v",
				after.LastChangedAt, before.LastChangedAt)
		}
	})
}

func TestAPlaceAnsweredOnSomeRoutesCarriesNoDeadline(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, shared())
		f.reported(t, found(inside, zlib))
		if open := f.open(t); len(open) != 1 || open[0].DueAt == nil {
			t.Fatalf("with nothing answering it the place is %+v, want it due", open)
		}
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))
		if open := f.open(t); len(open) != 1 || open[0].DueAt != nil {
			t.Errorf("answered through Y the place is due %v", open[0].DueAt)
		}
	})
}

func TestAnAnswerOnSomeRoutesGoesWithAPlaceThatClosesForAnotherReason(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, shared())
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))
		// The scanner stops reporting it.
		f.reported(t)
		for _, row := range f.every(t) {
			if row.ClosedAt != nil && row.ClosedBecause != finding.Disclaimed && row.StatedBy != nil {
				t.Errorf("closed as %q, still answered by statement %d", row.ClosedBecause, *row.StatedBy)
			}
		}
	})
}

func TestADuplicateOfAnIssueASupplierAnswersEverywhereIsRefused(t *testing.T) {
	// The place is open for the route nobody answered and is not work, so a
	// report pointed at it as a duplicate reaches nobody who is looking.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, shared())
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))
		if open := f.open(t); len(open) != 1 || open[0].StatedBy == nil {
			t.Fatalf("the place is %+v, want it open and answered through Y", open)
		}
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		named := f.claims(t, who, 1)
		_, err := f.store.Rule(ctx, who, f.productID, finding.Ruled{
			References: []string{named[0]}, Disposition: finding.Duplicate,
			DuplicateOf: f.issueID(t, inside),
		})
		if !errors.Is(err, finding.ErrDuplicateOfClosed) {
			t.Errorf("a duplicate of an issue a supplier answers everywhere was answered %v", err)
		}
	})
}

func TestARevisionRepeatingAClaimKeepsItsRow(t *testing.T) {
	// A fetched advisory read again with something new kept beside what it
	// said before differs in digest. What it repeats keeps its row, so no
	// approval citing it is told the publisher changed what they said.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage)
		from := finding.Supplied{Source: finding.FromAdvisory, Identifier: "ACME-SA-1",
			Publisher: "Acme Security", Document: "acme-sa-1.json", Digest: "sha256:first"}
		before := []finding.Statement{{Vulnerability: inside, Component: "zlib", Status: "not_affected"}}
		if _, _, err := f.store.RecordStatements(ctx, who, f.productID, from, before); err != nil {
			t.Fatal(err)
		}
		var first int64
		if err := f.db.DB.NewSelect().TableExpr(`"vex_statement"`).Column("id").Scan(ctx, &first); err != nil {
			t.Fatal(err)
		}
		from.Digest = "sha256:second"
		recorded, superseded, err := f.store.RecordStatements(ctx, who, f.productID, from,
			[]finding.Statement{
				{Vulnerability: inside, Component: "zlib", Status: "not_affected"},
				{Vulnerability: productOnly, Component: "curl", Status: "affected"},
			})
		if err != nil {
			t.Fatal(err)
		}
		if recorded != 2 || superseded != 0 {
			t.Errorf("the revision recorded %d and set aside %d, want 2 and none", recorded, superseded)
		}
		var kept finding.Statement
		if err := f.db.DB.NewSelect().Model(&kept).Where("ss.id = ?", first).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if kept.Superseded != nil || kept.Digest != "sha256:second" {
			t.Errorf("the repeated claim is superseded %v under %q, want standing in the revision",
				kept.Superseded, kept.Digest)
		}
	})
}

func TestNoDeadlineComesBackToAPlaceTheSupplierAnswers(t *testing.T) {
	// Every writer of a deadline leaves the place alone: the issue becoming
	// exploited, the issue rated here, and the windows changing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, shared())
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))
		answered := func(what string) {
			t.Helper()
			if open := f.open(t); len(open) != 1 || open[0].DueAt != nil {
				t.Errorf("after %s the place is due %v", what, open[0].DueAt)
			}
		}
		answered("the scan")

		issue := f.issueID(t, inside)
		if _, err := f.db.DB.NewUpdate().Table("vulnerability").Set("exploited = ?", true).
			Where("id = ?", issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := finding.Reranked(ctx, f.db.DB, []int64{issue}, time.Now().UTC(), 0); err != nil {
			t.Fatal(err)
		}
		answered("the issue became exploited")

		if _, err := f.store.Assess(ctx, f.planner(t, access.PublicTriage), f.productID, issue,
			"critical", "Reachable from the network in how we ship it."); err != nil {
			t.Fatal(err)
		}
		answered("the issue was rated here")

		if _, err := f.store.Recompute(ctx, finding.DefaultWindows()); err != nil {
			t.Fatal(err)
		}
		answered("the windows were recomputed")
	})
}

func TestEveryOtherClosureTakesTheSuppliersAnswerOffThePlace(t *testing.T) {
	// What closed it is the reason a register reads beside it.
	for _, c := range []struct {
		name  string
		close func(t *testing.T, f *fixture)
	}{
		{"the scanner stops reporting it", func(t *testing.T, f *fixture) { f.reported(t) }},
		{"the record excludes the version", func(t *testing.T, f *fixture) {
			r := found(inside, zlib)
			r.Unaffected = recordSays
			f.reported(t, r)
		}},
		{"the build patches it", func(t *testing.T, f *fixture) {
			if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, []sbom.Suppression{{
				Vulnerability: inside, Status: sbom.AlreadyFixed, Origin: sbom.FromStatement,
				Targets: []sbom.Target{{Purl: zlib.Purl}},
			}}, everyOrigin); err != nil {
				t.Fatal(err)
			}
			f.reported(t, found(inside, zlib))
		}},
		{"its issue merges into one already open there", func(t *testing.T, f *fixture) {
			f.reported(t, found(inside, zlib, "GHSA-aaaa-bbbb-cccc"))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.shipped(t, shared())
				f.acmeSays(t)
				if c.name == "its issue merges into one already open there" {
					// The other name first, so the place it holds is the
					// one kept, and the one the supplier answers closes.
					f.reported(t, found("GHSA-aaaa-bbbb-cccc", zlib))
					f.reported(t, found("GHSA-aaaa-bbbb-cccc", zlib), found(inside, zlib))
				} else {
					f.reported(t, found(inside, zlib))
				}
				if open := f.open(t); !anyAnswered(open) {
					t.Fatalf("nothing open is answered through Y: %+v", open)
				}
				c.close(t, f)
				closed := 0
				for _, row := range f.every(t) {
					if row.ClosedAt == nil || row.ClosedBecause == finding.Disclaimed {
						continue
					}
					closed++
					if row.StatedBy != nil {
						t.Errorf("closed as %q, still answered by statement %d", row.ClosedBecause, *row.StatedBy)
					}
				}
				if closed == 0 {
					t.Fatal("nothing closed, so this checked nothing")
				}
			})
		})
	}
}

// anyAnswered reports whether a supplier answers any of these rows.
func anyAnswered(rows []finding.Finding) bool {
	for _, row := range rows {
		if row.StatedBy != nil {
			return true
		}
	}
	return false
}

func TestAClaimMovedToAnotherReleaseOfTheProductIsSetAside(t *testing.T) {
	// What an approval was granted on stays readable as it was: a statement
	// about Y 4.2 is not rewritten into one about Y 4.3.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.planner(t, access.PublicTriage)
		at := func(version string) finding.Statement {
			return finding.Statement{Vulnerability: inside, Purl: zlib.Purl, Component: "zlib",
				About: "1.2.11", WithinPurl: "pkg:generic/acme-y@" + version, Within: "acme-y",
				WithinAbout: version, Placement: finding.PlacedInside, Status: "not_affected"}
		}
		from := finding.Supplied{Source: finding.FromVex, Publisher: "Acme Security",
			Document: "acme-y.openvex.json", Digest: "sha256:one"}
		if _, _, err := f.store.RecordStatements(ctx, who, f.productID, from,
			[]finding.Statement{at("4.9")}); err != nil {
			t.Fatal(err)
		}
		var first int64
		if err := f.db.DB.NewSelect().TableExpr(`"vex_statement"`).Column("id").Scan(ctx, &first); err != nil {
			t.Fatal(err)
		}

		// A plain addition: 4.10 sorts before 4.9, and 4.9 keeps its row.
		from.Digest = "sha256:two"
		if _, superseded, err := f.store.RecordStatements(ctx, who, f.productID, from,
			[]finding.Statement{at("4.9"), at("4.10")}); err != nil || superseded != 0 {
			t.Fatalf("adding 4.10 set aside %d: %v", superseded, err)
		}
		var kept finding.Statement
		if err := f.db.DB.NewSelect().Model(&kept).Where("ss.id = ?", first).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if kept.Superseded != nil || kept.WithinAbout != "4.9" {
			t.Errorf("the 4.9 row is superseded %v and now about %q", kept.Superseded, kept.WithinAbout)
		}

		// A move: 4.9 is no longer said, 4.11 is.
		from.Digest = "sha256:three"
		if _, superseded, err := f.store.RecordStatements(ctx, who, f.productID, from,
			[]finding.Statement{at("4.10"), at("4.11")}); err != nil || superseded != 1 {
			t.Fatalf("moving 4.9 to 4.11 set aside %d: %v", superseded, err)
		}
		if err := f.db.DB.NewSelect().Model(&kept).Where("ss.id = ?", first).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if kept.Superseded == nil || kept.WithinAbout != "4.9" {
			t.Errorf("the 4.9 row is superseded %v and about %q, want it set aside as it was",
				kept.Superseded, kept.WithinAbout)
		}
	})
}
