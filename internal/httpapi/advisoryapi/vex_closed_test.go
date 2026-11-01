// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// kernelPatch is the build's claim that a patch it carries fixes the issue in
// the kernel.
func kernelPatch(issue string) sbom.Suppression {
	return sbom.Suppression{
		Vulnerability: issue, Status: sbom.AlreadyFixed,
		Statement: "resolved by a patch the build carries",
		Targets:   []sbom.Target{{Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image"}},
		Origin:    sbom.FromPedigree,
	}
}

// kernelIn ships the kernel in another variant of the product, carrying the
// issues given, with the claims given.
func kernelIn(t *testing.T, r *httpapitest.Reach, variant string, claims []sbom.Suppression, issues ...string) {
	t.Helper()
	ctx := t.Context()
	product, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.NewStore(r.DB.DB).DeclareVariant(ctx, product.ID, variant, true); err != nil {
		t.Fatal(err)
	}
	kernelAt(t, r, httpapitest.Build{Product: "mine", BranchOrTag: "master", Variant: variant},
		"kernel-"+variant, claims, issues...)
}

// kernelAt ships the kernel in the build given, carrying the issues given,
// with the claims given.
func kernelAt(t *testing.T, r *httpapitest.Reach, b httpapitest.Build, hash string,
	claims []sbom.Suppression, issues ...string) {

	t.Helper()
	kernel := graph.Described{Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image", Version: "5.10"}
	build, scan := r.Shipped(t, b, hash, graph.Snapshot{
		Root:         httpapitest.SeededRoot,
		Components:   []graph.Described{kernel},
		Dependencies: []graph.Dependency{{Parent: httpapitest.SeededRoot, Child: kernel}},
	})
	r.Argued(t, build, scan, claims)
	reported := make([]finding.Reported, 0, len(issues))
	for _, issue := range issues {
		reported = append(reported, finding.Reported{
			Issue:     finding.Named{Identifier: issue, Severity: "high"},
			Component: kernel, FixState: finding.FixedUpstream, FixedIn: "5.10.0-27",
		})
	}
	r.Ran(t, build, reported)
}

// A patch is stated from the build's own findings: another build of the
// product patching the issue says nothing about this one.
func TestAPatchAnotherBuildCarriesIsNoStatementAboutThisOne(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		kernelAt(t, r, httpapitest.SeededBuild, "unpatched", nil, "CVE-2026-1000")
		kernelIn(t, r, "mellanox", []sbom.Suppression{kernelPatch("CVE-2026-9999")}, "CVE-2026-9999")
		if fixed := r.FixedIn(t); len(fixed) != 0 {
			t.Errorf("a patch another build carries is said here as %v fixed", fixed)
		}
	})
}

// An occurrence open in another build of the product does not stand in the way
// of what this build's patch fixes.
func TestAnIssueOpenInAnotherBuildLeavesThisBuildsPatchStated(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.PatchedKernel(t)
		kernelIn(t, r, "mellanox", nil, "CVE-2026-9999")
		fixed := r.FixedIn(t)
		if len(fixed["CVE-2026-9999"]) != 1 {
			t.Errorf("an issue open in another build hides this build's patch: %v fixed", fixed)
		}
	})
}

// A component this build no longer ships is stated as nothing, however many
// other builds of the product still ship it.
func TestAComponentAnotherBuildShipsIsNoStatementAboutThisOne(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.PatchedKernel(t)
		kernelIn(t, r, "mellanox", nil)
		r.PatchedRows(t, `UPDATE "graph_node" SET "closed_scan_id" = "opened_scan_id"
			WHERE "build_id" = (SELECT "build_id" FROM "finding" WHERE "closed_because" = 'patched')
			AND "component_id" IN (SELECT "id" FROM "component" WHERE "name" = 'linux-image')`)
		if fixed := r.FixedIn(t); len(fixed) != 0 {
			t.Errorf("a component only another build ships is said as %v fixed", fixed)
		}
	})
}

// A patched image is named by its open version's stamp, never by a version a
// later scan closed.
func TestAPatchedImageIsNamedByItsOpenVersionsStamp(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.PatchedKernel(t)
		const stamp = "pkg:oci/linux-image@master.7-abc?arch=amd64"
		for _, version := range []struct{ name, purl, closed string }{
			{"open", stamp, "NULL"},
			{"closed", "pkg:oci/aaa-closed", `"opened_scan_id"`},
		} {
			r.PatchedRows(t, `INSERT INTO "image_version" ("node_id", "version", "purl", "opened_scan_id", "closed_scan_id")
				SELECT "id", '`+version.name+`', '`+version.purl+`', "opened_scan_id", `+version.closed+`
				FROM "graph_node" WHERE "closed_scan_id" IS NULL
				AND "component_id" IN (SELECT "id" FROM "component" WHERE "name" = 'linux-image')`)
		}
		fixed := r.FixedIn(t)
		if len(fixed["CVE-2026-9999"]) != 1 || fixed["CVE-2026-9999"][0] != stamp {
			t.Errorf("a patched image is named %v, want its open version's %s", fixed["CVE-2026-9999"], stamp)
		}
	})
}

// A statement about patched components sharing a name and package identifier
// is dated by the lowest of their findings, the same row on every engine.
func TestAPatchIsDatedByTheFirstFindingItClosed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.PatchedKernel(t)
		const hash = "5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
		r.PatchedRows(t, `INSERT INTO "component" ("identity", "purl", "name", "version",
				"fold_key", "first_seen_at")
			SELECT '`+hash+`', "purl", "name", '5.10-2', '`+hash+`', "first_seen_at"
			FROM "component" WHERE "name" = 'linux-image'`)
		r.PatchedRows(t, `INSERT INTO "graph_node" ("build_id", "component_id", "opened_scan_id", "purl", "is_root")
			SELECT "build_id", (SELECT "id" FROM "component" WHERE "identity" = '`+hash+`'),
				"opened_scan_id", "purl", "is_root"
			FROM "graph_node" WHERE "closed_scan_id" IS NULL
			AND "component_id" IN (SELECT "id" FROM "component" WHERE "name" = 'linux-image' AND "identity" <> '`+hash+`')`)
		var first finding.Finding
		if err := r.DB.DB.NewSelect().Model(&first).Where(`"f"."closed_because" = 'patched'`).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		later := first.ClosedAt.Add(24 * time.Hour)
		if _, err := r.DB.ExecContext(t.Context(), `INSERT INTO "finding" ("build_id", "kind", "vulnerability_id",
				"visibility", "component_id", "occurrence_identity", "urgency",
				"urgency_exploited", "urgency_incident", "urgency_shipped",
				"opened_at", "closed_at", "closed_because", "suppressed_by")
			SELECT "build_id", "kind", "vulnerability_id", "visibility",
				(SELECT "id" FROM "component" WHERE "identity" = '`+hash+`'),
				"occurrence_identity", "urgency", "urgency_exploited", "urgency_incident",
				"urgency_shipped", "opened_at", ?, "closed_because", "suppressed_by"
			FROM "finding" WHERE "closed_because" = 'patched'`, later); err != nil {
			t.Fatal(err)
		}

		var doc struct {
			Statements []struct {
				Vulnerability struct {
					Name string `json:"name"`
				} `json:"vulnerability"`
				Timestamp time.Time `json:"timestamp"`
			} `json:"statements"`
		}
		httpapitest.Read(t, r, "triager", httpapitest.ABuild, &doc)
		stated := 0
		for _, one := range doc.Statements {
			if one.Vulnerability.Name != "CVE-2026-9999" {
				continue
			}
			stated++
			if !one.Timestamp.Equal(*first.ClosedAt) {
				t.Errorf("the patch is dated %s, want %s, when the first finding it closed was", one.Timestamp, first.ClosedAt)
			}
		}
		if stated != 1 {
			t.Errorf("%d statements about the patched issue, want one about both components", stated)
		}
	})
}

// Patches stated past the ceiling refuse the document, the same as dismissals
// do. Three patches against a ceiling of one, so a read cut short at the
// ceiling is told from one cut one past it.
func TestABuildPatchedPastTheCeilingIsAnsweredAsTooLarge(t *testing.T) {
	carryingOne := func(d *core.Deps) { d.VexCeiling = 1 }
	httpapitest.ReachAdjusted(t, httpapitest.CastSeed.Two, carryingOne, func(t *testing.T, r *httpapitest.Reach) {
		issues := []string{"CVE-2026-9999", "CVE-2026-1000", "CVE-2026-1001"}
		claims := make([]sbom.Suppression, 0, len(issues))
		for _, issue := range issues {
			claims = append(claims, kernelPatch(issue))
		}
		kernelAt(t, r, httpapitest.SeededBuild, "patched-thrice", claims, issues...)
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, httpapitest.ABuild, "")
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a build with three patches past a ceiling of one answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// A document of disclosed work states no patch of undisclosed work.
func TestAPatchedUndisclosedFindingIsNoStatementOfDisclosedWork(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.PatchedKernel(t)
		r.PatchedRows(t, `UPDATE "finding" SET "visibility" = 'private' WHERE "closed_because" = 'patched'`)
		if fixed := r.FixedIn(t); len(fixed) != 0 {
			t.Errorf("a patch of undisclosed work is said as %v fixed", fixed)
		}
	})
}

// A patch closing a code finding is no VEX statement: the document states the
// kinds a customer's scanner matches.
func TestAPatchedCodeFindingIsNoStatement(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.PatchedKernel(t)
		r.PatchedRows(t, `UPDATE "finding" SET "kind" = 'analysis' WHERE "closed_because" = 'patched'`)
		if fixed := r.FixedIn(t); len(fixed) != 0 {
			t.Errorf("a patched code finding is said as %v fixed", fixed)
		}
	})
}

// An open code finding of the issue at the component leaves its patch stated:
// it is no occurrence a VEX document speaks for.
func TestAnOpenCodeFindingLeavesAPatchStated(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.PatchedKernel(t)
		r.PatchedRows(t, `INSERT INTO "finding" ("build_id", "kind", "vulnerability_id",
				"visibility", "component_id", "occurrence_identity", "urgency",
				"urgency_exploited", "urgency_incident", "urgency_shipped",
				"opened_at")
			SELECT "build_id", 'analysis', "vulnerability_id", "visibility", "component_id",
				"occurrence_identity", "urgency", "urgency_exploited", "urgency_incident",
				"urgency_shipped", "opened_at"
			FROM "finding" WHERE "closed_because" = 'patched'`)
		if fixed := r.FixedIn(t); len(fixed["CVE-2026-9999"]) != 1 {
			t.Errorf("an open code finding hides the patch: %v fixed", fixed)
		}
	})
}

// openUndisclosedBeside opens an undisclosed finding of each issue closed for
// the reason given, at a second component of the same name and package
// identifier.
func openUndisclosedBeside(t *testing.T, r *httpapitest.Reach, because finding.Closure, name string) {
	t.Helper()
	const hash = "5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
	r.PatchedRows(t, `INSERT INTO "component" ("identity", "purl", "name", "version",
			"fold_key", "first_seen_at")
		SELECT '`+hash+`', "purl", "name", "version", '`+hash+`', "first_seen_at"
		FROM "component" WHERE "name" = '`+name+`'`)
	r.PatchedRows(t, `INSERT INTO "finding" ("build_id", "kind", "vulnerability_id",
			"visibility", "component_id", "occurrence_identity", "urgency",
			"urgency_exploited", "urgency_incident", "urgency_shipped",
			"opened_at")
		SELECT "build_id", "kind", "vulnerability_id", 'private',
			(SELECT "id" FROM "component" WHERE "identity" = '`+hash+`'),
			"occurrence_identity", "urgency", "urgency_exploited", "urgency_incident",
			"urgency_shipped", "opened_at"
		FROM "finding" WHERE "closed_because" = '`+string(because)+`'`)
}

// An undisclosed occurrence still open holds back a patch of disclosed work:
// the open check reads every visibility, whatever the document is read at.
func TestAnUndisclosedOpenOccurrenceHoldsBackAPatch(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.PatchedKernel(t)
		if fixed := r.FixedIn(t); len(fixed["CVE-2026-9999"]) != 1 {
			t.Fatalf("the patch is said as %v fixed before anything else is open", fixed)
		}
		openUndisclosedBeside(t, r, finding.Patched, "linux-image")
		if fixed := r.FixedIn(t); len(fixed) != 0 {
			t.Errorf("with an undisclosed occurrence open, the patch is said as %v fixed", fixed)
		}
	})
}

// An undisclosed occurrence still open holds back a supplier's statement of
// disclosed work, the same as it holds back a patch.
func TestAnUndisclosedOpenOccurrenceHoldsBackASuppliersStatement(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if got := r.VexedAs(t, "admin", "acme", "acme-y.openvex.json", httpapitest.AcmeSays(t)); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		r.ScannedInsideAcme(t, "inside", false)
		if _, said := statementsAbout(t, r, "with-suppliers"); len(said) != 1 {
			t.Fatalf("the document with suppliers says %+v, want the statement of not affected", said)
		}
		openUndisclosedBeside(t, r, finding.Disclaimed, "zlib")
		if _, said := statementsAbout(t, r, "with-suppliers"); len(said) != 0 {
			t.Errorf("with an undisclosed occurrence open, the document with suppliers says %+v", said)
		}
	})
}
