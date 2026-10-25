// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/findingsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

const leadCommit = "0123456789abcdef0123456789abcdef01234567"

// leadRun is one run of an analyzer over the seeded build's checkout, which
// is one repository on GitHub, reporting a leak in it or nothing. Its rule
// list holds a rule that never fires, so the list is the rule set.
func leadRun(found bool) string {
	results := ""
	if found {
		results = `{"ruleId":"leak","message":{"text":"p is leaked"},` +
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.c","uriBaseId":"SRCROOT"},` +
			`"region":{"startLine":12,"snippet":{"text":"return;"}}}}],` +
			`"codeFlows":[{"threadFlows":[{"locations":[` +
			`{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/b.c","uriBaseId":"SRCROOT"},"region":{"startLine":3}},"message":{"text":"allocated"}}}]}]}]}`
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clang-tidy","rules":[{"id":"leak"},{"id":"overflow"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///build/"}},` +
		`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/mine","revisionId":"` + leadCommit + `","mappedTo":{"uriBaseId":"SRCROOT"}}],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[` + results + `]}]}`
}

// applyRun receives and applies one run against the seeded build, built at
// the time given.
func applyRun(t *testing.T, r *httpapitest.Reach, built time.Time, doc string) {
	t.Helper()
	ctx := t.Context()
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	located, err := catalog.NewStore(r.DB.DB).Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	given := analysis.Describe([]sarif.Log{log}, analysis.Stated{Series: "clang-tidy/default", BuiltAt: built})
	target := r.TargetOf(t, httpapitest.SeededBuild)
	var runID int64
	if err := database.InTransaction(ctx, r.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		repositories, err := sourcelink.NewStore(tx).Config(ctx, located.ProductID)
		if err != nil {
			return err
		}
		placed, err := analysis.Place([]sarif.Log{log}, "/build", sarif.DefaultLimits().MaxBytes, repositories.Snippets)
		if err != nil {
			return err
		}
		store := series.NewStore(tx)
		run, _, err := store.Receive(ctx, series.Arriving{
			ProductID: located.ProductID, TargetID: target,
			Kind: kind.Analysis, Series: given.Series,
			ContentHash: fmt.Sprintf("run-%d", built.UnixNano()), BuiltAt: given.BuiltAt, Params: given.Params,
		})
		if err != nil {
			return err
		}
		runID = run.ID
		return placed.Hold(ctx, store, run.ID)
	}); err != nil {
		t.Fatal(err)
	}
	if status, err := analysis.NewApplier(r.DB).Apply(ctx, runID); err != nil || status != series.Applied {
		t.Fatalf("the run ended %s: %v", status, err)
	}
}

// seededLead is a lead on the seeded build, with the product linking GitHub
// and keeping its source, and the place it is addressed by.
func seededLead(t *testing.T, r *httpapitest.Reach) string {
	t.Helper()
	ctx := t.Context()
	r.Inventoried(t, "broadcom", "inventory-lead", map[string]string{"zlib": "1.3"})
	// Marked made, as reading the inventory does, so a run has a build to
	// place its results in.
	scans := ingest.NewStore(r.DB.DB)
	scan, err := scans.Newest(ctx, r.TargetOf(t, httpapitest.SeededBuild))
	if err != nil || scan == nil {
		t.Fatalf("the build has no upload: %v", err)
	}
	if err := scans.Made(ctx, scan.ID, 2, 2, "mine"); err != nil {
		t.Fatal(err)
	}
	located, err := catalog.NewStore(r.DB.DB).Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	if err := sourcelink.NewStore(r.DB.DB).Replace(ctx, located.ProductID, sourcelink.Config{
		Hosts: []sourcelink.Host{{Remote: "github.com", Web: "https://github.com", Style: sourcelink.GitHub}},
		Paths: []sourcelink.Path{{Prefix: "", Snippets: &yes}},
	}); err != nil {
		t.Fatal(err)
	}
	applyRun(t, r, time.Now().UTC().Add(-2*time.Hour), leadRun(true))
	var place string
	if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."place_identity"`).
		Where(`"f"."kind" = ?`, kind.Analysis).Scan(ctx, &place); err != nil {
		t.Fatal(err)
	}
	return place
}

const leadsAt = "/v1/products/mine/streams/master/variants/broadcom/leads/"

func TestALeadsEvidenceLinksEachPlaceIntoItsSource(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := seededLead(t, r)
		var got findingsapi.LeadEvidenceBody
		httpapitest.Read(t, r, "internal-reader", leadsAt+place, &got)
		if want := "https://github.com/acme/mine/blob/" + leadCommit + "/src/a.c#L12-L12"; got.At.Link != want {
			t.Errorf("the lead links to %q (%s); want %q", got.At.Link, got.At.Unlinked, want)
		}
		if got.At.Snippet != "return;" || got.At.SnippetLine != 12 || !got.Open || got.NotSeen != "" {
			t.Errorf("evidence %+v; want the open lead with its source", got.At)
		}
		if len(got.Steps) != 1 || got.Steps[0].Message != "allocated" ||
			got.Steps[0].Link != "https://github.com/acme/mine/blob/"+leadCommit+"/src/b.c#L3-L3" {
			t.Errorf("steps %+v; want the allocation, linked", got.Steps)
		}

		applyRun(t, r, time.Now().UTC().Add(-time.Hour), leadRun(false))
		httpapitest.Read(t, r, "internal-reader", leadsAt+place, &got)
		if got.NotSeen == "" || !got.Unchanged || got.Compare != "" {
			t.Errorf("not seen %v, unchanged %v, compare %q; want a disappearance at the same commit said so",
				got.NotSeen, got.Unchanged, got.Compare)
		}
	})
}

func TestALeadIsAnsweredOnlyToSomebodyReadingInternalMaterial(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := seededLead(t, r)
		absent := httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet, leadsAt+"0000", "")
		if absent.Code != http.StatusNotFound {
			t.Fatalf("a place holding no lead answered %d; want 404", absent.Code)
		}
		// Somebody who cannot see the product is refused at its name, as on
		// every route under it.
		for _, who := range []string{"reader", "private", "split-triager"} {
			got := httpapitest.AsPerson(t, r, who, http.MethodGet, leadsAt+place, "")
			if got.Code != http.StatusNotFound || got.Body.String() != absent.Body.String() {
				t.Errorf("%s was answered %d %s; want what a place holding nothing answers", who, got.Code, got.Body.String())
			}
		}
	})
}
