package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// One product's own page, and what one run of the scanner did.
//
// Both were questions the API could answer in pieces and no screen asked: "how
// is this product doing" was five requests and a spreadsheet, and a receipt
// saying "7,604 opened" is a number with no shape.
func TestAProductSaysHowItIsDoing(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		// One of the two undisclosed, so the same page answers differently for
		// two people — a count is a disclosure with the details removed.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		type build struct {
			Stream     string `json:"stream"`
			Variant    string `json:"variant"`
			Open       int    `json:"open"`
			Undecided  int    `json:"undecided"`
			Agreed     int    `json:"agreed"`
			LastScanAt string `json:"last_scan_at"`
		}
		read := func(t *testing.T, who string) struct {
			Name      string  `json:"name"`
			Builds    []build `json:"builds"`
			Open      int     `json:"open"`
			Undecided int     `json:"undecided"`
			Waiting   int     `json:"waiting"`
		} {
			t.Helper()
			var out struct {
				Name      string  `json:"name"`
				Builds    []build `json:"builds"`
				Open      int     `json:"open"`
				Undecided int     `json:"undecided"`
				Waiting   int     `json:"waiting"`
			}
			got := asPerson(t, r, who, http.MethodGet, "/v1/products/mine/overview", "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s asked how the product is doing and got %d: %s",
					who, got.Code, got.Body.String())
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			return out
		}

		// Both findings sit on one component of one build, and they are two
		// things to decide about rather than two places.
		open := read(t, "private-triage")
		if open.Name != "mine" || open.Open != 2 || open.Undecided != 2 {
			t.Fatalf("the product reads %+v, wanted two open and two undecided", open)
		}
		if len(open.Builds) == 0 {
			t.Fatal("the product's page names no builds")
		}
		var scanned *build
		for i := range open.Builds {
			if open.Builds[i].Open > 0 {
				scanned = &open.Builds[i]
			}
		}
		if scanned == nil || scanned.Open != 2 || scanned.LastScanAt == "" {
			t.Fatalf("the scanned build reads %+v", scanned)
		}
		if scanned.Stream == "" || scanned.Variant == "" {
			t.Errorf("a build came back unnamed: %+v", scanned)
		}

		// A count is a disclosure with the details removed, so somebody who
		// may not read the undisclosed one is told a smaller number.
		public := read(t, "triager")
		if public.Open != 1 || public.Undecided != 1 {
			t.Errorf("somebody who may read one of the two was told %+v", public)
		}

		// What is waiting for a second person here, counted through the same
		// population the review queue lists — and not their own claim, which
		// nobody can approve.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if got := read(t, "reviewer"); got.Waiting != 1 {
			t.Errorf("with a claim waiting, an approver is told %d", got.Waiting)
		}
		if got := read(t, "triager"); got.Waiting != 0 {
			t.Errorf("the proposer is told %d claims wait on them", got.Waiting)
		}
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
		after := read(t, "reviewer")
		if after.Waiting != 0 {
			t.Errorf("after agreeing, %d still waits", after.Waiting)
		}
		// And the agreed one is answered at every place, by the findings
		// list's own definition.
		agreed := 0
		for _, b := range after.Builds {
			agreed += b.Agreed
		}
		if agreed != 1 {
			t.Errorf("after agreeing, %d of the product's work reads as answered", agreed)
		}

		// A product somebody holds nothing on does not exist to them.
		// The approver holds the capability alone, which reaches no
		// product — that is the role held anywhere's rule, and this
		// page is not a way around it.
		if got := asPerson(t, r, "approver", http.MethodGet,
			"/v1/products/mine/overview", ""); got.Code != http.StatusNotFound {
			t.Errorf("somebody holding a capability alone read the product's page with %d",
				got.Code)
		}
	})
}

// What one run of the scanner did.
func TestARunSaysWhatItOpenedAndClosed(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		var runID int64
		if err := r.db.DB.NewSelect().TableExpr("\"scan_run\" AS \"sr\"").
			ColumnExpr("MAX(sr.id)").Scan(t.Context(), &runID); err != nil {
			t.Fatal(err)
		}
		at := fmt.Sprintf(
			"/v1/products/mine/streams/master/variants/broadcom/runs/%d", runID)

		read := func(t *testing.T, who string) struct {
			Scanner         string `json:"scanner"`
			DatabaseVersion string `json:"database_version"`
			Opened          struct {
				Total int `json:"total"`
				High  int `json:"high"`
				Low   int `json:"low"`
			} `json:"opened"`
			Closed struct {
				Total int `json:"total"`
			} `json:"closed"`
			OpenedExploited int `json:"opened_exploited"`
		} {
			t.Helper()
			var out struct {
				Scanner         string `json:"scanner"`
				DatabaseVersion string `json:"database_version"`
				Opened          struct {
					Total int `json:"total"`
					High  int `json:"high"`
					Low   int `json:"low"`
				} `json:"opened"`
				Closed struct {
					Total int `json:"total"`
				} `json:"closed"`
				OpenedExploited int `json:"opened_exploited"`
			}
			got := asPerson(t, r, who, http.MethodGet, at, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s asked what the run did and got %d: %s",
					who, got.Code, got.Body.String())
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			return out
		}

		// The run's own versions, and what it opened with a shape rather than
		// as one number: one high that is known-exploited, one low.
		all := read(t, "private-triage")
		if all.Scanner != "grype" || all.DatabaseVersion != "2026-08-28" {
			t.Errorf("the run reads %+v, wanted what it was measured with", all)
		}
		if all.Opened.Total != 2 || all.Opened.High != 1 || all.Opened.Low != 1 {
			t.Errorf("the run opened %+v, wanted one high and one low", all.Opened)
		}
		if all.OpenedExploited != 1 {
			t.Errorf("%d of what it opened reads as exploited, wanted one",
				all.OpenedExploited)
		}
		if all.Closed.Total != 0 {
			t.Errorf("the first run closed %d", all.Closed.Total)
		}

		// A count carries the reader's visibility, so somebody who may not
		// read the low one is told the run opened one thing.
		public := read(t, "triager")
		if public.Opened.Total != 1 || public.Opened.Low != 0 || public.Opened.High != 1 {
			t.Errorf("somebody who may read one of the two was told %+v", public.Opened)
		}

		// A run identifier from elsewhere is not this build's, so the path
		// cannot be doing the authorizing while the identifier does the
		// reading.
		var elsewhere int64
		if err := r.db.DB.NewSelect().TableExpr("\"target\" AS \"tg\"").ColumnExpr("tg.id").
			Where("tg.id <> (SELECT sr.target_id FROM \"scan_run\" AS \"sr\" WHERE sr.id = ?)", runID).
			Limit(1).Scan(t.Context(), &elsewhere); err != nil {
			t.Fatal(err)
		}
		other := map[string]any{
			"target_id": elsewhere, "scanner": "grype", "ran_here": true,
			"started_at": time.Now().UTC(), "finished_at": time.Now().UTC(),
		}
		if _, err := r.db.DB.NewInsert().Model(&other).TableExpr("\"scan_run\"").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		var theirs int64
		if err := r.db.DB.NewSelect().TableExpr("\"scan_run\" AS \"sr\"").ColumnExpr("MAX(sr.id)").
			Where("sr.target_id = ?", elsewhere).Scan(t.Context(), &theirs); err != nil {
			t.Fatal(err)
		}
		missing := fmt.Sprintf(
			"/v1/products/mine/streams/master/variants/broadcom/runs/%d", theirs)
		if got := asPerson(t, r, "private-triage", http.MethodGet, missing, ""); got.Code !=
			http.StatusNotFound {
			t.Errorf("another build's run read through this one answered %d", got.Code)
		}
	})
}

// The overview counts what somebody decides about, not places.
//
// A library at two places with two issues is four findings and two pieces of
// work. Counting rows would make a build look twice as bad as the list
// somebody opens next — the mistake that reported 441,108 open where 5,661
// issues were.
func TestAProductCountsThingsToDecideRatherThanPlaces(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedShared(t)
		// The same two issues on the same component in a second build. The
		// findings list answers for a whole product as one row per issue and
		// component across every build it holds, so this is still two things
		// to decide about — and summing the build rows would say four.
		r.alsoIn(t, "mellanox")
		got := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/products/mine/overview", "")
		if got.Code != http.StatusOK {
			t.Fatalf("the overview answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Open   int `json:"open"`
			Builds []struct {
				Open int `json:"open"`
			} `json:"builds"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Open != 2 {
			t.Errorf("the product reads %d open, wanted the two things to decide about "+
				"rather than a sum over its builds", out.Open)
		}
		if len(out.Builds) != 2 {
			t.Fatalf("the product names %d builds, wanted both", len(out.Builds))
		}
		summed := 0
		for _, b := range out.Builds {
			summed += b.Open
			if b.Open != 2 {
				t.Errorf("a build reads %d open, wanted its own two", b.Open)
			}
		}
		if summed == out.Open {
			t.Error("the product's total is the sum of its builds, which the list it links " +
				"to does not agree with")
		}
		// And the findings list agrees, because it is the same unit.
		list := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/products/mine/findings?limit=1", "")
		var page struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.Total != out.Open {
			t.Errorf("the overview says %d open and the list it opens says %d",
				out.Open, page.Total)
		}
	})
}

// alsoIn ships the same graph and the same findings in a second variant of the
// same product, so a product's own totals can be told from a sum over its
// builds.
func (r *reach) alsoIn(t *testing.T, variant string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.db.DB)
	product, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.DeclareVariant(ctx, product.ID, variant, true); err != nil {
		t.Fatal(err)
	}
	located, err := names.Locate(ctx, "mine", "master", variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "shared-" + variant,
		BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	root := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	lib := graph.Described{Purl: "pkg:deb/debian/libyang@2.1", Name: "libyang", Version: "2.1"}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:         root,
		Components:   []graph.Described{lib},
		Dependencies: []graph.Dependency{{Parent: root, Child: lib}},
	}); err != nil {
		t.Fatal(err)
	}
	findings := finding.NewStore(r.db.DB)
	run, err := findings.Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", ScannerVersion: "0.112.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{Issue: finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: lib, FixState: finding.NoFix},
		{Issue: finding.Named{Identifier: "CVE-2026-2", Severity: "low"},
			Component: lib, FixState: finding.NoFix},
	}); err != nil {
		t.Fatal(err)
	}
}
