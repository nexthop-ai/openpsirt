// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// LeadCommit is the commit the seeded lead's checkout was analyzed at.
const LeadCommit = "0123456789abcdef0123456789abcdef01234567"

// LeadRun is one run of an analyzer over the seeded build's checkout, which
// is one repository on GitHub, reporting a leak in it or nothing. Its rule
// list holds a rule that never fires, so the list is the rule set.
func LeadRun(found bool) string {
	if !found {
		return LeadRunAt(0)
	}
	return LeadRunAt(12)
}

// LeadRunAt is LeadRun reporting the leak at a line, or nothing at line 0. The
// result carries no fingerprint, so moving it pairs it on its nearest line.
func LeadRunAt(line int) string {
	results := ""
	if line > 0 {
		results = `{"ruleId":"leak","message":{"text":"p is leaked"},` +
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.c","uriBaseId":"SRCROOT"},` +
			`"region":{"startLine":` + strconv.Itoa(line) + `,"snippet":{"text":"return;"}}}}],` +
			`"codeFlows":[{"threadFlows":[{"locations":[` +
			`{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/b.c","uriBaseId":"SRCROOT"},"region":{"startLine":3}},"message":{"text":"allocated"}}}]}]}]}`
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clang-tidy","rules":[{"id":"leak"},{"id":"overflow"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///build/"}},` +
		`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/mine","revisionId":"` + LeadCommit + `","mappedTo":{"uriBaseId":"SRCROOT"}}],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[` + results + `]}]}`
}

// ApplyRun receives and applies one run of the seeded lead's series against
// the seeded build, built at the time given.
func ApplyRun(t *testing.T, r *Reach, built time.Time, doc string) {
	t.Helper()
	ApplyRunIn(t, r, "clang-tidy/default", built, doc)
}

// OtherToolRun is one run of another analyzer, tool, over the seeded build's
// checkout, reporting rule at each line of file given, the rule tagged with
// the weakness CWE-tag. Its rule list holds a rule that never fires, so the
// list is the rule set.
func OtherToolRun(tool, rule, tag, file string, lines ...int) string {
	results := make([]string, 0, len(lines))
	for _, line := range lines {
		results = append(results, `{"ruleId":"`+rule+`","message":{"text":"`+rule+` here"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"`+file+`","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":`+strconv.Itoa(line)+`}}}]}`)
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tool + `","rules":[` +
		`{"id":"` + rule + `","properties":{"tags":["external/cwe/cwe-` + tag + `"]}},{"id":"unfired"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///build/"}},` +
		`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/mine","revisionId":"` + LeadCommit + `","mappedTo":{"uriBaseId":"SRCROOT"}}],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[` + strings.Join(results, ",") + `]}]}`
}

// ApplyRunIn receives and applies one run of a series against the seeded
// build, built at the time given. A series is one tool, so a second tool's
// run is applied in a series of its own.
func ApplyRunIn(t *testing.T, r *Reach, seriesName string, built time.Time, doc string) {
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
	given := analysis.Describe([]sarif.Log{log}, analysis.Stated{Series: seriesName, BuiltAt: built})
	target := r.TargetOf(t, SeededBuild)
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

// SeededLead is a lead on the seeded build, with the product linking GitHub
// and keeping its source, and the place it is addressed by.
func SeededLead(t *testing.T, r *Reach) string {
	t.Helper()
	ctx := t.Context()
	r.Inventoried(t, "broadcom", "inventory-lead", map[string]string{"zlib": "1.3"})
	// Marked made, as reading the inventory does, so a run has a build to
	// place its results in.
	scans := ingest.NewStore(r.DB.DB)
	scan, err := scans.Newest(ctx, r.TargetOf(t, SeededBuild))
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
	ApplyRun(t, r, time.Now().UTC().Add(-2*time.Hour), LeadRun(true))
	var place string
	if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."place_identity"`).
		Where(`"f"."kind" = ?`, kind.Analysis).Scan(ctx, &place); err != nil {
		t.Fatal(err)
	}
	return place
}

// HandedOffLead is the seeded lead confirmed and handed off as a flaw against
// the seeded build, kept or moved into its case, with its place and the flaw's
// identifier.
func HandedOffLead(t *testing.T, r *Reach, move bool) (string, string) {
	t.Helper()
	place := SeededLead(t, r)
	at := "/v1/products/mine/streams/master/variants/broadcom/leads/" + place
	if w := AsPerson(t, r, "internal-triager", "POST", at+"/decision",
		`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); w.Code != 201 {
		t.Fatalf("the lead was not confirmed: %d %s", w.Code, w.Body.String())
	}
	w := AsPerson(t, r, "lead-handler", "POST", at+"/hand-off",
		`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks on the early return","move":`+
			strconv.FormatBool(move)+`}`)
	if w.Code != 201 {
		t.Fatalf("the lead was not handed off: %d %s", w.Code, w.Body.String())
	}
	var done struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &done); err != nil {
		t.Fatal(err)
	}
	return place, done.Identifier
}
