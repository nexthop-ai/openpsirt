// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// Each test here makes one row a finding of a kind the consumer under test does
// not name, by rewriting its kind in place, and reads the consumer before and
// after. The row keeps everything else that would carry it: its visibility,
// its occurrence, its issue and its versions, so only its kind keeps it out. The
// consumers that name the analysis kind, and the four pinned beside the
// vulnerability lists, are in analysis_reach_test.go.

// asKind rewrites the kind and visibility of every finding of one issue.
func asKind(t *testing.T, r *httpapitest.Reach, identifier, kind, visibility string) {
	t.Helper()
	r.PatchedRows(t, `UPDATE "finding" SET "kind" = '`+kind+`', "visibility" = '`+visibility+`'
		WHERE "vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = '`+identifier+`')`)
}

// openRows is how many findings of one issue are open.
func openRows(t *testing.T, r *httpapitest.Reach, identifier string) int {
	t.Helper()
	n, err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		Where(`"v"."identifier" = ?`, identifier).
		Where(`"f"."closed_at" IS NULL`).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

// A scan's sweep closes the vulnerability findings it no longer reports, and
// leaves a lead at the same component open: absence in an inventory scan says
// nothing about an analyzer's result.
func TestAScansSweepClosesNoLead(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		asKind(t, r, "CVE-2026-1000", "analysis", "internal")
		r.Ran(t, r.TargetOf(t, httpapitest.SeededBuild), nil)
		if got := openRows(t, r, "CVE-2026-9999"); got != 0 {
			t.Fatalf("the sweep left %d vulnerability findings open, so this checks nothing", got)
		}
		if got := openRows(t, r, "CVE-2026-1000"); got != 1 {
			t.Errorf("the sweep left %d of the lead open; want it untouched", got)
		}
	})
}

// A decision lapses when the versions it was made about move, and a decision
// standing over leads alone lapses nowhere: a lead is carried by matching, and
// a version moving under it is not a reason to ask again.
func TestAVersionMovingLapsesNoDecisionAboutALead(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		decisions := map[string]int64{}
		for _, issue := range []string{"CVE-2026-CURL1", "CVE-2026-CURL2"} {
			decided := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
				"/v1/products/mine/branches-and-tags/master/variants/broadcom/components/libcurl4t64/bulk-decision",
				`{"vulnerabilities":["`+issue+`"],"outcome":"not-applicable",`+
					`"justification":"vulnerable_code_cannot_be_controlled_by_adversary",`+
					`"selected_by":"the transfer path","reasoning":"Nothing an attacker sends reaches it."}`)
			if decided.Code != http.StatusCreated {
				t.Fatalf("deciding %s answered %d: %s", issue, decided.Code, decided.Body.String())
			}
			var made struct {
				DecisionID int64 `json:"decision_id"`
			}
			if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
				t.Fatal(err)
			}
			r.Agreed(t, made.DecisionID)
			decisions[issue] = made.DecisionID
		}
		asKind(t, r, "CVE-2026-CURL1", "analysis", "public")
		r.CurlMovedTo(t, "8.6.0")
		lapsed := func(decision int64) int {
			n, err := r.DB.DB.NewSelect().Table("decision_occurrence").
				Where(`"decision_id" = ?`, decision).Where(`"state" = ?`, "lapsed").Count(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			return int(n)
		}
		if got := lapsed(decisions["CVE-2026-CURL2"]); got == 0 {
			t.Fatal("the decision over vulnerability findings did not lapse, so this checks nothing")
		}
		if got := lapsed(decisions["CVE-2026-CURL1"]); got != 0 {
			t.Errorf("%d rows of the decision over leads lapsed; want none", got)
		}
	})
}

// The pass rewriting deadlines writes a vulnerability's and takes one away
// where there is no fix to take, and leaves a lead's as it was: a lead carries
// no deadline the policy sets or clears.
func TestTheDeadlinePassRewritesNoLead(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		sentinel := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
		// moved is, for each issue, whether the pass changed the deadline it
		// was given.
		moved := func() map[string]bool {
			t.Helper()
			r.PatchedRows(t, `UPDATE "finding" SET "due_at" = '2001-02-03 04:05:06'`)
			if _, err := finding.NewStore(r.DB.DB).Recompute(t.Context(), finding.DefaultWindows()); err != nil {
				t.Fatal(err)
			}
			var rows []struct {
				Identifier string     `bun:"identifier"`
				Due        *time.Time `bun:"due_at"`
			}
			if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
				Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
				ColumnExpr(`"v"."identifier", "f"."due_at"`).Scan(t.Context(), &rows); err != nil {
				t.Fatal(err)
			}
			out := map[string]bool{}
			for _, row := range rows {
				out[row.Identifier] = row.Due == nil || !row.Due.UTC().Equal(sentinel)
			}
			return out
		}
		// The fixable one is given a deadline, and the one with no fix has its
		// deadline taken away.
		if got := moved(); !got["CVE-2026-9999"] || !got["CVE-2026-1000"] {
			t.Fatalf("the pass moved %v of the vulnerabilities' deadlines, so this checks nothing", got)
		}
		asKind(t, r, "CVE-2026-9999", "analysis", "public")
		asKind(t, r, "CVE-2026-1000", "analysis", "public")
		if got := moved(); got["CVE-2026-9999"] || got["CVE-2026-1000"] {
			t.Errorf("the pass moved the deadlines of leads: %v", got)
		}
	})
}

// The screens about what a build contains count the vulnerability findings at
// a component and no lead there.
func TestTheInventoryScreensCountNoLead(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		counted := func() int {
			t.Helper()
			var top struct {
				Items []struct {
					Component string `json:"component"`
					Findings  int    `json:"findings"`
				} `json:"items"`
			}
			httpapitest.Read(t, r, "reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/components", &top)
			total := 0
			for _, item := range top.Items {
				total += item.Findings
			}
			return total
		}
		if counted() == 0 {
			t.Fatal("the tree counts nothing at the scanned component, so this checks nothing")
		}
		asKind(t, r, "CVE-2026-9999", "analysis", "public")
		if got := counted(); got != 0 {
			t.Errorf("the tree counts %d findings where the one finding is a lead", got)
		}
	})
}

// The figures about findings — the trend and a product's overview — count
// the vulnerability and no lead.
func TestTheFiguresCountNoLead(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		figures := func() (trend, overview int) {
			t.Helper()
			var points struct {
				Items []struct {
					Open int `json:"open"`
				} `json:"items"`
			}
			httpapitest.Read(t, r, "reader", "/v1/trend?weeks=4", &points)
			if len(points.Items) == 0 {
				t.Fatal("the trend has no points")
			}
			var shown struct {
				Open int `json:"open"`
			}
			httpapitest.Read(t, r, "reader", "/v1/products/mine/overview", &shown)
			return points.Items[len(points.Items)-1].Open, shown.Open
		}
		if trend, overview := figures(); trend == 0 || overview == 0 {
			t.Fatalf("the figures count %d and %d open, so this checks nothing", trend, overview)
		}
		asKind(t, r, "CVE-2026-9999", "analysis", "public")
		if trend, overview := figures(); trend != 0 || overview != 0 {
			t.Errorf("the trend counts %d open and the overview %d where the one finding is a lead", trend, overview)
		}
	})
}

// An advisory names every release of a flaw recorded here, and no release
// where the flaw's finding is a lead: a lead nobody judged is not a statement
// about what a release ships.
func TestAnAdvisoryNamesNoReleaseOfALead(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		r.ScannedAlso(t, "mellanox", "3.7.0")
		made := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"},{"stream":"master","variant":"mellanox"}],`+
				`"summary":"The management socket answers before anyone has authenticated.",`+
				`"severity":"high","component":"libnl-3-200"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording a flaw answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		named := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", recorded.Identifier)
		releases := func() map[string]bool {
			t.Helper()
			got := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet, "/v1/advisories/"+named+"/document", "")
			if got.Code != http.StatusOK {
				t.Fatalf("generating the advisory answered %d: %s", got.Code, got.Body.String())
			}
			var doc struct {
				Vulnerabilities []struct {
					Status map[string][]string `json:"product_status"`
				} `json:"vulnerabilities"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			out := map[string]bool{}
			for _, v := range doc.Vulnerabilities {
				for _, each := range v.Status {
					for _, release := range each {
						out[release] = true
					}
				}
			}
			return out
		}
		if got := releases(); !got["mine:master:broadcom"] || !got["mine:master:mellanox"] {
			t.Fatalf("the advisory names %v, so this checks nothing", got)
		}
		// The flaw's finding on one build only, so the advisory is still read
		// through the other.
		r.PatchedRows(t, `UPDATE "finding" SET "kind" = 'analysis'
			WHERE "kind" = 'entered' AND "target_id" = `+httpapitest.Itoa(r.TargetOf(t, httpapitest.SeededBuild)))
		if got := releases(); got["mine:master:broadcom"] || !got["mine:master:mellanox"] {
			t.Errorf("the advisory names %v; want the release whose finding is the flaw's alone", got)
		}
	})
}

// The lead reads take the analysis kind alone. A finding holding everything a
// lead holds — its analyzer's result, its sighting, its occurrence and its
// visibility — and filed as another kind answers the evidence, the fixed
// closure and the lead queue as though nothing were there.
func TestTheLeadReadsRefuseEveryOtherKind(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededLead(t, r)
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
		queued := func() int {
			t.Helper()
			total := 0
			for _, state := range []string{"", "not-reproduced", "fixed"} {
				var queue struct {
					Total int `json:"total"`
				}
				httpapitest.Read(t, r, "internal-triager", "/v1/products/mine/code-findings?state="+state, &queue)
				total += queue.Total
			}
			return total
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodGet, at, ""); got.Code != http.StatusOK {
			t.Fatalf("the lead's evidence answered %d, so this checks nothing: %s", got.Code, got.Body)
		}
		if got := queued(); got != 1 {
			t.Fatalf("the queue holds %d with one lead seeded, so this checks nothing", got)
		}
		for _, other := range []string{"vulnerability", "entered"} {
			r.PatchedRows(t, `UPDATE "finding" SET "kind" = '`+other+`' WHERE "occurrence_identity" = '`+occurrence+`'`)
			if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodGet, at, ""); got.Code != http.StatusNotFound {
				t.Errorf("the evidence of a finding of kind %s answered %d: %s", other, got.Code, got.Body)
			}
			// Not reproduced, so the closure would otherwise be taken.
			r.PatchedRows(t, `UPDATE "sighting" SET "absent_run_id" = "last_run_id"`)
			if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at+"/fixed",
				`{"because":"the parser was rewritten","fixed_in":1}`); got.Code != http.StatusNotFound {
				t.Errorf("closing a finding of kind %s as a fixed lead answered %d: %s", other, got.Code, got.Body)
			}
			if got := queued(); got != 0 {
				t.Errorf("the queue holds %d rows where the one finding is of kind %s", got, other)
			}
		}
	})
}
