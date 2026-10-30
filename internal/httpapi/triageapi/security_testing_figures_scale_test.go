// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the security testing figures cost on the component hub's build of
// 16,000 components and 4,000 code findings: their openings spread over two
// years, a tenth closed as fixed, a twentieth judged, a hundred and four runs
// of the series before the one applied, and the build read as a release.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it; one engine at a time is OPENPSIRT_TEST_ENGINES.
package triageapi_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// figureHistory is how many runs of the series came before the one the hub
// applies, a nightly series over a hundred and four days.
const figureHistory = 104

func TestMeasureTheSecurityTestingFigures(t *testing.T) {
	const n, codeFindings = 16000, 4000
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		began := time.Now()
		hubSeeded(t, r, n, codeFindings)
		now := time.Now().UTC()
		day := 24 * time.Hour
		// Openings a week apart over two years, by a hundred residues of
		// the identifier, and every tenth closed half way to now.
		for d := range 100 {
			if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
				Set(`"opened_at" = ?`, now.Add(-time.Duration(d*7)*day)).
				Where(`"kind" = ?`, kind.Analysis).Where(`"id" % 100 = ?`, d).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
				Set(`"closed_at" = ?`, now.Add(-time.Duration(d*7/2)*day)).
				Where(`"kind" = ?`, kind.Analysis).Where(`"id" % 100 = ?`, d).Where(`"id" % 10 = 0`).
				Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var open []string
		if err := r.DB.DB.NewSelect().TableExpr(`"finding"`).ColumnExpr(`"occurrence_identity"`).
			Where(`"kind" = ?`, kind.Analysis).Where(`"closed_at" IS NULL`).
			OrderExpr(`"id"`).Limit(codeFindings/20).Scan(ctx, &open); err != nil {
			t.Fatal(err)
		}
		for _, occurrence := range open {
			at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence + "/decision"
			if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, at,
				`{"outcome":"confirmed","reasoning":"measured"}`); w.Code != http.StatusCreated {
				t.Fatalf("confirming answered %d: %s", w.Code, w.Body.String())
			}
		}
		var run struct {
			ID      int64     `bun:"id"`
			BuiltAt time.Time `bun:"built_at"`
		}
		if err := r.DB.DB.NewSelect().TableExpr(`"series_run"`).ColumnExpr(`"id", "built_at"`).
			Limit(1).Scan(ctx, &run); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= figureHistory; i++ {
			at := now.Add(-time.Duration(i) * day)
			if _, err := r.DB.DB.NewRaw(`INSERT INTO "series_run" ("series_id", "build_id", "content_hash",
					"built_at", "received_at", "status", "comparable", "not_comparable", "applied_at",
					"units_expected", "units_analyzed")
				SELECT "series_id", "build_id", ?, ?, ?, "status", "comparable", "not_comparable", ?,
					"units_expected", "units_analyzed"
				FROM "series_run" WHERE "id" = ?`,
				fmt.Sprintf("%064d", i), run.BuiltAt.Add(-time.Duration(i)*day), at, at, run.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%d components, %d code findings: seeded in %s", n, codeFindings, time.Since(began).Round(time.Second))
		paths := []string{
			"/v1/products/mine/code-finding-time-to-judge?weeks=104",
			"/v1/products/mine/code-finding-time-to-fix?weeks=104",
			"/v1/products/mine/code-finding-precision",
			"/v1/products/mine/analysis-coverage?weeks=104",
		}
		timed(t, r, fmt.Sprintf("%d components", n), paths)
		// The build read as a release: a release line reads every tag's
		// code findings.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"branch_or_tag"`).Set(`"kind" = 'tag'`).
			Where(`"name" = 'master'`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		timed(t, r, fmt.Sprintf("%d components as a release", n), []string{
			"/v1/products/mine/code-findings-by-release",
		})
	})
}
