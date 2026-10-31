// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the VEX document of the component hub's build costs: 16,000 components
// and 84,000 findings, some decided, some patched by the build and some closed
// by a supplier's statement, read through the document of one build, the one
// with suppliers' statements, and the statements published about it.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it; one engine at a time is OPENPSIRT_TEST_ENGINES.
package triageapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// vexDecisions is how many kernel issues each decided kernel binary's decision
// names, the most one bulk decision takes.
const vexDecisions = 100

// TestMeasureTheVEXDocumentOfTheHubBuild times the reads a VEX document of the
// hub's build makes, on the statistics the load leaves and again after every
// table is analyzed, as a server start does.
func TestMeasureTheVEXDocumentOfTheHubBuild(t *testing.T) {
	const n = 16000
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		began := time.Now()
		vexSeeded(t, r, n)
		t.Logf("%d components: seeded in %s", n, time.Since(began).Round(time.Second))
		slowest := &longestStatement{}
		deps := r.Deps
		deps.DB = dbtest.Hooked(r.DB, slowest)
		measured := *r
		measured.Handler, _ = httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, deps)
		const build = "/v1/products/mine/branches-and-tags/master/variants/broadcom/vex"
		reads := map[string]func() string{}
		for _, path := range []string{build, build + "?kind=with-suppliers"} {
			reads["GET "+path] = func() string {
				got := httpapitest.AsPerson(t, &measured, "private", http.MethodGet, path, "")
				if got.Code != http.StatusOK {
					t.Fatalf("GET %s answered %d: %s", path, got.Code, got.Body.String())
				}
				var doc struct {
					Statements []json.RawMessage `json:"statements"`
				}
				if err := json.Unmarshal(got.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("%d statements", len(doc.Statements))
			}
		}
		product, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		subject := access.Published([]int64{product.ID})
		named, err := catalog.NewStore(r.DB.DB).LocateVisible(ctx, subject, "mine", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		published := vex.NewStore(deps.DB.DB)
		reads["the statements published"] = func() string {
			built, err := published.Public(ctx, subject, named, r.BuildOf(t, httpapitest.SeededBuild))
			if err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf("%d facts", len(built.Facts))
		}
		names := make([]string, 0, len(reads))
		for name := range reads {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, stats := range []string{"as loaded", "analyzed"} {
			if stats == "analyzed" {
				if _, err := database.AnalyzeEveryTable(ctx, r.DB); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range names {
				var took []time.Duration
				var statement time.Duration
				var said, which string
				for i := range 4 {
					slowest.reset()
					began := time.Now()
					said = reads[name]()
					if i > 0 {
						took = append(took, time.Since(began))
						if longest, query := slowest.took(); longest > statement {
							statement, which = longest, query
						}
					}
				}
				slices.Sort(took)
				t.Logf("%s, %s: %s, %s; slowest statement %s: %s", stats, name,
					took[1].Round(time.Millisecond), said, statement.Round(time.Millisecond), which)
			}
		}
	})
}

// vexSeeded is the hub's build of n components with every third dependency
// finding closed, each at its own moment over a year. Three kernel binaries
// each carry a decision that a hundred of their issues do not apply, agreed,
// and a fourth one that a hundred apply. Of the closed findings, every tenth
// is patched by a claim the build makes and every tenth beside it closed by a
// supplier's statement.
func vexSeeded(t *testing.T, r *httpapitest.Reach, n int) {
	t.Helper()
	ctx := t.Context()
	hubSeeded(t, r, n, 4000)
	now := time.Now().UTC()
	for d := range 100 {
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_at" = ?`, now.Add(-time.Duration(d*87)*time.Hour)).
			Where(`"kind" <> ?`, kind.Analysis).Where(`"id" % 3 = 0`).Where(`"id" % 300 BETWEEN ? AND ?`, 3*d, 3*d+2).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	decided := func(binary int, offset int, body string) {
		issues := make([]string, 0, vexDecisions)
		for v := range vexDecisions {
			issues = append(issues, fmt.Sprintf("%q", fmt.Sprintf("CVE-2026-%d", 100000+v*7+offset)))
		}
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/products/mine/branches-and-tags/master/variants/broadcom/components/linux-image-%d/bulk-decision", binary),
			`{"vulnerabilities":[`+strings.Join(issues, ",")+`],`+body+`}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding at linux-image-%d answered %d: %s", binary, got.Code, got.Body.String())
		}
		var made struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		r.Agreed(t, made.DecisionID)
	}
	for binary := range 3 {
		decided(binary, binary, `"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
			`"selected_by":"the driver","reasoning":"The driver is not built."`)
	}
	decided(3, 3, `"outcome":"affected","selected_by":"the driver","reasoning":"The driver is built and reachable."`)

	build := r.BuildOf(t, httpapitest.SeededBuild)
	var scan int64
	if err := r.DB.DB.NewSelect().TableExpr(`"scan"`).ColumnExpr(`MIN("id")`).
		Where(`"build_id" = ?`, build).Scan(ctx, &scan); err != nil {
		t.Fatal(err)
	}
	claim := map[string]any{
		"build_id": build, "identity": "measured-patch", "vulnerability": "CVE-2026-100000",
		"status": "fixed", "origin": "declared", "opened_scan_id": scan,
	}
	if _, err := r.DB.DB.NewInsert().Model(&claim).TableExpr(`"suppression"`).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var patch int64
	if err := r.DB.DB.NewSelect().TableExpr(`"suppression"`).ColumnExpr(`MAX("id")`).
		Where(`"identity" = ?`, "measured-patch").Scan(ctx, &patch); err != nil {
		t.Fatal(err)
	}
	var person int64
	if err := r.DB.DB.NewSelect().TableExpr(`"person"`).ColumnExpr(`MIN("id")`).Scan(ctx, &person); err != nil {
		t.Fatal(err)
	}
	product, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	statement := &finding.Statement{
		ProductID: product.ID, Publisher: "acme", Vulnerability: "cve-2026-100000",
		Component: "linux-image-0", Status: "not_affected", Justification: "component_not_present",
		Source: finding.FromVex, Document: "acme.json", Digest: strings.Repeat("0", 64),
		UploadedBy: person, UploadedAt: now,
	}
	if _, err := r.DB.DB.NewInsert().Model(statement).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	for _, closed := range []struct {
		because string
		column  string
		by      int64
		at      int
	}{{string(finding.Patched), "suppressed_by", patch, 0}, {string(finding.Disclaimed), "stated_by", statement.ID, 3}} {
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_because" = ?`, closed.because).Set(`? = ?`, bun.Ident(closed.column), closed.by).
			Where(`"build_id" = ?`, build).Where(`"closed_at" IS NOT NULL`).Where(`"kind" <> ?`, kind.Analysis).
			Where(`"id" % 30 = ?`, closed.at).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// longestStatement keeps how long the longest statement since the last reset
// took, and the head of it.
type longestStatement struct {
	mu      sync.Mutex
	longest time.Duration
	query   string
}

func (s *longestStatement) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (s *longestStatement) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if took := time.Since(event.StartTime); took > s.longest {
		s.longest = took
		s.query = strings.Join(strings.Fields(event.Query), " ")
		if len(s.query) > 160 {
			s.query = s.query[:160]
		}
	}
}

func (s *longestStatement) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.longest, s.query = 0, ""
}

func (s *longestStatement) took() (time.Duration, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.longest, s.query
}
