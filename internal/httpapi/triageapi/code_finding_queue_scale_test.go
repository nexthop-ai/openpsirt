// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What reading a product's code finding queue costs: on one build holding the
// first run of two analyzers, every code finding of which is open and in the
// queue, and on the component hub's build, where some are closed. The order
// asks of every row whether another analyzer reports the same flaw on its
// build, and a closed one is listed until it opens anew there.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it; one engine at a time is OPENPSIRT_TEST_ENGINES.
package triageapi_test

import (
	"context"
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

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// measuredRun is one analyzer's first run over the seeded checkout: code findings
// results across files of twenty, five lines apart, under eight rules of
// three weakness families. offset moves every line, so a second tool's
// results sit beside the first's.
func measuredRun(tool string, codeFindings, offset int) string {
	tags := []string{"787", "416", "476", "401", "120", "190", "563", "252"}
	rules := make([]string, 0, len(tags))
	for i, tag := range tags {
		rules = append(rules, fmt.Sprintf(`{"id":"r%d","properties":{"tags":["external/cwe/cwe-%s"]}}`, i, tag))
	}
	results := make([]string, 0, codeFindings)
	for i := range codeFindings {
		results = append(results, fmt.Sprintf(`{"ruleId":"r%d","message":{"text":"code finding %d"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/f%05d.c","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":%d}}}]}`, i%len(tags), i, i/20, 10+5*(i%20)+offset))
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tool + `","rules":[` +
		strings.Join(rules, ",") + `,{"id":"unfired"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///build/"}},` +
		`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/mine","revisionId":"` +
		httpapitest.CodeFindingCommit + `","mappedTo":{"uriBaseId":"SRCROOT"}}],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[` + strings.Join(results, ",") + `]}]}`
}

func TestMeasureTheCodeFindingQueueOfOneBuild(t *testing.T) {
	for _, codeFindings := range []int{4000, 8000, 16000} {
		t.Run(fmt.Sprintf("%d code findings", codeFindings), func(t *testing.T) {
			httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
				httpapitest.SeededCodeFinding(t, r)
				built := time.Now().UTC().Add(-time.Hour)
				httpapitest.ApplyRunIn(t, r, "clang/measured", built, measuredRun("clang", codeFindings/2, 0))
				httpapitest.ApplyRunIn(t, r, "cppcheck/measured", built, measuredRun("cppcheck", codeFindings/2, 3))
				for _, query := range []string{"", "?state=open"} {
					path := "/v1/products/mine/code-findings" + query
					began := time.Now()
					got := httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet, path, "")
					took := time.Since(began)
					if got.Code != http.StatusOK {
						t.Fatalf("GET %s answered %d: %s", path, got.Code, got.Body.String())
					}
					t.Logf("%d code findings, GET %s: %s", codeFindings, path, took.Round(time.Millisecond))
				}
			})
		})
	}
}

// queueTags is the weaknesses of the hub run's eight rules: three families,
// so a second analyzer's result beside a first's is the same flaw.
var queueTags = []string{"787", "416", "476", "401", "120", "190", "563", "252"}

// TestMeasureTheCodeFindingQueueOfTheHubBuild times the queue of the
// component hub's build of 16,000 components and 84,000 findings, with two
// analyzers' 4,000 code findings each a line apart, so most are the same flaw
// as another's. Every tenth code finding is closed, and every third
// dependency finding, each at its own moment over a year, as findings close
// one scan at a time. Each read is timed on the statistics the load leaves
// and again after every table is analyzed, as a server start does.
func TestMeasureTheCodeFindingQueueOfTheHubBuild(t *testing.T) {
	const n, codeFindings = 16000, 4000
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		began := time.Now()
		queueSeeded(t, r, n, codeFindings)
		t.Logf("%d components, %d code findings a tool: seeded in %s", n, codeFindings, time.Since(began).Round(time.Second))
		// The handler again, over a handle timing each statement it makes.
		slowest := &slowestStatement{}
		deps := r.Deps
		deps.DB = dbtest.Hooked(r.DB, slowest)
		measured := *r
		measured.Handler, _ = httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, deps)
		paths := []string{
			"/v1/products/mine/code-findings",
			"/v1/products/mine/code-findings?state=fixed",
			"/v1/products/mine/code-findings?state=open",
			"/v1/products/mine/code-findings?series=clang/measured",
			"/v1/products/mine/components/linux/code-finding-counts",
			"/v1/products/mine/code-finding-series",
			"/v1/products/mine/code-finding-trend?weeks=104",
		}
		for _, stats := range []string{"as loaded", "analyzed"} {
			if stats == "analyzed" {
				if _, err := database.AnalyzeEveryTable(ctx, r.DB); err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range paths {
				var took []time.Duration
				var statement time.Duration
				var body string
				for i := range 4 {
					slowest.reset()
					began := time.Now()
					got := httpapitest.AsPerson(t, &measured, "code-finding-handler", http.MethodGet, path, "")
					if i > 0 {
						took = append(took, time.Since(began))
						statement = max(statement, slowest.took())
					}
					if got.Code != http.StatusOK {
						t.Fatalf("GET %s answered %d: %s", path, got.Code, got.Body.String())
					}
					body = got.Body.String()
				}
				slices.Sort(took)
				t.Logf("%s, GET %s: %s, slowest statement %s, %s", stats, path,
					took[1].Round(time.Millisecond), statement.Round(time.Millisecond), said(body))
			}
		}
	})
}

// queueSeeded is the hub's build of n components with two analyzers'
// codeFindings results each a line apart, every tenth code finding and every
// third dependency finding closed, each at its own moment over a year.
func queueSeeded(t *testing.T, r *httpapitest.Reach, n, codeFindings int) {
	t.Helper()
	ctx := t.Context()
	hubSeeded(t, r, n, codeFindings, queueTags...)
	httpapitest.ApplyRunIn(t, r, "cppcheck/measured", time.Now().UTC().Add(-time.Hour),
		hubRun("cppcheck", n, codeFindings, 1, queueTags))
	now := time.Now().UTC()
	for d := range 100 {
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_at" = ?`, now.Add(-time.Duration(d*87)*time.Hour)).
			Where(`"kind" = ?`, kind.Analysis).Where(`"id" % 10 = 0`).Where(`"id" % 1000 BETWEEN ? AND ?`, 10*d, 10*d+9).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_at" = ?`, now.Add(-time.Duration(d*87)*time.Hour)).
			Where(`"kind" <> ?`, kind.Analysis).Where(`"id" % 3 = 0`).Where(`"id" % 300 BETWEEN ? AND ?`, 3*d, 3*d+2).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// slowestStatement keeps how long the slowest statement since the last reset
// took.
type slowestStatement struct {
	mu      sync.Mutex
	slowest time.Duration
}

func (s *slowestStatement) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (s *slowestStatement) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slowest = max(s.slowest, time.Since(event.StartTime))
}

func (s *slowestStatement) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slowest = 0
}

func (s *slowestStatement) took() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.slowest
}
