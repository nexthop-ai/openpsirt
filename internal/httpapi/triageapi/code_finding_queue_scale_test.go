// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What reading a product's code finding queue costs on one build holding the first
// run of two analyzers, every code finding of which is open and in the queue. The
// order asks of every row whether another analyzer reports the same flaw on
// its build.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package triageapi_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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
