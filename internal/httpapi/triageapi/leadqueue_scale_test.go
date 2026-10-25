// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What reading a product's lead queue costs on one build holding the first
// run of two analyzers, so every lead arrives in the baseline.
//
// The baseline is the worst case: where a baseline lead stands asks whether
// another analyzer reports the same flaw on its build, of every row.
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

// measuredRun is one analyzer's first run over the seeded checkout: leads
// results across files of twenty, five lines apart, under eight rules of
// three weakness families. offset moves every line, so a second tool's
// results sit beside the first's.
func measuredRun(tool string, leads, offset int) string {
	tags := []string{"787", "416", "476", "401", "120", "190", "563", "252"}
	rules := make([]string, 0, len(tags))
	for i, tag := range tags {
		rules = append(rules, fmt.Sprintf(`{"id":"r%d","properties":{"tags":["external/cwe/cwe-%s"]}}`, i, tag))
	}
	results := make([]string, 0, leads)
	for i := range leads {
		results = append(results, fmt.Sprintf(`{"ruleId":"r%d","message":{"text":"lead %d"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/f%05d.c","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":%d}}}]}`, i%len(tags), i, i/20, 10+5*(i%20)+offset))
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tool + `","rules":[` +
		strings.Join(rules, ",") + `,{"id":"unfired"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///build/"}},` +
		`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/mine","revisionId":"` +
		httpapitest.LeadCommit + `","mappedTo":{"uriBaseId":"SRCROOT"}}],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[` + strings.Join(results, ",") + `]}]}`
}

func TestMeasureTheLeadQueueOfOneBuild(t *testing.T) {
	for _, leads := range []int{4000, 8000, 16000} {
		t.Run(fmt.Sprintf("%d leads", leads), func(t *testing.T) {
			httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
				httpapitest.SeededLead(t, r)
				built := time.Now().UTC().Add(-time.Hour)
				httpapitest.ApplyRunIn(t, r, "clang/measured", built, measuredRun("clang", leads/2, 0))
				httpapitest.ApplyRunIn(t, r, "cppcheck/measured", built, measuredRun("cppcheck", leads/2, 3))
				for _, query := range []string{"", "?state=baseline"} {
					path := "/v1/products/mine/leads" + query
					began := time.Now()
					got := httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet, path, "")
					took := time.Since(began)
					if got.Code != http.StatusOK {
						t.Fatalf("GET %s answered %d: %s", path, got.Code, got.Body.String())
					}
					t.Logf("%d leads, GET %s: %s", leads, path, took.Round(time.Millisecond))
				}
			})
		})
	}
}
