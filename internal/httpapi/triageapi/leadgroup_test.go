// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// overflowsBesideTheLeak is the seeded run, the leak's last place being
// src/b.c line 3, with an overflow reported at each line of src/b.c given,
// the leak's rule tagged leakTag and the overflow's overflowTag.
func overflowsBesideTheLeak(leakTag, overflowTag string, lines ...int) string {
	return overflowsIn("src/b.c", leakTag, overflowTag, lines...)
}

// overflowsIn is overflowsBesideTheLeak reporting the overflows in file.
func overflowsIn(file, leakTag, overflowTag string, lines ...int) string {
	results := ""
	for _, line := range lines {
		results += `{"ruleId":"overflow","message":{"text":"n overflows"},` +
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + file + `","uriBaseId":"SRCROOT"},` +
			`"region":{"startLine":` + strconv.Itoa(line) + `}}}]},`
	}
	doc := strings.Replace(httpapitest.LeadRunAt(12), `"results":[`, `"results":[`+results, 1)
	return strings.Replace(doc, `"rules":[{"id":"leak"},{"id":"overflow"}]`,
		`"rules":[{"id":"leak","properties":{"tags":["external/cwe/cwe-`+leakTag+`"]}},`+
			`{"id":"overflow","properties":{"tags":["external/cwe/cwe-`+overflowTag+`"]}}]`, 1)
}

// kinOf is the leads a lead's evidence says are one flaw with it, or may be.
func kinOf(t *testing.T, r *httpapitest.Reach, place string) []struct {
	Place string `json:"place"`
	Line  int    `json:"line"`
	Same  bool   `json:"same"`
} {
	t.Helper()
	var got struct {
		Kin []struct {
			Place string `json:"place"`
			Line  int    `json:"line"`
			Same  bool   `json:"same"`
		} `json:"kin"`
	}
	httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/streams/master/variants/broadcom/leads/"+place, &got)
	return got.Kin
}

func TestASecondAnalyzerReportingTheSameFlawGroupsItAndPullsItIn(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		if got := leadState(t, r, place); got != "baseline" {
			t.Fatalf("the seeded lead is %q; want it in the baseline", got)
		}
		// CWE-416 and CWE-787 are both the bounds family. The overflow a
		// line past the leak's last place is the same flaw, the one nine
		// past possibly is, and the one twelve past is not.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), overflowsBesideTheLeak("416", "787", 4, 12, 15))
		kin := kinOf(t, r, place)
		if len(kin) != 2 || !kin[0].Same || kin[0].Line != 4 || kin[1].Same || kin[1].Line != 12 {
			t.Fatalf("the leak's kin are %+v; want the overflow on line 4 the same and line 12 possibly", kin)
		}
		if got := leadState(t, r, place); got != "open" {
			t.Errorf("a lead another analyzer reports is %q; want it out of the baseline", got)
		}
		// The queue puts the flaw two analyzers report above the one only
		// one does.
		queue := leadsOf(t, r, "internal-reader", "")
		if len(queue.Items) != 4 {
			t.Fatalf("the queue is %+v; want the leak and three overflows", queue.Items)
		}
		top := map[string]bool{queue.Items[0].Place: true, queue.Items[1].Place: true}
		if !top[place] || !top[kin[0].Place] {
			t.Errorf("the queue is %+v; want the leak and the overflow on line 4 first", queue.Items)
		}
		// The overflows of one rule are never one flaw with each other.
		for _, k := range kinOf(t, r, kin[0].Place) {
			if k.Place != place {
				t.Errorf("the overflow on line 4 is grouped with %+v of its own rule", k)
			}
		}
	})
}

func TestLeadsOfUnrelatedWeaknessesAreNotOneFlaw(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		// CWE-563 is dead code, which is no family of CWE-787's.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), overflowsBesideTheLeak("563", "787", 3))
		if kin := kinOf(t, r, place); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none", kin)
		}
		if got := leadState(t, r, place); got != "baseline" {
			t.Errorf("a lead no analyzer corroborates is %q; want it in the baseline", got)
		}
	})
}

func TestLeadsInTwoFilesAreNotOneFlaw(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), overflowsIn("src/c.c", "416", "787", 3))
		if kin := kinOf(t, r, place); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none in another file", kin)
		}
	})
}
