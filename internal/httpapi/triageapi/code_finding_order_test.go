// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// ratedRun is the seeded run reporting two more code findings after the first, a
// leak in src/d.c and an overflow in src/c.c, with each rule carrying the
// properties given.
func ratedRun(leak, overflow string) string {
	doc := strings.Replace(httpapitest.CodeFindingRunAt(12), `"results":[`,
		`"results":[{"ruleId":"overflow","message":{"text":"n overflows"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/c.c","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":4}}}]},`+
			`{"ruleId":"leak","message":{"text":"q is leaked"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/d.c","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":9}}}]},`, 1)
	return strings.Replace(doc, `"rules":[{"id":"leak"},{"id":"overflow"}]`,
		`"rules":[{"id":"leak","properties":{`+leak+`}},{"id":"overflow","properties":{`+overflow+`}}]`, 1)
}

// ratedCase is one pair of code findings the queue orders: a leak in d.c and an
// overflow in c.c, under a directory and a pair of rules of the case's own,
// each rule carrying the properties given.
type ratedCase struct {
	name, leak, overflow, first string
}

// paths is where the case's leak and overflow are reported.
func (c ratedCase) paths(i int) (leak, overflow string) {
	return fmt.Sprintf("src/%d/d.c", i), fmt.Sprintf("src/%d/c.c", i)
}

// casesRun is the seeded run reporting two more code findings for every case
// after the first, with each case's rules carrying its properties, or none
// where rated is false.
func casesRun(cases []ratedCase, rated bool) string {
	var results, rules []string
	for i, c := range cases {
		leakAt, overflowAt := c.paths(i)
		results = append(results,
			fmt.Sprintf(`{"ruleId":"overflow-%d","message":{"text":"n overflows"},`+
				`"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q,"uriBaseId":"SRCROOT"},`+
				`"region":{"startLine":4}}}]}`, i, overflowAt),
			fmt.Sprintf(`{"ruleId":"leak-%d","message":{"text":"q is leaked"},`+
				`"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q,"uriBaseId":"SRCROOT"},`+
				`"region":{"startLine":9}}}]}`, i, leakAt))
		leak, overflow := c.leak, c.overflow
		if !rated {
			leak, overflow = ``, ``
		}
		rules = append(rules, fmt.Sprintf(`{"id":"leak-%d","properties":{%s}}`, i, leak),
			fmt.Sprintf(`{"id":"overflow-%d","properties":{%s}}`, i, overflow))
	}
	doc := strings.Replace(httpapitest.CodeFindingRunAt(12), `"results":[`,
		`"results":[`+strings.Join(results, ",")+`,`, 1)
	return strings.Replace(doc, `"rules":[{"id":"leak"},{"id":"overflow"}]`,
		`"rules":[{"id":"leak"},{"id":"overflow"},`+strings.Join(rules, ",")+`]`, 1)
}

// Every case is a pair of its own in one queue: the order between two code
// findings is read from their own rules, so the cases share a run.
func TestTheQueueIsOrderedByTheToolsOwnRating(t *testing.T) {
	cases := []ratedCase{
		{"memory safety over a severe leak", `"tags":["external/cwe/cwe-401"],"security-severity":"9.8"`,
			`"tags":["external/cwe/cwe-787"]`, "c.c"},
		{"a use after free over severe dead code", `"tags":["external/cwe/cwe-416"]`,
			`"tags":["external/cwe/cwe-563"],"security-severity":"9.8"`, "d.c"},
		{"a severe overflow", ``, `"security-severity":"9.8"`, "c.c"},
		{"a severe leak", `"security-severity":"9.8"`, `"security-severity":"2.0"`, "d.c"},
		{"a severer overflow", `"security-severity":"2.0"`, `"security-severity":"9.8"`, "c.c"},
		{"any severity over none", `"security-severity":"0.5"`, `"precision":"very-high"`, "d.c"},
		{"a precise overflow", `"precision":"low"`, `"precision":"Very-High"`, "c.c"},
		{"a precise leak", `"precision":"high"`, `"precision":"medium"`, "d.c"},
	}
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		queue := func() []string {
			got := codeFindingsOf(t, r, "security-testing-reader", "")
			if len(got.Items) != 1+2*len(cases) {
				t.Fatalf("the queue is %+v; want the seeded code finding and two for each case", got.Items)
			}
			paths := make([]string, 0, len(got.Items))
			for _, item := range got.Items {
				paths = append(paths, item.Path)
			}
			return paths
		}
		// Every rule is on record unrated before a run rates it, as the
		// seeded code finding's rules are, so the rating arrives as a change
		// to a rule held.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-90*time.Minute), casesRun(cases, false))
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), casesRun(cases, true))
		rated := queue()
		// A run of the tool that rates nothing and tags nothing leaves the
		// rating and the weaknesses recorded.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Minute), casesRun(cases, false))
		unrated := queue()
		for i, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				leak, overflow := c.paths(i)
				first, second := overflow, leak
				if c.first == "d.c" {
					first, second = leak, overflow
				}
				for when, paths := range map[string][]string{"rated": rated, "after an unrated run": unrated} {
					if at, after := slices.Index(paths, first), slices.Index(paths, second); at < 0 || after < 0 || at > after {
						t.Errorf("%s the queue is %v; want %s before %s", when, paths, first, second)
					}
				}
			})
		}
	})
}
