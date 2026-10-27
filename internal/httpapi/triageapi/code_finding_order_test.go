// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
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

func TestTheQueueIsOrderedByTheToolsOwnRating(t *testing.T) {
	for _, c := range []struct {
		name, leak, overflow, first string
	}{
		{"memory safety over a severe leak", `"tags":["external/cwe/cwe-401"],"security-severity":"9.8"`,
			`"tags":["external/cwe/cwe-787"]`, "src/c.c"},
		{"a use after free over severe dead code", `"tags":["external/cwe/cwe-416"]`,
			`"tags":["external/cwe/cwe-563"],"security-severity":"9.8"`, "src/d.c"},
		{"a severe overflow", ``, `"security-severity":"9.8"`, "src/c.c"},
		{"a severe leak", `"security-severity":"9.8"`, `"security-severity":"2.0"`, "src/d.c"},
		{"a severer overflow", `"security-severity":"2.0"`, `"security-severity":"9.8"`, "src/c.c"},
		{"any severity over none", `"security-severity":"0.5"`, `"precision":"very-high"`, "src/d.c"},
		{"a precise overflow", `"precision":"low"`, `"precision":"Very-High"`, "src/c.c"},
		{"a precise leak", `"precision":"high"`, `"precision":"medium"`, "src/d.c"},
	} {
		t.Run(c.name, func(t *testing.T) {
			httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
				httpapitest.SeededCodeFinding(t, r)
				httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(c.leak, c.overflow))
				got := codeFindingsOf(t, r, "internal-reader", "")
				if len(got.Items) != 3 || got.Items[0].Path != c.first {
					t.Fatalf("the queue is %+v; want %s first", got.Items, c.first)
				}
				// A run of the tool that rates nothing and tags nothing
				// leaves the rating and the weaknesses recorded.
				httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Minute), ratedRun(``, ``))
				if got := codeFindingsOf(t, r, "internal-reader", ""); len(got.Items) != 3 || got.Items[0].Path != c.first {
					t.Errorf("after an unrated run the queue is %+v; want %s first still", got.Items, c.first)
				}
			})
		})
	}
}
