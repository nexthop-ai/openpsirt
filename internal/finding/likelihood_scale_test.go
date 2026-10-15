// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package finding_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// likelihoodDayIssues is how many issues a feed moves in one day. The real
// image's scan names 7,652, every one of them with an estimate.
const likelihoodDayIssues = 7600

func TestMeasureALikelihoodDay(t *testing.T) {
	// A scan the day a likelihood feed moves every issue: each issue's
	// estimate, the scanned build's order and a tag's order are rewritten,
	// each issue to a value of its own. Measured as statements and as the
	// time the application holds its transaction, which is how long the rows
	// it writes stay locked.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		yesterday := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		today := yesterday.AddDate(0, 0, 1)
		report := func(on *time.Time, shift int) []finding.Reported {
			out := make([]finding.Reported, 0, 2*likelihoodDayIssues)
			for i := range likelihoodDayIssues {
				for _, component := range []string{"libnl", "swss"} {
					at := libnl
					if component == "swss" {
						at = swss
					}
					r := found(fmt.Sprintf("CVE-2026-%05d", i), at)
					r.Issue.Likelihood = float64(1+(i*7+shift)%9973) / 10000
					r.Issue.LikelihoodPercentile = 0.5
					r.Issue.LikelihoodOn = on
					out = append(out, r)
				}
			}
			return out
		}
		tag := f.anotherBuild(t, "24.06")
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), report(&yesterday, 0)); err != nil {
			t.Fatal(err)
		}
		f.shippedTo(t, tag, twoConsumers())
		if _, err := f.store.Apply(ctx, tag, f.runOn(t, tag), report(&yesterday, 0)); err != nil {
			t.Fatal(err)
		}

		asked := &matchedStatements{}
		f.db.AddQueryHook(asked)
		run := f.run(t)
		start := time.Now()
		applied, err := f.store.Apply(ctx, f.target, run, report(&today, 1))
		if err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		estimates, estimated := asked.matching(`UPDATE "vulnerability" AS "vu" SET "likelihood_ppm"`)
		var ordered, reranked int
		var orderedRows, rerankedRows int64
		asked.mu.Lock()
		for _, each := range asked.sent {
			if !strings.HasPrefix(each.query, `UPDATE "finding" AS "f" SET `) {
				continue
			}
			if strings.HasPrefix(each.query, `UPDATE "finding" AS "f" SET "urgency" = (CASE WHEN`) {
				reranked++
				rerankedRows += each.matched
			} else {
				ordered++
				orderedRows += each.matched
			}
		}
		total := len(asked.sent)
		asked.mu.Unlock()
		t.Logf("likelihood day: %d issues, %d findings updated in the scanned build", likelihoodDayIssues,
			applied.Updated)
		t.Logf("estimates: %d statements, %d rows", estimates, estimated)
		t.Logf("scanned build's order: %d statements, %d rows", ordered, orderedRows)
		t.Logf("other builds' order: %d statements, %d rows", reranked, rerankedRows)
		t.Logf("application: %d statements, %s in one transaction", total, took.Round(time.Millisecond))
	})
}
