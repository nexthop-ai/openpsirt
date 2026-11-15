// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/series"
)

func TestARunIsComparableOnlyWhereNothingSaysItFailedOrChanged(t *testing.T) {
	// Each case breaks one condition of a run that is otherwise comparable,
	// so it reaches only the arm that names that condition.
	n := func(v int) *int { return &v }
	yes, no := true, false
	covered := func() series.Params {
		return series.Params{
			ToolName: "clang-tidy", ToolVersion: "18.1.3", RulesDigest: "abc", RulesCount: n(2),
			UnitsExpected: n(10), UnitsAnalyzed: n(10), ExitStatus: n(0), Completed: &yes,
		}
	}
	earlier := &series.Run{Params: covered()}
	cases := []struct {
		name     string
		params   func(p *series.Params)
		previous *series.Run
		signals  int
		want     series.Reason
	}{
		{name: "a covered run with nothing before it", params: func(*series.Params) {}},
		{name: "a covered run like the one before it", params: func(*series.Params) {}, previous: earlier},
		{name: "a tool that exited with a failure", params: func(p *series.Params) { p.ExitStatus = n(1) },
			want: series.ExitStatus},
		{name: "a tool that said it did not finish", params: func(p *series.Params) { p.Completed = &no },
			want: series.Incomplete},
		{name: "a tool that reported a failure of its own run", params: func(*series.Params) {}, signals: 1,
			want: series.FailureSignal},
		{name: "a run stating neither units nor rules", params: func(p *series.Params) {
			p.UnitsExpected, p.UnitsAnalyzed, p.RulesCount = nil, nil, nil
		}, want: series.NoCoverage},
		{name: "a run short of its units", params: func(p *series.Params) { p.UnitsAnalyzed = n(9) },
			want: series.UnitsShort},
		{name: "another version of the tool", params: func(p *series.Params) { p.ToolVersion = "19.1.0" },
			previous: earlier, want: series.ToolChanged},
		{name: "another rule set", params: func(p *series.Params) { p.RulesDigest = "def" },
			previous: earlier, want: series.RulesChanged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := covered()
			c.params(&p)
			ok, reason := series.Comparability(p, c.previous, c.signals)
			if ok != (c.want == "") || reason != c.want {
				t.Errorf("comparable %v for %q; want reason %q", ok, reason, c.want)
			}
		})
	}
}
