// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package kind

import "testing"

func TestEveryConsumerIncludesOnlyDeclaredKinds(t *testing.T) {
	all := consumers()
	if len(all) == 0 {
		t.Fatal("no consumers were found, so this checked nothing")
	}
	for _, c := range all {
		kinds := c.Kinds()
		if len(kinds) == 0 {
			t.Errorf("%s includes no kind", c)
		}
		for _, k := range kinds {
			if !Known(k) {
				t.Errorf("%s includes %q, which nothing declares", c, k)
			}
			if !c.includes(k) {
				t.Errorf("%s lists %q and does not include it", c, k)
			}
		}
	}
	if Known("dependency") {
		t.Error("a kind nothing declares is known")
	}
}

// builtForAnalysis is the consumers that read analysis results.
var builtForAnalysis = map[Consumer]bool{Evidence: true}

func TestAnalysisReachesOnlyTheConsumersBuiltForIt(t *testing.T) {
	for _, c := range consumers() {
		if got, want := c.includes(Analysis), builtForAnalysis[c]; got != want {
			t.Errorf("%s includes analysis results: %v; want %v", c, got, want)
		}
	}
}

func TestOnlyTheSweepAndTheAnalysisConsumersLeaveRecordedFlawsOut(t *testing.T) {
	for _, c := range consumers() {
		if got, want := c.includes(Entered), c != Closure && !builtForAnalysis[c]; got != want {
			t.Errorf("%s includes recorded flaws: %v; want %v", c, got, want)
		}
	}
}

func TestAConditionNamesTheKindsItIncludes(t *testing.T) {
	for _, c := range []struct {
		kinds []Kind
		where string
		args  int
	}{
		{nil, "1 = 0", 0},
		{[]Kind{Vulnerability}, `"f"."kind" = ?`, 1},
		{[]Kind{Vulnerability, Entered}, `"f"."kind" IN (?)`, 1},
	} {
		where, args := In(`"f"."kind"`, c.kinds)
		if where != c.where || len(args) != c.args {
			t.Errorf("%v: %q with %d arguments; want %q with %d", c.kinds, where, len(args), c.where, c.args)
		}
	}
}
