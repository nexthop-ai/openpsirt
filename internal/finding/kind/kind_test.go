// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package kind

import (
	"reflect"
	"testing"
)

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
			if !c.Includes(k) {
				t.Errorf("%s lists %q and does not include it", c, k)
			}
		}
	}
	if Known("dependency") {
		t.Error("a kind nothing declares is known")
	}
}

// builtForAnalysis is the consumers that read analysis results.
var builtForAnalysis = map[Consumer]bool{Assignment: true, Decisions: true, Exports: true, Evidence: true, CodeFindings: true}

func TestAnalysisReachesOnlyTheConsumersBuiltForIt(t *testing.T) {
	for _, c := range consumers() {
		if got, want := c.Includes(Analysis), builtForAnalysis[c]; got != want {
			t.Errorf("%s includes analysis results: %v; want %v", c, got, want)
		}
	}
}

func TestOnlyTheSweepAndTheCodeFindingReadersLeaveRecordedFlawsOut(t *testing.T) {
	for _, c := range consumers() {
		if got, want := c.Includes(Entered), c != Closure && c != Evidence && c != CodeFindings; got != want {
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

// Every declared kind is in exactly one family, so a list of held work split
// by family loses no row and counts none twice.
func TestEveryKindIsInOneFamily(t *testing.T) {
	declared := Declarations()
	if len(declared) == 0 {
		t.Fatal("no kinds were found, so this checked nothing")
	}
	for _, d := range declared {
		in := 0
		for _, f := range Families() {
			for _, k := range f.Kinds() {
				if k == d.Kind {
					in++
				}
			}
		}
		if in != 1 {
			t.Errorf("%s is in %d families; want 1", d.Kind, in)
		}
	}
	for _, f := range Families() {
		for _, k := range f.Kinds() {
			if !Known(k) {
				t.Errorf("the %s family holds %q, which nothing declares", f, k)
			}
		}
	}
}

func TestAFamilyNarrowsAConsumerToItsKinds(t *testing.T) {
	const column = `"f"."kind"`
	for _, c := range []struct {
		consumer Consumer
		family   Family
		kinds    []Kind
	}{
		{Assignment, "", Assignment.Kinds()},
		{Assignment, Code, []Kind{Analysis}},
		{Assignment, Dependency, []Kind{Vulnerability, Entered}},
		{Notifications, Code, nil},
	} {
		where, args := c.consumer.WhereIn(column, c.family)
		wantWhere, wantArgs := In(column, c.kinds)
		if where != wantWhere || !reflect.DeepEqual(args, wantArgs) {
			t.Errorf("%s in the %q family keeps %q %v; want %v, %q %v",
				c.consumer, c.family, where, args, c.kinds, wantWhere, wantArgs)
		}
	}
}
