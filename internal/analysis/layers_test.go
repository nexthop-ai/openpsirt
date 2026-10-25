// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sarif"
)

func TestAWholeKeyPairsStrongBeforeAProbableLayerIsAsked(t *testing.T) {
	got := pair(
		[]candidate{
			{findingID: 1, key: "other", functionKey: "f", lineKey: "l", line: 10},
			{findingID: 2, key: "k", functionKey: "f", lineKey: "l", line: 90},
		},
		[]Keyed{{Key: "k", FunctionKey: "f", LineKey: "l", Placed: placedAt(10)}})
	if len(got) != 1 || got[0].candidate != 1 || got[0].on != onKey || !strong(got[0].on) {
		t.Errorf("paired %+v; want the second lead on its whole key", got)
	}
}

func TestAMovedResultPairsProbablyOnItsFunction(t *testing.T) {
	got := pair(
		[]candidate{{findingID: 1, key: "before", functionKey: "f", lineKey: "l", line: 10}},
		[]Keyed{{Key: "after", FunctionKey: "f", LineKey: "other", Placed: placedAt(40)}})
	if len(got) != 1 || got[0].on != onFunction || strong(got[0].on) {
		t.Errorf("paired %+v; want a probable pairing on the function", got)
	}
}

func TestAResultNamingNoFunctionIsNeverPairedOnOne(t *testing.T) {
	got := pair(
		[]candidate{{findingID: 1, key: "before", lineKey: "l", line: 10}},
		[]Keyed{{Key: "after", LineKey: "l", Placed: placedAt(12)}})
	if len(got) != 1 || got[0].on != onLine {
		t.Errorf("paired %+v; want the nearest line, since neither names a function", got)
	}
}

func TestAMovedResultPairsWithTheLeadNearestItsLine(t *testing.T) {
	got := pair(
		[]candidate{
			{findingID: 1, key: "a", lineKey: "l", line: 10},
			{findingID: 2, key: "b", lineKey: "l", line: 50},
		},
		[]Keyed{{Key: "c", LineKey: "l", Placed: placedAt(48)}})
	if len(got) != 1 || got[0].candidate != 1 || got[0].on != onLine {
		t.Errorf("paired %+v; want the lead at line 50", got)
	}
}

func TestEachLeadPairsWithOneResultAtMost(t *testing.T) {
	got := pair(
		[]candidate{{findingID: 1, key: "k", lineKey: "l", line: 10}},
		[]Keyed{{Key: "k", LineKey: "l", Placed: placedAt(10)}, {Key: "k", LineKey: "l", Placed: placedAt(10)}})
	if len(got) != 1 || got[0].result != 0 {
		t.Errorf("paired %+v; want the first result alone", got)
	}
}

func TestALeadTheLastRunSawComesBeforeOneItMissed(t *testing.T) {
	got := pair(
		[]candidate{
			{findingID: 1, key: "k", lineKey: "l", line: 10, absent: true},
			{findingID: 2, key: "k", lineKey: "l", line: 10},
		},
		[]Keyed{{Key: "k", LineKey: "l", Placed: placedAt(10)}})
	if len(got) != 1 || got[0].candidate != 1 {
		t.Errorf("paired %+v; want the lead the last run saw", got)
	}
}

func TestTheLineLayerOffersAResultItsNearestEightLeads(t *testing.T) {
	// Nine leads at lines 1 to 9 and nine results at line 1. Each result is
	// offered lines 1 to 8, so the ninth finds them all taken and the lead at
	// line 9 is never offered.
	var leads []candidate
	var results []Keyed
	for i := range 9 {
		leads = append(leads, candidate{findingID: int64(i + 1), key: "lead", lineKey: "l", line: i + 1})
		results = append(results, Keyed{Key: "result", LineKey: "l", Placed: placedAt(1)})
	}
	if got := pair(leads, results); len(got) != 8 {
		t.Errorf("%d pairs; want 8", len(got))
	}
}

// placedAt is a result at a line, and nothing else.
func placedAt(line int) sarif.Placed { return sarif.Placed{StartLine: line} }
