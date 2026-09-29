// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

func TestEveryBuildIsCountedInTheOneStateItIsIn(t *testing.T) {
	// The coverage tiles are read side by side as parts of one estate, so a
	// build counted as scanned and as something else too makes the parts add
	// up to more than the whole.
	seen := time.Now()
	rows := []ingest.Coverage{
		{Product: "scanned", LastReceivedAt: &seen},
		{Product: "quiet", LastReceivedAt: &seen, Quiet: true},
		{Product: "never, young"},
		{Product: "never, quiet", Quiet: true},
		{Product: "out of support", OutOfSupport: true, LastReceivedAt: &seen},
		{Product: "out of support and out of use", OutOfSupport: true, RetiredFromUse: true},
		{Product: "out of use", RetiredFromUse: true, LastReceivedAt: &seen},
		{Product: "out of use, never", RetiredFromUse: true},
	}
	got := countCoverage(rows)
	want := coverageCounts{quiet: 2, never: 2, unsupported: 2, retired: 2, scanned: 1}
	if got != want {
		t.Errorf("counted %+v, want %+v", got, want)
	}
	// Every build but the quiet one a scan reached is in exactly one of the
	// four states that are not quiet.
	if sum := got.never + got.unsupported + got.retired + got.scanned; sum != len(rows)-1 {
		t.Errorf("the states hold %d builds of %d, less the one only quiet", sum, len(rows))
	}
}
