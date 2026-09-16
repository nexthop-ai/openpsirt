//go:build measure

// What an unbounded bulk promise costs, measured rather than assumed.
//
// A bulk judgment is bounded and a promise to upgrade is not, because the next
// scan re-checks every row a promise names. Removing the bound moves the
// question from "will this be refused" to "will this commit", and the answer
// is a property of four database engines rather than of this code — so it is
// measured on all four, on real servers, and the numbers are written down.
//
// Behind a build tag because it is a measurement and not a gate: it takes
// minutes, it asserts almost nothing, and its output is numbers. `make
// measure` runs it.
package triage_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The sizes a real image produces. One kernel bump reaches 4,485 findings
// across 44,016 places; a cumulative bundle reaches 243,945, which is the
// largest single act the data can ask for.
var promiseSizes = []int{2_000, 44_016, 243_945}

func TestMeasureAnUnboundedPromise(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// Every size runs against the same database, so the places have to go
		// on rather than start again: the unique index over the live key is
		// what a bulk write contends with, and a second act naming a place the
		// first already claimed measures that refusal instead.
		var written int
		for _, size := range promiseSizes {
			t.Run(fmt.Sprintf("%d places", size), func(t *testing.T) {
				proposals := make([]triage.Proposal, 0, size)
				for i := range size {
					at := f.at()
					// A distinct place per row, of the width a place identity
					// has: the unique index over the live key is what a bulk
					// write actually contends with, and rows that collide
					// would measure the refusal instead.
					at.PlaceIdentity = fmt.Sprintf("%064x", written+i)
					at.Visibility = access.Public
					proposals = append(proposals, triage.Proposal{
						Place: at, Outcome: triage.NotApplicable,
						Justification: triage.CodeNotInExecutePath,
						Reasoning:     "Measuring what one act of this size costs to commit.",
						By:            f.proposer, NeedsApproval: true,
					})
				}

				started := time.Now()
				recorded, err := f.store.ProposeMany(t.Context(), f.triager, proposals, size)
				took := time.Since(started)
				if err != nil {
					t.Fatalf("%d rows in one transaction: %v (after %s)", size, err, took)
				}
				if len(recorded) != size {
					t.Fatalf("%d rows asked for and %d written", size, len(recorded))
				}
				written += size
				t.Logf("%8d places in one transaction: %s (%.0f rows/s)",
					size, took.Round(time.Millisecond), float64(size)/took.Seconds())
			})
		}
	})
}
