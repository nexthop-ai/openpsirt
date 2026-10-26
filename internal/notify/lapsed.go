// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// Lapses tells people that a judgment of theirs has stopped applying.
//
// One of the two outcomes a proposer still hears about by message rather than
// by looking. Approval is silent because it is what they asked for; a lapse is
// not — nothing they did caused it, it hands work back to them, and the
// alternative is the finding reappearing as though nobody had ever looked at
// it, with the reasoning stranded on a row nothing points at.
//
// Returned as a function rather than called from the scanner, because what a
// scan does and how anybody hears about it are separate concerns — and because
// this package reads what has been ingested, so a scanner reaching it directly
// would close a cycle between the two. The deployment wires them together.
func Lapses(db *bun.DB, logger *slog.Logger) func(context.Context, []triage.ForPerson) {
	return func(ctx context.Context, told []triage.ForPerson) {
		for _, one := range told {
			if err := NewStore(db).Tell(ctx, Lapse(one)); err != nil && logger != nil {
				logger.Error("could not say that a decision lapsed",
					"person", one.PersonID, "decision", one.DecisionID, "error", err)
			}
		}
	}
}

// Lapse is what one person is told about the rows of theirs that lapsed.
//
// A link to the claims that are theirs to re-affirm rather than to one of the
// rows: a version bump lapses many claims at once, and the work is re-affirming
// all of them.
func Lapse(one triage.ForPerson) Telling {
	what := "A decision of yours"
	if one.Rows > 1 {
		what = fmt.Sprintf("%d decisions of yours", one.Rows)
	}
	why := " stopped applying: the code it was a claim about has moved."
	again := " The finding is open again, and re-affirming it is yours to do."
	switch {
	case one.RatedWorse:
		why = " stopped applying: the issue is rated worse than when it was made."
	case one.Probable:
		why = " stopped applying: an analyzer run matched the lead only by its function or its nearest line."
		again = " The lead is open again, and re-affirming it is yours to do."
	}
	return Telling{
		PersonID: one.PersonID, Kind: ClaimLapsed,
		Body: what + why + again,
		Link: weblink.ReviewQueueReaffirm(),
		// As careful as the most careful row.
		Private:  one.Undisclosed,
		Internal: one.Internal,
		// The fields a later read narrows by, off the representative row.
		ProductID:       &one.ProductID,
		VulnerabilityID: &one.VulnerabilityID,
	}
}
