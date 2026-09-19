package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/triage"
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
//
// A link to the decision rather than to the finding: naming the finding needs
// somebody to read it as, and nobody is acting here — a scan is. A decision is
// reachable exactly when what it is about is.
func Lapses(db *bun.DB, logger *slog.Logger) func(context.Context, []triage.ForPerson) {
	return func(ctx context.Context, told []triage.ForPerson) {
		for _, one := range told {
			what := "A decision of yours"
			if one.Rows > 1 {
				what = fmt.Sprintf("%d decisions of yours", one.Rows)
			}
			if err := NewStore(db).Tell(ctx, Telling{
				PersonID: one.PersonID, Kind: ClaimLapsed,
				Body: what + " stopped applying: the code it was a claim about has moved. " +
					"The finding is open again, and the reasoning is on the claim that lapsed.",
				Link: "/decisions/" + strconv.FormatInt(one.DecisionID, 10),
				// As careful as the most careful row.
				Private: one.Undisclosed,
				// The fields a later read narrows by, off the
				// representative row.
				ProductID:       &one.ProductID,
				VulnerabilityID: &one.VulnerabilityID,
			}); err != nil && logger != nil {
				logger.Error("could not say that a decision lapsed",
					"person", one.PersonID, "decision", one.DecisionID, "error", err)
			}
		}
	}
}
