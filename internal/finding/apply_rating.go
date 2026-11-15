// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// learnedExploitation is the moment to record beside a clock that just moved,
// or nothing where the row is no longer exploited.
//
// The day the known-exploited catalog listed the issue, or the run's start
// where that is earlier or no day is known. The run's start rather than the
// wall clock, because that is what the deadline beside it was counted from and
// the two have to agree. A finding first seen after the listing still counts
// from when it was seen, which Deadline answers by counting from the later of
// this and the opening.
func learnedExploitation(f Finding, listedOn *time.Time, startedAt time.Time) *time.Time {
	if !f.RankExploited {
		return nil
	}
	return exploitationKnown(listedOn, startedAt)
}

// exploitationKnown is when exploitation counts from: the day the catalog
// listed the issue, or the moment it was learned here where that is earlier or
// no day is known.
func exploitationKnown(listedOn *time.Time, learnedAt time.Time) *time.Time {
	if listedOn != nil && listedOn.Before(learnedAt) {
		at := listedOn.UTC()
		return &at
	}
	return &learnedAt
}

// ranking reports whether an open finding's place in the order has moved, and
// whether exploitation is what moved it.
//
// The two are separate, and deliberately: every ranking signal moves the
// order, and exploitation is the only one that starts a clock over. A score
// somebody revised upward is worth reordering the list for and is not worth
// resetting a deadline over — likelihood and score are not in the deadline at
// all, and a deadline recounted whenever a number was revised would never
// arrive, which is the same failure as recounting it nightly.
//
// It does not answer whether the deadline moved. That is asked of the deadline
// itself, because a fix appearing upstream moves it and touches no ranking
// signal at all.
func ranking(held heldFinding, found Finding) (moved, exploitationMoved bool) {
	moved = held.Urgency != found.Urgency ||
		held.RankExploited != found.RankExploited ||
		held.RankShipped != found.RankShipped
	exploitationMoved = held.RankExploited != found.RankExploited
	return moved, exploitationMoved
}

// ratingRow is one issue as ratingsInForce reads it.
type ratingRow struct {
	ID            int64      `bun:"id"`
	Published     string     `bun:"published"`
	Assessed      string     `bun:"assessed"`
	Exploited     bool       `bun:"exploited"`
	Incident      int        `bun:"incident"`
	ScoreCenti    int        `bun:"score_centi"`
	LikelihoodPPM int        `bun:"likelihood_ppm"`
	ExploitedOn   *time.Time `bun:"exploited_on"`
}

// ratingsInForce reads what is on record about each interned issue.
//
// Read back from the issue rather than taken from the report that is being
// applied, and that is the point of it. A report is one source's account of
// one moment: it may omit that something is being exploited, or carry a score
// lower than a report last week gave. What is stored is the worst anybody has
// claimed, moving only toward worse, plus this product's rating where somebody
// here has made one — so the issue is the one place that knows everything
// known about it, and ranking from anywhere else makes the order depend on
// which scan ran last.
//
// The rating is this build's product's. Another product's rating of the same
// issue reaches nothing here, which is what makes two products able to hold
// different ones.
//
// Interning has already folded this report into the row, so what comes back
// includes whatever this report knew that the row did not.
func ratingsInForce(ctx context.Context, tx bun.IDB, productID int64,
	interned map[string]int64) (map[int64]Rating, error) {

	ids := distinct(slices.Collect(maps.Values(interned)))
	ratings := map[int64]Rating{}
	if len(ids) == 0 {
		return ratings, nil
	}
	var rows []ratingRow
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var found []ratingRow
		err := tx.NewSelect().
			TableExpr(`"vulnerability" AS "v"`).
			Join(rating.Here, productID).
			// Whether this product has been recorded as attacked through the
			// issue. A left join on the standing record rather than a column
			// on the issue, because the record belongs to one product and the
			// issue is shared by all of them.
			Join(standingExploitationHere, productID).
			ColumnExpr(`"v"."id" AS "id"`).
			ColumnExpr(`COALESCE("v"."severity", ?) AS "published"`, "").
			ColumnExpr(`COALESCE("ir"."severity", ?) AS "assessed"`, "").
			ColumnExpr(`"v"."exploited" AS "exploited"`).
			ColumnExpr(`CASE WHEN "eh"."id" IS NULL THEN 0 ELSE 1 END AS "incident"`).
			ColumnExpr(`COALESCE("v"."score_centi", 0) AS "score_centi"`).
			ColumnExpr(`COALESCE("v"."likelihood_ppm", 0) AS "likelihood_ppm"`).
			ColumnExpr(`"v"."exploited_on" AS "exploited_on"`).
			Where(`"v"."id" IN (?)`, bun.List(batch)).
			Scan(ctx, &found)
		rows = append(rows, found...)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read what is on record about these issues: %w", err)
	}
	for _, row := range rows {
		ratings[row.ID] = Rating{
			Published: row.Published, Assessed: row.Assessed,
			Exploited: row.Exploited, Incident: row.Incident == 1,
			ScoreCenti:    row.ScoreCenti,
			LikelihoodPPM: row.LikelihoodPPM,
			ExploitedOn:   row.ExploitedOn,
		}
	}
	return ratings, nil
}
