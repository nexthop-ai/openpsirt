// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// AnalysisDrops tells the internal readers of a product about an analyzer run
// that marked much of a build's code findings no longer detected at once.
//
// Returned as a function for the applier to call, on the terms Movements is:
// what a run does and how anybody hears about it are separate concerns.
func AnalysisDrops(db *bun.DB, logger *slog.Logger) func(context.Context, analysis.Drop) {
	return func(ctx context.Context, drop analysis.Drop) {
		if err := dropped(ctx, db, drop); err != nil && logger != nil {
			// Logged and carried on. The run is applied and its receipt says
			// the same, so a message nobody could compose is not a reason to
			// fail the run.
			logger.Error("could not say an analyzer run dropped sharply",
				"run", drop.RunID, "build", drop.TargetID, "error", err)
		}
	}
}

// dropped tells everybody who reads internal findings in the product.
func dropped(ctx context.Context, db *bun.DB, drop analysis.Drop) error {
	placed, err := catalog.NewStore(db).Describe(ctx, drop.TargetID)
	if err != nil {
		return fmt.Errorf("read which build the run was for: %w", err)
	}
	var name string
	if err := db.NewSelect().Model((*series.Series)(nil)).Column("name").
		Where(`"id" = ?`, drop.SeriesID).Scan(ctx, &name); err != nil {
		return fmt.Errorf("read which analysis the run was of: %w", err)
	}
	reach, err := whoActs(ctx, db)
	if err != nil {
		return err
	}
	body := fmt.Sprintf("%s %s %s: one run of %s marked %d of %d open code findings no longer detected. "+
		"It was applied.", placed.Product, placed.Stream, placed.Variant, name, drop.Missed, drop.Live)
	where := weblink.CodeFindings(placed.Addressed.Product, placed.Addressed.Stream, placed.Addressed.Variant,
		string(analysis.NoLongerDetected), name)
	together := identify("security-testing-dropped " + strconv.FormatInt(drop.RunID, 10))
	productID := placed.ProductID
	var failed error
	for personID, per := range reach {
		// The code findings named are internal, so reading internal findings is the
		// question, and the link answers for exactly that.
		if !per[productID].readsInternal {
			continue
		}
		if err := NewStore(db).Tell(ctx, Telling{
			PersonID: personID, Kind: SecurityTestingDropped,
			Body: body, Link: where, ProductID: &productID,
			Together: together, Private: true, Internal: true,
		}); err != nil {
			// Carried on for the reason Movements carries on: an event has no
			// retry, so stopping tells a random subset.
			failed = errors.Join(failed,
				fmt.Errorf("tell %d an analyzer run dropped sharply: %w", personID, err))
		}
	}
	return failed
}
