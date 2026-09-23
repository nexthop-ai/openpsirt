// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Movements tells people about an upload that changed much of what a build is
// made of.
//
// A build that expected to move three dependencies and moved two hundred has
// had a base image change under it, a lockfile regenerated, or a transitive
// tree arrive. The receipt says so to whoever reads it; this is what reaches
// somebody who is not watching.
//
// Returned as a function rather than called from the reader, on the terms the
// lapse notice is: what an upload does and how anybody hears about it are
// separate concerns, and this package reads what has been ingested, so a
// reader reaching it directly would close a cycle between the two.
func Movements(db *bun.DB, logger *slog.Logger) func(context.Context, ingest.Stored) {
	return func(ctx context.Context, stored ingest.Stored) {
		if err := moved(ctx, db, stored); err != nil && logger != nil {
			// Logged and carried on. The inventory is stored and the receipt
			// carries the same numbers, so a message nobody could compose is
			// not a reason to fail the upload that earned it.
			logger.Error("could not say what an upload changed about a build",
				"build", stored.TargetID, "scan", stored.ScanID, "error", err)
		}
	}
}

// moved works out whether an upload is worth telling anybody about, and tells
// them.
func moved(ctx context.Context, db *bun.DB, stored ingest.Stored) error {
	movement, answered, err := graph.NewStore(db).Moved(ctx, stored.TargetID, stored.ScanID)
	if err != nil {
		return err
	}
	// The first inventory read for a build is the first picture of it rather
	// than a change to one, so there is nothing to be unlike.
	if !answered {
		return nil
	}

	settings := setting.NewStore(db)
	share, err := settings.Count(ctx, setting.DeltaShare, setting.DefaultDeltaShare)
	if err != nil {
		return fmt.Errorf("read how much of a build may move: %w", err)
	}
	floor, err := settings.Count(ctx, setting.DeltaFloor, setting.DefaultDeltaFloor)
	if err != nil {
		return fmt.Errorf("read how few names are worth reporting: %w", err)
	}
	if !outsized(movement, share, floor) {
		return nil
	}

	placed, err := catalog.NewStore(db).Describe(ctx, stored.TargetID)
	if err != nil {
		return fmt.Errorf("read which build this upload was for: %w", err)
	}

	reach, err := whoActs(ctx, db)
	if err != nil {
		return err
	}
	var failed error
	body := saying(placed, movement)
	// One upload is one thing to carry outside, however many people read the
	// product. Hashed for the reason a condition's key is: it lands in a
	// fixed-width column beside keys other passes invent.
	together := identify("inventory-moved " + strconv.FormatInt(stored.ScanID, 10))
	where := "/products/" + url.PathEscape(placed.Addressed.Product) +
		"/streams/" + url.PathEscape(placed.Addressed.Stream) +
		"/variants/" + url.PathEscape(placed.Addressed.Variant) +
		"/scans/" + strconv.FormatInt(stored.ScanID, 10) + "/changes"

	for personID, per := range reach {
		// Whoever may read the product, which is exactly who the link
		// answers for. This names no finding — it is arithmetic over the
		// documents a build sent — so reading the product is the whole of
		// the question, and telling somebody the screen would refuse is an
		// alarm pointing at a refusal.
		if !per[placed.ProductID].readsIn() {
			continue
		}
		productID := placed.ProductID
		if err := NewStore(db).Tell(ctx, Telling{
			PersonID: personID, Kind: InventoryMoved,
			Body: body, Link: where, ProductID: &productID,
			Together: together,
		}); err != nil {
			// Carried on rather than returned. The map is walked in no
			// order, so stopping at the first failure tells a random subset
			// and the rest hear nothing — and an event has no retry, so
			// "the rest" means for ever.
			failed = errors.Join(failed,
				fmt.Errorf("tell %d what an upload changed: %w", personID, err))
		}
	}
	return failed
}

// outsized says whether an upload moved enough of a build's inventory that
// somebody should hear about it.
//
// Both thresholds, and both have to be passed. The share is what makes the
// question "is this unlike this build" — forty names is a rebuild on an
// inventory of two thousand and a different build on an inventory of sixty —
// and the floor is what keeps a small inventory from asking it every time
// three dependencies move.
func outsized(movement graph.Movement, share, floor int) bool {
	names := movement.Added + movement.Removed + movement.Changed
	if names < floor {
		return false
	}
	// Multiplied out rather than divided, so that the comparison is in whole
	// names and a share of a small inventory does not round to nothing. It is
	// also what makes an inventory that held nothing pass whatever the share
	// is — whatever arrived is the whole of it — while the floor above still
	// applies to it, as it does to every upload.
	return names*100 >= share*movement.Held
}

// saying is what an outsized upload is told as.
//
// The fact and the three numbers behind it. Which names moved is a list, and a
// list belongs on the screen the link leads to — where who may read it is
// decided by the same rule that decided who was told.
func saying(placed *catalog.Placement, movement graph.Movement) string {
	names := movement.Added + movement.Removed + movement.Changed
	moved := "1 name moved"
	if names != 1 {
		moved = fmt.Sprintf("%d names moved", names)
	}
	// The size is what the change is against rather than what the names were
	// part of: a build that gained thirty has not moved thirty of what it
	// held.
	return fmt.Sprintf("%s %s %s: %s in one upload, against an inventory of %d. "+
		"%d arrived, %d left, %d at different versions.",
		placed.Product, placed.Stream, placed.Variant,
		moved, movement.Held, movement.Added, movement.Removed, movement.Changed)
}
