// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// LeadAct is something a person did to a lead that the product's internal
// triagers hear about: handed it off as a flaw, moved it into or out of the
// flaw's case, or withdrew the agreed dismissal holding it out of the queue.
type LeadAct struct {
	Kind      Kind
	ProductID int64
	// Occurrence is the lead's occurrence identity.
	Occurrence string
	// By is who did it, and is not told.
	By int64
	// Into says a move took the lead into its flaw's case, and its absence
	// that an undo took it back out.
	Into bool
}

// TellLeadTriagers tells everybody who triages internal work in the product
// what was done to a lead. Each is an event: what happened stays true of the
// moment it happened.
func TellLeadTriagers(ctx context.Context, db *bun.DB, act LeadAct) error {
	lead, err := leadNamed(ctx, db, act.ProductID, act.Occurrence)
	if err != nil {
		return err
	}
	if lead == nil {
		return nil
	}
	what := fmt.Sprintf("A lead of %s at %s in %s %s %s", lead.Rule, lead.Path,
		lead.Product, lead.Stream, lead.Variant)
	var body string
	switch act.Kind {
	case LeadHandedOff:
		body = what + " was handed off as a flaw."
	case LeadMoved:
		body = what + " was moved into its flaw's case. Internal readers keep its state, rule, occurrence and sightings."
		if !act.Into {
			body = what + " was taken back out of its flaw's case and is internal again."
		}
	case LeadReopened:
		body = what + " is back in the queue: its dismissal was withdrawn."
	default:
		return fmt.Errorf("%s is not something done to a lead", act.Kind)
	}
	reach, err := whoActs(ctx, db)
	if err != nil {
		return err
	}
	link := weblink.Lead(lead.ProductName, lead.StreamName, lead.VariantName, act.Occurrence)
	productID := act.ProductID
	var failed error
	for personID, per := range reach {
		if personID == act.By || !per[productID].triagesInternal {
			continue
		}
		if err := NewStore(db).Tell(ctx, Telling{
			PersonID: personID, Kind: act.Kind, Body: body, Link: link,
			ProductID: &productID, Private: true, Internal: true,
			Concerns: ConcerningLead(productID, act.Occurrence),
		}); err != nil {
			// Carried on: an event has no retry, so stopping tells a random
			// subset.
			failed = errors.Join(failed, fmt.Errorf("tell %d about a lead: %w", personID, err))
		}
	}
	return failed
}

// namedLead is what a line about a lead names.
type namedLead struct {
	Rule    string `bun:"rule"`
	Path    string `bun:"path"`
	Product string `bun:"product"`
	Stream  string `bun:"stream"`
	Variant string `bun:"variant"`
	// The same three as an address names them.
	ProductName string `bun:"product_name"`
	StreamName  string `bun:"stream_name"`
	VariantName string `bun:"variant_name"`
}

// leadNamed is the lead at an occurrence in a product as its newest open finding
// there names it, or its newest finding where none is open. Nil where the
// occurrence holds none.
func leadNamed(ctx context.Context, db bun.IDB, productID int64, occurrence string) (*namedLead, error) {
	var out namedLead
	err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "st"."product_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		ColumnExpr(`"v"."identifier" AS "rule"`).
		ColumnExpr(`"ar"."path" AS "path"`).
		ColumnExpr(`"p"."display_name" AS "product"`).
		ColumnExpr(`"st"."display_name" AS "stream"`).
		ColumnExpr(`"va"."display_name" AS "variant"`).
		ColumnExpr(`"p"."name" AS "product_name"`).
		ColumnExpr(`"st"."name" AS "stream_name"`).
		ColumnExpr(`"va"."name" AS "variant_name"`).
		Where(`"st"."product_id" = ?`, productID).
		Where(`"f"."occurrence_identity" = ?`, occurrence).
		Where(`"f"."kind" = ?`, kind.Analysis).
		OrderExpr(`(CASE WHEN "f"."closed_at" IS NULL THEN 0 ELSE 1 END), "f"."id" DESC`).
		Limit(1).
		Scan(ctx, &out)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read which lead this is: %w", err)
	}
	return &out, nil
}
