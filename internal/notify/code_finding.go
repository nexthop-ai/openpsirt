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

// CodeFindingAct is something a person did to a code finding that the product's internal
// triagers hear about: recorded it as a flaw, included it in or took it out of its
// flaw's disclosure, or withdrew the agreed dismissal holding it out of the queue.
type CodeFindingAct struct {
	Kind      Kind
	ProductID int64
	// Occurrence is the code finding's occurrence identity.
	Occurrence string
	// By is who did it, and is not told.
	By int64
	// Into says the code finding was included in its flaw's disclosure, and its
	// absence that it was taken out.
	Into bool
}

// TellCodeFindingTriagers tells everybody who triages internal work in the product
// what was done to a code finding. Each is an event: what happened stays true of the
// moment it happened.
func TellCodeFindingTriagers(ctx context.Context, db *bun.DB, act CodeFindingAct) error {
	codeFinding, err := codeFindingNamed(ctx, db, act.ProductID, act.Occurrence)
	if err != nil {
		return err
	}
	if codeFinding == nil {
		return nil
	}
	what := fmt.Sprintf("A code finding of %s at %s in %s %s %s", codeFinding.Rule, codeFinding.Path,
		codeFinding.Product, codeFinding.BranchOrTag, codeFinding.Variant)
	var body string
	switch act.Kind {
	case CodeFindingRecordedAsFlaw:
		body = what + " was recorded as a flaw."
	case CodeFindingIncludedInDisclosure:
		body = what + " was included in its flaw's disclosure. Internal readers keep its state, rule, occurrence and sightings."
		if !act.Into {
			body = what + " was taken out of its flaw's disclosure and is internal only again."
		}
	case CodeFindingReopened:
		body = what + " is back in the queue: its dismissal was withdrawn."
	default:
		return fmt.Errorf("%s is not something done to a code finding", act.Kind)
	}
	reach, err := whoActs(ctx, db)
	if err != nil {
		return err
	}
	link := weblink.CodeFinding(codeFinding.ProductName, codeFinding.BranchOrTagName, codeFinding.VariantName, act.Occurrence)
	productID := act.ProductID
	var failed error
	for personID, per := range reach {
		if personID == act.By || !per[productID].triagesInternal {
			continue
		}
		if err := NewStore(db).Tell(ctx, Telling{
			PersonID: personID, Kind: act.Kind, Body: body, Link: link,
			ProductID: &productID, Private: true, Internal: true,
			Concerns: ConcerningCodeFinding(productID, act.Occurrence),
		}); err != nil {
			// Carried on: an event has no retry, so stopping tells a random
			// subset.
			failed = errors.Join(failed, fmt.Errorf("tell %d about a code finding: %w", personID, err))
		}
	}
	return failed
}

// namedCodeFinding is what a line about a code finding names.
type namedCodeFinding struct {
	Rule        string `bun:"rule"`
	Path        string `bun:"path"`
	Product     string `bun:"product"`
	BranchOrTag string `bun:"branch_or_tag"`
	Variant     string `bun:"variant"`
	// The same three as an address names them.
	ProductName     string `bun:"product_name"`
	BranchOrTagName string `bun:"branch_or_tag_name"`
	VariantName     string `bun:"variant_name"`
}

// codeFindingNamed is the code finding at an occurrence in a product as its newest open finding
// there names it, or its newest finding where none is open. Nil where the
// occurrence holds none.
func codeFindingNamed(ctx context.Context, db bun.IDB, productID int64, occurrence string) (*namedCodeFinding, error) {
	var out namedCodeFinding
	err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "st"."product_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		ColumnExpr(`"v"."identifier" AS "rule"`).
		ColumnExpr(`"ar"."path" AS "path"`).
		ColumnExpr(`"p"."display_name" AS "product"`).
		ColumnExpr(`"st"."display_name" AS "branch_or_tag"`).
		ColumnExpr(`"va"."display_name" AS "variant"`).
		ColumnExpr(`"p"."name" AS "product_name"`).
		ColumnExpr(`"st"."name" AS "branch_or_tag_name"`).
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
		return nil, fmt.Errorf("read which code finding this is: %w", err)
	}
	return &out, nil
}
