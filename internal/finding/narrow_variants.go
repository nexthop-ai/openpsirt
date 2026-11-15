// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// VariantSpread is how a group is spread over the variants of a branch.
type VariantSpread string

const (
	// AnyVariants is no narrowing by spread.
	AnyVariants VariantSpread = ""
	// OnlyThisVariant keeps rows no other variant of the same branch holds
	// open — what is specific to the variant the selection names.
	OnlyThisVariant VariantSpread = "only"
	// EveryVariant keeps rows every build of the same branch holds open —
	// what is common to the product rather than to how it was built.
	EveryVariant VariantSpread = "every"
)

// VariantSpreads is every narrowing by spread a request can ask for. No
// narrowing is the absence of one, so it is not among them.
func VariantSpreads() []VariantSpread { return []VariantSpread{OnlyThisVariant, EveryVariant} }

// onThisRowsBranch is the branch the row's own build sits on.
//
// Spelled as a scalar subquery, which is how the other five lookups of this
// shape here are written, rather than as a join correlated outward from
// inside a subquery.
const onThisRowsBranch = `(SELECT "tg0"."branch_or_tag_id" FROM "build" AS "tg0"` +
	` WHERE "tg0"."id" = "f"."build_id")`

// acrossVariants keeps rows by how the variants of a branch share them.
//
// The comparison is against the other builds on the row's own branch, whatever
// the selection holds. Taken over the selection's branches together, a
// selection naming a variant and leaving the branch at all compares each row
// against every other variant on either branch: an issue open on one branch's
// variant and on a different variant of another branch is dropped from "only",
// though on its own branch nothing else has it.
//
// A row is held elsewhere where the same issue is open at the same fold, which
// is the grain the list groups by. The fold is looked up from the row's
// component rather than read off the outer query, because not every query this
// narrows has the component joined under a known name.
//
// Both conditions are placed on the rows rather than as a HAVING, because the
// question is about an occurrence: a group open on two branches keeps the
// occurrences where its variant is alone with it and drops the occurrences
// where it is not.
func (f Filter) acrossVariants(q *bun.SelectQuery) *bun.SelectQuery {
	if f.AcrossVariants == AnyVariants || len(f.BuildIDs) == 0 {
		return q
	}
	// The same issue at the same fold, open and seen by this reader; which
	// build is added by the caller.
	heldElsewhere := func() *bun.SelectQuery {
		kinds, args := kind.Triage.Where(`"f2"."kind"`)
		held, heldArgs := openOn("f2", f.OpenOn)
		return q.NewSelect().TableExpr(`"finding" AS "f2"`).
			Join(`JOIN "component" AS "c2" ON "c2"."id" = "f2"."component_id"`).
			ColumnExpr("1").
			Where(`"f2"."vulnerability_id" = "f"."vulnerability_id"`).
			Where(`"c2"."fold_key" = (SELECT "c1"."fold_key" FROM "component" AS "c1"`+
				` WHERE "c1"."id" = "f"."component_id")`).
			Where(held, heldArgs...).
			Where(`"f2"."visibility" IN (?)`, bun.List(f.Visible)).
			Where(kinds, args...)
	}
	switch f.AcrossVariants {
	case OnlyThisVariant:
		// A variant has to be named for "only this one" to mean anything;
		// the caller refuses the request before it reaches here, and this
		// is the same answer for a caller that did not.
		if f.VariantID == nil {
			return q.Where("1 = 0")
		}
		others := q.NewSelect().TableExpr(`"build" AS "b2"`).
			ColumnExpr(`"b2"."id"`).
			Where(`"b2"."branch_or_tag_id" = `+onThisRowsBranch).
			Where(`"b2"."variant_id" <> ?`, *f.VariantID)
		return q.Where("NOT EXISTS (?)", heldElsewhere().
			Where(`"f2"."build_id" IN (?)`, others))
	case EveryVariant:
		// No build on the row's own branch lacks it.
		lacking := q.NewSelect().TableExpr(`"build" AS "b2"`).
			ColumnExpr(`"b2"."id"`).
			Where(`"b2"."branch_or_tag_id" = `+onThisRowsBranch).
			Where("NOT EXISTS (?)", heldElsewhere().Where(`"f2"."build_id" = "b2"."id"`))
		return q.Where("NOT EXISTS (?)", lacking)
	}
	return q
}
