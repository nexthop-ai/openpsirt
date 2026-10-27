// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// Piece is one piece of work as the findings list shows it: an issue at a
// fold, which is every binary of one source package at one version.
type Piece struct {
	VulnerabilityID int64
	Fold            string
}

// Handed is what one assignment over a narrowing did.
type Handed struct {
	// Pieces is how many rows of the list the narrowing admitted, which is
	// what the person acting was looking at.
	Pieces int
	// Moved is how many findings changed hands. Fewer than the pieces cover
	// where somebody without the assigner right met work a colleague holds:
	// those rows stay where they are, as they would one at a time.
	Moved int64
	// Withheld is every visibility other than public among the pieces, across
	// the product, which decides what may be said about the act outside the
	// application.
	Withheld []access.Visibility
	// Left is the pieces that did not wholly land where they were sent,
	// because somebody else holds part of them and this caller may not take
	// it. Read after the write, narrowed to what the caller may see.
	Left []Piece
}

// Admits answers whether work holding these visibilities may go where it is
// being sent, read through the transaction the assignment runs in. Withheld is
// every visibility other than public open among the work, each once; empty is
// work disclosed throughout.
type Admits func(ctx context.Context, db bun.IDB, withheld []access.Visibility) error

// AssignMatching hands every piece of work a narrowing admits to one party, or
// back to nobody, in one act.
//
// The pieces are the list's own rows, resolved here from the same filter the
// list pages through, so "everything matching" means what the screen counted
// rather than what one page held. Each piece is then assigned the way a single
// assignment is: across every build of the product, at every binary of the
// fold, under the rule moveWork holds about who may move what.
//
// Only narrows the pieces to the ones a person picked, and is ignored when
// empty. A picked piece the narrowing no longer admits is not assigned: the
// selection was made out of that list, and a row that has left it is not one
// the person is looking at any more.
//
// Admits is asked about every visibility among the pieces before anything is
// written, inside the transaction, so a recipient who may not read undisclosed
// work is refused the whole act rather than handed the disclosed half of it.
func (s *Store) AssignMatching(ctx context.Context, subject access.Subject, scope Scope,
	filter Filter, only []Piece, to *int64, admits Admits) (Handed, error) {

	var handed Handed
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		handed = Handed{}
		inner := &Store{db: tx, now: s.now, reach: s.reach}
		// Asked afresh on every attempt: the filter is a value, and inScope
		// writes the product, the builds and the reader into it.
		narrowed := filter
		productID, visible, buildIDs, err := inner.inScope(ctx, subject, scope, &narrowed)
		if err != nil {
			return err
		}
		dispatches, err := mayHandOver(subject, productID)
		if err != nil {
			return err
		}
		// Refused before anything is read, by the rule moveWhere holds, so a
		// hand-off nobody may make is refused whether or not anything matches.
		if err := mayMove(subject, productID, to, dispatches); err != nil {
			return err
		}
		if len(buildIDs) == 0 {
			return nil
		}
		// Inside the attempt, like the builds: the issues are read from the
		// decision occurrences as they stand when this attempt runs.
		if err := inner.decidedIssuesFor(ctx, &narrowed, []int64{productID}, false); err != nil {
			return err
		}

		pieces, err := inner.pieces(ctx, buildIDs, visible, narrowed)
		if err != nil {
			return err
		}
		if len(only) > 0 {
			picked := make(map[Piece]bool, len(only))
			for _, each := range only {
				picked[each] = true
			}
			kept := pieces[:0]
			for _, each := range pieces {
				if picked[each] {
					kept = append(kept, each)
				}
			}
			pieces = kept
		}
		handed.Pieces = len(pieces)
		if len(pieces) == 0 {
			return nil
		}

		// One statement per fold, naming every issue at it. A fold is one
		// source package at one version, so a product has hundreds of them
		// where it has thousands of pieces.
		byFold := map[string][]int64{}
		for _, each := range pieces {
			byFold[each.Fold] = append(byFold[each.Fold], each.VulnerabilityID)
		}
		folds := make([]string, 0, len(byFold))
		for fold := range byFold {
			folds = append(folds, fold)
		}
		// A fixed order, so two acts over overlapping work take their row
		// locks in the same sequence rather than each waiting on the other.
		sort.Strings(folds)

		// Every visibility among what is being handed over, across the
		// product rather than the selection: the assignment is product-wide,
		// so an undisclosed occurrence in another build travels with it. Narrowed
		// by what the caller may see, like a single assignment.
		kinds, kindArgs := kind.Triage.Where(`"kind"`)
		var withheld []access.Visibility
		for _, fold := range folds {
			held, err := withheldAmong(ctx, tx, visible, func(q *bun.SelectQuery) *bun.SelectQuery {
				return q.Where(inThisProduct, productID).
					Where(kinds, kindArgs...).
					Where(`"vulnerability_id" IN (?)`, bun.List(byFold[fold])).
					Where(inFold, fold)
			})
			if err != nil {
				return fmt.Errorf("read how far this is disclosed: %w", err)
			}
			withheld = append(withheld, held...)
		}
		handed.Withheld = inOrder(withheld)
		if to != nil && admits != nil {
			if err := admits(ctx, tx, handed.Withheld); err != nil {
				return err
			}
		}

		for _, fold := range folds {
			moved, err := inner.moveWhere(ctx, tx, subject, productID, to, dispatches,
				func(q *bun.UpdateQuery) *bun.UpdateQuery {
					return asPieces(q).Where(`"vulnerability_id" IN (?)`, bun.List(byFold[fold])).
						Where(inFold, fold)
				})
			if err != nil {
				return err
			}
			handed.Moved += moved
		}

		for _, fold := range folds {
			left, err := inner.leftBehind(ctx, productID, visible, byFold[fold], fold, to)
			if err != nil {
				return err
			}
			handed.Left = append(handed.Left, left...)
		}
		return nil
	})
	return handed, err
}

// leftBehind is the pieces at one fold with an open, visible occurrence not held
// where the act sent them.
func (s *Store) leftBehind(ctx context.Context, productID int64, visible []access.Visibility,
	issues []int64, fold string, to *int64) ([]Piece, error) {

	held := "assigned_to IS NULL"
	var args []any
	if to != nil {
		// Null-safe, so its negation holds for an occurrence nobody holds: NOT
		// over a comparison with NULL is NULL, and the row would be left out.
		held = "(assigned_to IS NOT NULL AND assigned_to = ?)"
		args = append(args, *to)
	}
	var ids []int64
	kinds, kindArgs := kind.Triage.Where(`"kind"`)
	if err := s.db.NewSelect().Model((*Finding)(nil)).
		Column("vulnerability_id").
		Where(kinds, kindArgs...).
		Where(inThisProduct, productID).
		Where(`"vulnerability_id" IN (?)`, bun.List(issues)).
		Where(inFold, fold).
		Where(`"closed_at" IS NULL`).
		Where(`"visibility" IN (?)`, bun.List(visible)).
		Where("NOT ("+held+")", args...).
		Group("vulnerability_id").
		Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("read what stayed where it was: %w", err)
	}
	out := make([]Piece, 0, len(ids))
	for _, id := range ids {
		out = append(out, Piece{VulnerabilityID: id, Fold: fold})
	}
	return out, nil
}

// inFold narrows findings to the binaries of one fold.
const inFold = `"component_id" IN (SELECT "c"."id" FROM "component" AS "c" WHERE ` +
	FoldedOn + ` = ?)`

// pieces is every group a narrowing admits, unpaged: the rows the findings
// list would show across all its pages, as an issue and a fold.
//
// The page's own statement without its order and its bounds, narrowed by the
// same filter, so a filter that holds on the list holds here and a group
// condition — how far decided, who holds it — is asked of the same group.
func (s *Store) pieces(ctx context.Context, buildIDs []int64, visible []access.Visibility,
	filter Filter) ([]Piece, error) {

	var rows []struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Fold            string `bun:"fold"`
	}
	q := filter.listed(s.db, buildIDs, visible).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(FoldedOn + ` AS "fold"`)
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what the narrowing admits: %w", err)
	}
	out := make([]Piece, 0, len(rows))
	for _, row := range rows {
		out = append(out, Piece{VulnerabilityID: row.VulnerabilityID, Fold: row.Fold})
	}
	return out, nil
}
