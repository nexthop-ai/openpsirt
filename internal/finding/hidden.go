// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Hidden counts what the line keeps out of a list, so that the list can say so
// rather than showing a smaller number with nothing explaining it.
//
// Counted through the rest of the filter, because "hidden by the line" has to
// mean hidden from *this* list — a number counted against everything would say
// six thousand on a page showing fifty.
func (s *Store) Hidden(ctx context.Context, subject access.Subject, scope Scope,
	filter Filter) (int, error) {

	if !filter.Floor.Hides() || filter.BelowFloor {
		return 0, nil
	}
	// The same query, with the line inverted rather than removed.
	below := filter
	below.Floor = Floor{}
	productID, visible, targets, err := s.inScope(ctx, subject, scope, &below)
	if err != nil {
		return 0, err
	}
	if len(targets) == 0 {
		return 0, nil
	}
	counted := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		ColumnExpr("f.vulnerability_id").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr(GroupedOn)
	if words := filter.Floor.admits(); len(words) > 0 {
		// The line's own condition, negated: no exploitation signal at
		// all, and rated beneath the line. Both read the way
		// Floor.narrow reads them, including the threshold that covers
		// both bands.
		counted = counted.Where("f.urgency < ?", int64(exploiting)).
			Where("f.vulnerability_id IN (?)",
				counted.NewSelect().TableExpr(`"vulnerability" AS "v"`).
					Join(rating.Here, productID).
					Column("v.id").
					Where(rating.BandExpr+" NOT IN (?)", bun.List(words)))
	}
	n, err := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, below.narrow(counted)).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count what the line keeps out: %w", err)
	}
	return n, nil
}
