// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// ReleaseState is what the latest scans of one release say about one issue.
type ReleaseState struct {
	// Scanned says a scanner's findings have been applied to a build of the
	// release at least once.
	Scanned bool
	// Open says a finding of the issue is open in a build of the release,
	// among those this subject may read.
	Open bool
}

// HeldOpenIn is what the latest scans of each of these releases of one
// product say about one issue: whether any build of the release has been
// scanned, and whether a finding of the issue is open in one.
//
// A fact for a reader to weigh, never a verdict: an issue open in a release
// named as carrying its fix may be a scanner matching a version it should
// not, and one absent may be a build nobody has scanned since.
//
// Narrowed as the question that authorizes one issue in one product is. A
// collaborator on the case reads the pair whole; anybody else reads the
// findings their visibility on the product reaches, and nothing where they do
// not see the product.
func HeldOpenIn(ctx context.Context, db bun.IDB, subject access.Subject, productID,
	vulnerabilityID int64, streams []int64) (map[int64]ReleaseState, error) {

	out := make(map[int64]ReleaseState, len(streams))
	if len(streams) == 0 {
		return out, nil
	}
	var scanned []int64
	if err := db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("DISTINCT tg.stream_id").
		Where("tg.stream_id IN (?)", bun.List(streams)).
		Where("st.product_id = ?", productID).
		Where("tg.last_run_id IS NOT NULL").
		Scan(ctx, &scanned); err != nil {
		return nil, fmt.Errorf("read which releases have been scanned: %w", err)
	}
	for _, id := range scanned {
		out[id] = ReleaseState{Scanned: true}
	}

	onCase := subject.OnCase(productID, vulnerabilityID)
	if subject.Kind != access.Person || (!onCase && !subject.Sees(productID)) {
		return out, nil
	}
	q := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("DISTINCT tg.stream_id").
		Where("tg.stream_id IN (?)", bun.List(streams)).
		Where("st.product_id = ?", productID).
		Where("f.closed_at IS NULL").
		Where(HeldAs("f.vulnerability_id"), vulnerabilityID)
	if !onCase {
		_, all := subject.Products()
		q = inOneProduct(q, subject, productID, all)
	}
	var open []int64
	if err := q.Scan(ctx, &open); err != nil {
		return nil, fmt.Errorf("read where an issue is open in these releases: %w", err)
	}
	// A finding open in a build is one a scan placed there, whether or not a
	// scanner run is recorded beside it: a flaw found here is entered by hand.
	for _, id := range open {
		out[id] = ReleaseState{Scanned: true, Open: true}
	}
	return out, nil
}
