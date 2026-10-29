// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// SeriesCount is how many of a product's code findings one analyzer series holds in
// each state.
type SeriesCount struct {
	// Series is the series' name, as its producer first sent it.
	Series string
	// ByState counts the series' code findings in each state, every state named and
	// zero where none stands there. Waiting is the open ones whose decision waits
	// for a second person, and Ruled the dismissed ones a suppression rule
	// covers. A code finding on two builds in two states counts in both, as the queue
	// counts it.
	ByState map[State]int
	Waiting int
	Ruled   int
}

// CountsBySeries is how many code findings each analyzer series of a product holds,
// by where they stand, one entry per series in the order of its name.
//
// Refused to anybody who does not read security testing material in the product, in
// whole: a count of code findings is at security testing visibility however it is narrowed. Counted over
// what the code finding queue lists for the same reader, so each figure is the length
// of the list asking for that series and state.
//
// A series holding no code finding is listed with every count zero. An analyzer that
// runs and finds nothing is a fact about the product.
func CountsBySeries(ctx context.Context, db bun.IDB, subject access.Subject, productID int64) ([]SeriesCount, error) {
	if !subject.Sees(productID) || !subject.Reads(access.SecurityTesting, productID) {
		return nil, access.Denied(fmt.Sprintf("read the code finding counts of product %d", productID))
	}
	visible, err := finding.CodeFindingVisible(subject, productID)
	if err != nil {
		return nil, err
	}

	kinds, kindArgs := kind.CodeFindings.Where(`"se"."kind"`)
	var named []struct {
		ID   int64  `bun:"id"`
		Name string `bun:"name"`
	}
	if err := db.NewSelect().TableExpr(`"series" AS "se"`).
		ColumnExpr(`"se"."id", "se"."name"`).
		Where(`"se"."product_id" = ?`, productID).
		Where(kinds, kindArgs...).
		OrderExpr(`"se"."name_folded" ASC, "se"."id" ASC`).
		Scan(ctx, &named); err != nil {
		return nil, fmt.Errorf("read the analyzer series of product %d: %w", productID, err)
	}

	var counted []struct {
		SeriesID     int64 `bun:"series_id"`
		State        State `bun:"stands"`
		Awaits       int   `bun:"awaits"`
		Covered      int   `bun:"covered"`
		CodeFindings int   `bun:"code_findings"`
	}
	if err := db.NewSelect().
		TableExpr(`(?) AS "l"`, codeFindingFindings(db, subject, Scope{ProductID: productID}, visible)).
		ColumnExpr(`"l"."series_id", "l"."stands", "l"."awaits", "l"."covered"`).
		ColumnExpr(`COUNT(DISTINCT "l"."occurrence_identity") AS "code_findings"`).
		GroupExpr(`"l"."series_id", "l"."stands", "l"."awaits", "l"."covered"`).
		Scan(ctx, &counted); err != nil {
		return nil, fmt.Errorf("count the code findings of product %d by series: %w", productID, err)
	}

	out := make([]SeriesCount, len(named))
	at := make(map[int64]*SeriesCount, len(named))
	for i, each := range named {
		out[i] = SeriesCount{Series: each.Name, ByState: map[State]int{}}
		for _, state := range States() {
			out[i].ByState[state] = 0
		}
		at[each.ID] = &out[i]
	}
	for _, c := range counted {
		one, ok := at[c.SeriesID]
		if !ok {
			continue
		}
		one.ByState[c.State] += c.CodeFindings
		if c.State == Open && c.Awaits == 1 {
			one.Waiting += c.CodeFindings
		}
		if c.State == Dismissed && c.Covered == 1 {
			one.Ruled += c.CodeFindings
		}
	}
	return out, nil
}
