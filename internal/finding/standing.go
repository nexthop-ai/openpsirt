// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// A product's standing, per build.
//
// There was no page for one product. "How is SONiC doing" was five
// requests and a spreadsheet: what is open per build, how much of it is
// overdue, how much has been decided, when each build was last scanned. Every
// piece existed and none of them sat together, so the question was answered by
// somebody who already knew where to look.

// BuildStanding is one build of a product and how far its work has got.
//
// Named for the build because "Standing" is already what a decision is when it
// still applies, and one word for two things is how two readers come to mean
// different ones.
type BuildStanding struct {
	TargetID int64
	Stream   string
	Variant  string
	// Open is issues at components, the unit every count here uses.
	Open int
	// Overdue is how many of those are past a deadline, and Exploited how many
	// somebody is known to be exploiting. Those two are what decides whether a
	// build needs an afternoon or a week.
	Overdue   int
	Exploited int
	// Undecided is how many nobody has claimed anything about, and Agreed how
	// many are answered at every place by a standing decision — the same two
	// words the findings list's state filter uses, by the same definition, so
	// this page and that list cannot disagree about what "agreed" means.
	Undecided int
	Agreed    int
}

// HowItStands reads each build of a product with how far its work has got, and
// the product's own totals.
//
// The product's totals are not the sum of its builds. The findings list
// answers for a whole product as one row per issue and component across every
// build it holds, so a library carrying one issue in two builds is
// one thing to decide about and two build rows. Adding the build rows up would
// put a number on this page that the list it links to contradicts — which is
// the failure this page exists to avoid, arrived at from the other side. So
// the totals are counted again, over the product, by the same grouping the
// list uses.
//
// Derived rather than stored for the reason every count here is: a stored
// total is right at the end of a scan and drifts from the list beside it
// thereafter.
func (s *Store) HowItStands(ctx context.Context, subject access.Subject,
	productID int64) ([]BuildStanding, BuildStanding, error) {

	var whole BuildStanding
	if !subject.Sees(productID) {
		return nil, whole, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return nil, whole, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	// The store's clock, like everything else here, so a frozen clock
	// reaches it and so one answer is worked out from one moment.
	now := s.now().UTC()

	// The things somebody decides about: one row per build, issue and
	// component, with the places counted and the standing decisions counted
	// against them. The state words below compare an approved count against
	// the number of places, which is why the decisions are counted as a
	// correlated EXISTS per place rather than joined — a join multiplies the
	// rows and a place with two decisions would count twice.
	// The one count no list carries: anything that still says something about
	// the place. A withdrawn claim does not — it covers the place so that
	// "lapsed" can be said, and counting it as a claim took the finding out
	// of the undecided figure while putting it in no other, which is the same
	// hole the list's own state words had. Spelled through the same helper as
	// the rest, so the correlation and the version match are one expression.
	anyClaim := decisionState{"any_claim", " AND de.state <> ?", []any{"withdrawn"}}
	// The things somebody decides about, grouped one way for the build rows
	// and another for the product's own totals: with the build in the key it
	// is one row per build, and without it a group in three builds is one
	// thing, which is what the findings list answers for a whole product.
	grouped := func(byBuild bool) *bun.SelectQuery {
		q := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
			ColumnExpr(`COUNT(*) AS "places"`).
			ColumnExpr(`MIN(f.due_at) AS "due_at"`).
			ColumnExpr(`MAX(f.urgency) AS "urgency"`).
			// The flag rather than the urgency's top bands, which answer
			// "some exploitation". This total is the feed's word about the
			// world, and a product recorded as attacked here is a different
			// fact that would be counted under the wrong name.
			ColumnExpr(exploitedAcross+` AS "exploited"`).
			ColumnExpr(decidedAs("?", anyClaim), productID, "withdrawn")
		q = decisionCounts(q, "?", []any{productID}, claimApproved).
			Where(inThisProductAs("f.target_id"), productID).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible))
		if byBuild {
			return q.ColumnExpr(`f.target_id AS "target_id"`).
				GroupExpr("f.target_id, f.vulnerability_id, f.component_id")
		}
		return q.GroupExpr("f.vulnerability_id, f.component_id")
	}
	// The four sums each grouping is reduced by, spelled once so the build
	// rows and the product's totals cannot come to mean different things.
	counted := func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.
			ColumnExpr(`COUNT(*) AS "open"`).
			ColumnExpr(`SUM(CASE WHEN grouped.due_at IS NOT NULL AND grouped.due_at < ? THEN 1 ELSE 0 END) AS "overdue"`, now).
			ColumnExpr(`SUM(grouped.exploited) AS "exploited"`).
			ColumnExpr(`SUM(CASE WHEN grouped.any_claim = 0 THEN 1 ELSE 0 END) AS "undecided"`).
			ColumnExpr(`SUM(CASE WHEN grouped.approved_here = grouped.places THEN 1 ELSE 0 END) AS "agreed"`)
	}
	groups := grouped(true)

	var rows []struct {
		TargetID  int64  `bun:"target_id"`
		Stream    string `bun:"stream"`
		Variant   string `bun:"variant"`
		Open      int    `bun:"open"`
		Overdue   int    `bun:"overdue"`
		Exploited int    `bun:"exploited"`
		Undecided int    `bun:"undecided"`
		Agreed    int    `bun:"agreed"`
	}
	err := counted(s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, groups).
		Join(`JOIN "target" AS "tg" ON tg.id = grouped.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`grouped.target_id AS "target_id"`).
		ColumnExpr(`MIN(st.name) AS "stream"`).
		ColumnExpr(`MIN(va.name) AS "variant"`)).
		GroupExpr("grouped.target_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, whole, fmt.Errorf("read how this product's builds stand: %w", err)
	}

	var totals []struct {
		Open      int `bun:"open"`
		Overdue   int `bun:"overdue"`
		Exploited int `bun:"exploited"`
		Undecided int `bun:"undecided"`
		Agreed    int `bun:"agreed"`
	}
	if err := counted(s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, grouped(false))).
		Scan(ctx, &totals); err != nil {
		return nil, whole, fmt.Errorf("read how this product stands: %w", err)
	}
	if len(totals) == 1 {
		whole = BuildStanding{
			Open: totals[0].Open, Overdue: totals[0].Overdue,
			Exploited: totals[0].Exploited, Undecided: totals[0].Undecided,
			Agreed: totals[0].Agreed,
		}
	}

	out := make([]BuildStanding, 0, len(rows))
	for _, row := range rows {
		out = append(out, BuildStanding{
			TargetID: row.TargetID, Stream: row.Stream, Variant: row.Variant,
			Open: row.Open, Overdue: row.Overdue, Exploited: row.Exploited,
			Undecided: row.Undecided, Agreed: row.Agreed,
		})
	}
	return out, whole, nil
}
