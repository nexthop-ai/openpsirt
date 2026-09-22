package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// The findings list across every product somebody may see.
//
// The work starts from an issue as often as from a product. Findings were
// answerable one product at a time, so "which of our products are carrying
// this, and what is running out anywhere" was a question assembled by hand
// once per product. At a dozen products that is the first thing anybody
// complains about, and the issue page answers only half of it: it answers for
// one issue, and the other half is the list — with filters, an order and
// paging.
//
// One row per product, issue and component. The same library carrying the
// same issue in two products is two pieces of work, decided separately by
// different people; in three builds of one product it is one, with a count.
// That is the grain the per-product list already groups at, one level out.
//
// Every product's own line still applies. A line is a claim about what is
// worth an afternoon *here*, and a list that ignored the lines would hand
// somebody back the thousands of rows their products deliberately set aside.
// Applied per row from the product's own column rather than from one number
// chosen for the page.
//
// Nothing about it is a new visibility rule, and that is exactly where it
// has to be right: a page spanning products is where narrowing afterwards gets
// forgotten, and the total leaks even when no row is shown. So the narrowing
// is in the statement, and an issue that exists only in products somebody
// holds nothing on answers as an issue that does not exist.

// Anywhere is what is open across every product this subject may see.
//
// Ordered, filtered and paged the way the per-product list is, by the same
// allowlist and the same expressions, because two lists with two orders is how
// they come to disagree in front of somebody.
//
// The filters that are about one build are refused rather than ignored: a
// subtree is a walk over one build's edges, and "differs between builds" is a
// statement about a selection. Answering them from whichever build sorted
// first is the failure being avoided.
func (s *Store) Anywhere(ctx context.Context, subject access.Subject,
	limit, offset int, filter Filter) ([]Group, int, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read findings across products")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, 0, nil
	}
	if filter.Beneath != nil {
		return nil, 0, fmt.Errorf("read findings beneath a component: a subtree is a walk over" +
			" one build's edges, and this list spans products")
	}
	limit = database.AList.Of(limit)
	filter.Across = true
	filter.ProductID = 0
	filter.HeldBy = subject.Mine()
	// All three are statements about a selection of builds, which this is not.
	filter.Builds = 0
	filter.DiffersBetweenBuilds = false
	filter.AcrossVariants = AnyVariants
	// The line is applied per product below rather than from the filter's one
	// word, so the filter's own is turned off — including its inverse, which
	// would otherwise ask for what is beneath a line that is not in the query.
	line := filter.Floor
	filter.Floor = Floor{}
	wasBelow := filter.BelowFloor
	filter.BelowFloor = true

	// The deployment's line, which a product that states none inherits.
	deployment := NoFloor
	if !wasBelow {
		word, set, err := setting.NewStore(s.db).Get(ctx, setting.TriageFloor)
		if err != nil {
			return nil, 0, err
		}
		if set && word != "" {
			deployment = word
		}
		// A caller may raise the line for the whole page — that is what the
		// severity control on the list does — but never lower it below what a
		// product decided, because the line is the product's decision.
		if line.Hides() && Ranks(line.Word) > Ranks(deployment) {
			deployment = line.Word
		}
	}

	// pastEOL is which releases are past their date, read once for the
	// page. This list spans products and resolves no build identifiers, so
	// the two questions are conditions here rather than a narrowing of a
	// target list — the same rule, applied where this query can reach it.
	var pastEOL []int64
	if filter.Workable.asks() && len(filter.Workable.Support) == 1 {
		var err error
		if pastEOL, err = catalog.NewStore(s.db).
			StreamsPastEndOfLife(ctx, s.now().UTC()); err != nil {
			return nil, 0, err
		}
	}

	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		if len(filter.Workable.Kinds) == 1 {
			q = q.Where("st.kind = ?", filter.Workable.Kinds[0])
		}
		if len(filter.Workable.Support) == 1 {
			switch {
			case filter.Workable.Support[0] == PastEndOfLife && len(pastEOL) == 0:
				q = q.Where("1 = 0")
			case filter.Workable.Support[0] == PastEndOfLife:
				q = q.Where("st.id IN (?)", bun.List(pastEOL))
			case len(pastEOL) > 0:
				q = q.Where("st.id NOT IN (?)", bun.List(pastEOL))
			}
		}
		q = q.TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			Join(`JOIN "product" AS "p" ON p.id = st.product_id`).
			// The issue is joined for everybody here, unlike the per-product
			// page: the line this list applies is the row's own product's, so
			// the rating has to be compared in the statement rather than
			// turned into a list of admitted words before it.
			Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
			// And whatever the row's own product rates it, for the same
			// reason: a rating belongs to a product, so a list spanning them
			// reads each row's against the product that row is in.
			Join(rating.For(rating.OnStream)).
			// And the component, for the fold: two binaries of one source
			// package carrying one issue are one row here as they are on the
			// per-product list, because they are one thing to decide about.
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			Where("f.closed_at IS NULL")
		q = onlyReadable(q, subject, products, all)
		if !wasBelow {
			// Never below the line where somebody is using one,
			// and being exploited is not a claim about how bad
			// something is — it is a fact, and the one thing a
			// line cannot set aside. Read off the urgency, whose
			// two top bands are the feed's word and this product's
			// own record of being attacked (the exploiting threshold).
			q = q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
				return q.
					WhereOr("f.urgency >= ?", int64(exploiting)).
					WhereOr(ratedAt+" >= "+lineAt, deployment)
			})
		}
		return filter.narrow(q)
	}

	var heads []struct {
		ProductID       int64  `bun:"product_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Fold            string `bun:"fold"`
		ComponentID     int64  `bun:"component_id"`
		Places          int    `bun:"places"`
		Urgency         int64  `bun:"urgency"`
		Total           int    `bun:"total"`
	}
	page := narrow(s.db.NewSelect()).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(FoldedOn + ` AS "fold"`).
		ColumnExpr(`MIN(f.component_id) AS "component_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`MAX(f.urgency) AS "urgency"`).
		ColumnExpr(`COUNT(*) OVER () AS "total"`).
		GroupExpr(GroupedAcross)
	if err := page.OrderExpr(sortedAcross(filter)).
		Limit(limit).Offset(offset).Scan(ctx, &heads); err != nil {
		return nil, 0, fmt.Errorf("read what is open anywhere: %w", err)
	}
	total := 0
	if len(heads) > 0 {
		total = heads[0].Total
	} else {
		counted := narrow(s.db.NewSelect()).
			ColumnExpr("f.vulnerability_id").
			GroupExpr(GroupedAcross)
		var err error
		if total, err = s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`, counted).Count(ctx); err != nil {
			return nil, 0, fmt.Errorf("count what is open anywhere: %w", err)
		}
		return nil, total, nil
	}

	issues := make([]int64, 0, len(heads))
	components := make([]int64, 0, len(heads))
	folds := make([]string, 0, len(heads))
	within := make([]int64, 0, len(heads))
	for _, head := range heads {
		issues = append(issues, head.VulnerabilityID)
		components = append(components, head.ComponentID)
		folds = append(folds, head.Fold)
		within = append(within, head.ProductID)
	}

	// rows is what the page shows about each row, in one statement over
	// the page's products, issues and folds as three lists. That admits
	// combinations no row asked for, which are read and dropped on the way
	// into the map; what it buys is the index, which is the same trade the
	// per-product page makes.
	var rows []struct {
		ProductID       int64  `bun:"product_id"`
		Product         string `bun:"product"`
		ProductName     string `bun:"product_name"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Stream          string `bun:"stream"`
		Variant         string `bun:"variant"`
		Builds          int    `bun:"builds"`
		decorated
	}
	body := narrow(s.db.NewSelect()).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`MIN(COALESCE(NULLIF(p.display_name, ''), p.name)) AS "product_name"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(FoldedOn+` AS "fold"`).
		ColumnExpr(`MIN(f.component_id) AS "component_id"`).
		ColumnExpr(`COUNT(DISTINCT f.component_id) AS "packages"`).
		ColumnExpr(`MIN(st.name) AS "stream"`).
		ColumnExpr(`MIN(va.name) AS "variant"`).
		ColumnExpr(`COUNT(DISTINCT f.target_id) AS "builds"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`MAX(f.urgency) AS "urgency"`).
		ColumnExpr(`MAX(COALESCE(v.likelihood_ppm, 0)) AS "likelihood_ppm"`).
		ColumnExpr(`MAX(COALESCE(v.score_centi, 0)) AS "score_centi"`).
		// Whether anything here carries a score at all, and the scheme it is
		// on. This list spans products, so it is the one place a version 3
		// number and a version 4 number sit in the same column.
		ColumnExpr(`MAX(CASE WHEN v.score_centi IS NULL THEN 0 ELSE 1 END) AS "scored"`).
		ColumnExpr(`MAX(COALESCE(v.score_version, '')) AS "score_version"`).
		ColumnExpr(`SUM(CASE WHEN f.suppressed_by IS NULL THEN 0 ELSE 1 END) AS "answered"`).
		ColumnExpr(`MIN(f.opened_at) AS "opened_at"`).
		ColumnExpr(`MIN(f.due_at) AS "due_at"`).
		// One undisclosed place makes the group undisclosed, counted rather
		// than aggregated over the word — a maximum of the word returns
		// "public" for a mixed group, which is the one case it matters for.
		ColumnExpr(`SUM(CASE WHEN f.visibility = ? THEN 1 ELSE 0 END) > 0 AS "undisclosed"`,
			access.Private).
		ColumnExpr(`MIN(f.disclose_at) AS "disclose_at"`).
		// Both ends, because a group whose places disagree is mixed and a
		// minimum alone answers with one of the disagreeing values.
		ColumnExpr(`MIN(f.fix_state) AS "fix_state_least"`).
		ColumnExpr(`MAX(f.fix_state) AS "fix_state_most"`).
		ColumnExpr(`MIN(f.fixed_in) AS "fixed_in"`).
		ColumnExpr(`MIN(COALESCE(f.matched, '')) AS "matched"`).
		ColumnExpr(`MIN(f.target_id) AS "target_id"`).
		ColumnExpr(`MIN(f.consumer_id) AS "consumer_id"`).
		ColumnExpr(`COUNT(DISTINCT f.consumer_id) AS "consumers"`).
		ColumnExpr(`SUM(CASE WHEN f.consumer_id IS NULL THEN 1 ELSE 0 END) AS "direct"`).
		ColumnExpr(`0 AS "total"`)
	// The decision state of each, spelled once for every list
	// that asks (see decided.go). Across products the row names its own.
	body = decisionCounts(body, "st.product_id", nil,
		claimWaiting, claimApproved, claimLapsed, claimSentBack).
		Where("st.product_id IN (?)", bun.List(within)).
		Where("f.vulnerability_id IN (?)", bun.List(issues)).
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		GroupExpr(GroupedAcross)
	if err := body.Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read about what is open anywhere: %w", err)
	}

	type anyKey struct {
		product, vulnerability int64
		fold                   string
	}
	known := make(map[anyKey]int, len(rows))
	for i, row := range rows {
		known[anyKey{row.ProductID, row.VulnerabilityID, row.Fold}] = i
	}
	named, err := issuesNamed(ctx, s.db, issues)
	if err != nil {
		return nil, 0, err
	}
	// Each product's own rating of each of its issues. Keyed on the
	// pair, because this list spans products and one issue may be rated
	// differently in two of them — which is the whole reason a rating belongs
	// to a product.
	rated, err := RatingsIn(ctx, s.db, within, issues)
	if err != nil {
		return nil, 0, err
	}
	shipped, err := componentsNamed(ctx, s.db, components)
	if err != nil {
		return nil, 0, err
	}

	// The marks people put on these, in their own product's words. The
	// list is where a mark is for — the point of putting one on is finding the
	// work again — so a mark this list did not draw was one nobody saw, on the
	// screen somebody reaches before they have picked a product.
	wanted := make(map[acrossKey]bool, len(heads))
	for _, head := range heads {
		wanted[acrossKey{head.ProductID, head.VulnerabilityID, head.ComponentID}] = true
	}
	marks, err := s.tagsAcross(ctx, wanted, within, issues, components)
	if err != nil {
		return nil, 0, err
	}

	groups := make([]Group, 0, len(heads))
	for _, head := range heads {
		at, held := known[anyKey{head.ProductID, head.VulnerabilityID, head.Fold}]
		if !held {
			continue
		}
		row := rows[at]
		// The issue and the component come off the head rather than off the
		// row: this statement selects the product's own identifier at the
		// outer level, so the embedded row's copy of it is never filled.
		shape := row.decorated
		shape.VulnerabilityID, shape.ComponentID = head.VulnerabilityID, head.ComponentID
		group := groupFrom(shape, named, rated, shipped,
			// The line this row's own product states, or the deployment's
			// where it states none, and the product whose rating it is
			// compared against. One word chosen for a page that spans
			// products would answer for none of them, and neither would one
			// rating.
			Floor{Word: deployment, ProductID: head.ProductID})
		group.Product, group.ProductName = row.Product, row.ProductName
		// One build of possibly several, so a row has somewhere to link to and
		// an action has a build to name. What says there are others is the
		// count beside it.
		group.Builds, group.Stream, group.Variant = row.Builds, row.Stream, row.Variant
		group.Tags = marks[acrossKey{head.ProductID, head.VulnerabilityID, head.ComponentID}]
		groups = append(groups, group)
	}
	return groups, total, nil
}

// ratedAt is the rating in force, as a number that compares against a line.
//
// The words rank; the column holds words. Inside one product the line is read
// first and turned into a list of words the query admits, which cannot be done
// across products — each row's line is its own — so the comparison happens in
// SQL, in the order the one list states.
var ratedAt = rankCase(rating.BandExpr, 0)

// lineAt is the line the row's own product holds, as the same number. A
// product that states none inherits the deployment's, which is bound.
//
// Zero for anything that is not a band, which is what makes the sentinel for
// "no line" compare below every rating.
var lineAt = rankCase("COALESCE(NULLIF(p.triage_floor, ''), ?)", 0)

// sortedAcross is the ORDER BY the cross-product list is paged with.
//
// The same allowlist and the same expressions as the per-product list, with
// the product added to the tie-break: two rows equal on the sorted column must
// not swap between pages, and across products the pair that was enough is not
// — one issue in one component can be a row in a dozen products.
func sortedAcross(filter Filter) string {
	return orderedBy(filter, ByUrgency) + ", st.product_id, f.vulnerability_id, " + FoldedOn
}
