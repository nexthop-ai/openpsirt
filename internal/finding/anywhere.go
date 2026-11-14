// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// The findings list across every product somebody may see.
//
// The work starts from an issue as often as from a product. "Which of our
// products are carrying this, and what is running out anywhere" is one
// question across products. The issue page answers it for one issue; this
// answers it as a list, with filters, an order and paging.
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
	if len(filter.Beneath) > 0 {
		return nil, 0, refusal.Errorf("read findings beneath a component: a subtree is a walk over" +
			" one build's edges, and this list spans products")
	}
	limit = database.AList.Of(limit)
	if err := s.decidedIssuesFor(ctx, &filter, products, all); err != nil {
		return nil, 0, err
	}
	filter.Across = true
	filter.ProductID = 0
	filter.HeldBy = subject.Mine()
	filter.reader = subject
	// The store's clock, as a list within a product reads it.
	filter.now = s.now
	// All three are statements about a selection of builds, which this is not.
	filter.Builds = 0
	filter.DiffersBetweenBuilds = false
	filter.AcrossVariants = AnyVariants
	// The line is applied per product below rather than from the filter's one
	// word, so the filter's own is turned off — including its inverse, which
	// would otherwise ask for what is beneath a line that is not in the query.
	line := filter.MinimumSeverity
	filter.MinimumSeverity = MinimumSeverity{}
	wasBelow := filter.BelowMinimumSeverity
	filter.BelowMinimumSeverity = true

	// The deployment's line, which a product that states none inherits.
	deployment := NoMinimumSeverity
	if !wasBelow {
		var err error
		if deployment, err = deploymentMinimumSeverity(ctx, s.db); err != nil {
			return nil, 0, err
		}
	}
	// A caller may raise the line for the whole page — that is what the
	// severity control on the list does — but never lower it below what a
	// product decided, because the minimum severity is the product's decision. So the
	// raise is a second condition beside each product's own minimum severity, and a row
	// passes both: the higher of the two.
	raised := 0
	if !wasBelow && line.Hides() {
		raised = Ranks(line.Word)
	}

	// pastEOL is which releases are past their date, read once for the
	// page. This list spans products and resolves no build identifiers, so
	// the narrowing is a condition here rather than a narrowing of a target
	// list.
	pastEOL, err := filter.Workable.pastEOL(ctx, s.db, s.now().UTC())
	if err != nil {
		return nil, 0, err
	}

	// readable is the open occurrences this subject may read, in the releases
	// asked for, with the build and its branch or tag joined.
	readable := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = filter.Workable.where(q, pastEOL)
		kinds, kindArgs := kind.Triage.Where(`"f"."kind"`)
		q = q.TableExpr(`"finding" AS "f"`).
			Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
			Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
			Where(kinds, kindArgs...)
		held, heldArgs := openOn("f", filter.OpenOn)
		q = q.Where(held, heldArgs...)
		return onlyReadable(q, subject, products, all)
	}
	// withRating joins the issue and whatever the row's own product rates it: a
	// rating belongs to a product, so a list spanning them reads each row's
	// against the product that row is in.
	withRating := func(q *bun.SelectQuery, product rating.On) *bun.SelectQuery {
		return q.Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
			Join(rating.For(product))
	}
	// lined keeps what each row's own product's line admits, where somebody
	// is using one. urgent is how the statement says a row carries an
	// exploitation signal.
	//
	// Never below the line where somebody is using one, and being exploited
	// is not a claim about how bad something is — it is a fact, and the one
	// thing a line cannot set aside. Read off the urgency, whose two top bands
	// are the feed's word and this product's own incident (the
	// exploiting threshold).
	lined := func(q *bun.SelectQuery, urgent string, args ...any) *bun.SelectQuery {
		if wasBelow {
			return q
		}
		q = q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				WhereOr(urgent, args...).
				WhereOr(ratedAt+" >= "+lineAt, deployment)
		})
		if raised > 0 {
			q = q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
				return q.
					WhereOr(urgent, args...).
					WhereOr(ratedAt+" >= ?", raised)
			})
		}
		return q
	}
	// narrow is every condition on an occurrence, for the statement over the
	// page's own rows (see Filter.ofPage).
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = withRating(readable(q).
			Join(`JOIN "product" AS "p" ON "p"."id" = "st"."product_id"`), rating.OnBranchOrTag).
			// And the component, for the fold: two binaries of one source
			// package carrying one issue are one row here as they are on the
			// per-product list, because they are one thing to decide about.
			Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`)
		return filter.ofPage(lined(q, `"f"."urgency" >= ?`, int64(exploiting)))
	}
	// grouped is the page's grouping in two levels (see twolevel.go). The first
	// groups each product's occurrences by issue and component, and by whether
	// they carry an exploitation signal, which is the one thing about an
	// occurrence the line reads; the second reads the issue, its rating and the
	// product's line once per partial group rather than once per occurrence,
	// keeps what the line admits, and groups on the fold. A partial group is
	// wholly on one side of the line, so everything counted after it is counted
	// over exactly the occurrences the one-level statement admits.
	grouped := func() *bun.SelectQuery {
		rows := readable(s.db.NewSelect())
		// A condition on the rating in force is asked of each occurrence, so
		// where one is asked the rating is joined below the grouping as well.
		if len(filter.severities()) > 0 || filter.Reassessed {
			rows = withRating(rows, rating.OnBranchOrTag)
		}
		hot := `CASE WHEN "f"."urgency" >= ? THEN 1 ELSE 0 END`
		keys := []partKey{
			{expr: `"st"."product_id"`, name: "product_id"},
			{expr: `"f"."vulnerability_id"`, name: "vulnerability_id"},
			{expr: `"f"."component_id"`, name: "component_id"},
		}
		if !wasBelow {
			keys = append(keys, partKey{expr: hot, args: []any{int64(exploiting)}, name: "hot"})
		}
		q := filter.folded(s.db, rows, keys)
		by, known := order[filter.SortBy]
		if !wasBelow || (known && by.issue) {
			q = withRating(q, rating.OnPartial)
		}
		if !wasBelow {
			q = q.Join(`JOIN "product" AS "p" ON "p"."id" = "f"."product_id"`)
		}
		return lined(q, "f.hot = ?", 1).GroupExpr(`"f"."product_id", ` + GroupedOn)
	}

	var heads []struct {
		ProductID       int64  `bun:"product_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Fold            string `bun:"fold"`
		ComponentID     int64  `bun:"component_id"`
		Occurrences     int    `bun:"places"`
		Urgency         int64  `bun:"urgency"`
		Total           int    `bun:"total"`
	}
	// Read through paged, as the per-product page is, because the filter
	// decides what the HAVING holds. The product is in the tie-break: two rows
	// equal on the sorted column must not swap between pages, and across
	// products one issue in one component can be a row in a dozen products.
	key, sorted := pagedOrder(filter, "product_id", "vulnerability_id", "fold")
	page := grouped().
		ColumnExpr(`"f"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(FoldedOn + ` AS "fold"`).
		ColumnExpr(`MIN("f"."component_id") AS "component_id"`).
		ColumnExpr(overParts.occurrences() + ` AS "places"`).
		ColumnExpr(overParts.peak() + ` AS "urgency"`)
	if key != "" {
		page = page.ColumnExpr(key + ` AS "sort_key"`)
	}
	if err := paged(s.db, page, "product_id", "vulnerability_id", "fold", "component_id",
		"places", "urgency").OrderExpr(sorted).
		Limit(int64(limit)).Offset(int64(offset)).Scan(ctx, &heads); err != nil {
		return nil, 0, fmt.Errorf("read what is open anywhere: %w", err)
	}
	total := 0
	if len(heads) > 0 {
		total = heads[0].Total
	} else {
		var err error
		if total, err = s.countGroups(ctx, grouped()); err != nil {
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
		BranchOrTag     string `bun:"branch_or_tag"`
		Variant         string `bun:"variant"`
		Builds          int    `bun:"builds"`
		decorated
	}
	body := groupDecorations(narrow(s.db.NewSelect()).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`MIN("p"."name") AS "product"`).
		ColumnExpr(`MIN(` + catalog.ShownExpr("p") + `) AS "product_name"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(FoldedOn + ` AS "fold"`).
		ColumnExpr(`MIN("st"."name") AS "branch_or_tag"`).
		ColumnExpr(`MIN("va"."name") AS "variant"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`MAX("f"."urgency") AS "urgency"`).
		// The two exploitation flags, which the packed number above cannot
		// tell apart. A column this query does not select is left at its zero
		// value, so both are selected here as on the per-product list.
		ColumnExpr(exploitedAcross + ` AS "exploited"`).
		ColumnExpr(incidentAcross + ` AS "incident"`).
		ColumnExpr(`0 AS "total"`))
	// The decision state of each, spelled once for every list
	// that asks (see decided.go). Across products the row names its own.
	body = decisionCounts(body, `"st"."product_id"`, nil,
		decisionWaiting, decisionApproved, decisionLapsed, decisionSentBack).
		Where(`"st"."product_id" IN (?)`, bun.List(within)).
		Where(`"f"."vulnerability_id" IN (?)`, bun.List(issues)).
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
	named, err := issuesNamed(ctx, s.db, subject, issues)
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
	// Each row is named as the build it links to stated it.
	pageBuilds := make([]int64, 0, len(rows))
	for _, row := range rows {
		pageBuilds = append(pageBuilds, row.BuildID)
	}
	shipped, err := componentsNamed(ctx, s.db, components, pageBuilds)
	if err != nil {
		return nil, 0, err
	}

	// The marks people put on these, in their own product's words. The
	// list is where a mark is for — the point of putting one on is finding the
	// work again — so a mark this list did not draw was one nobody saw, on the
	// screen somebody reaches before they have picked a product.
	wanted := make(map[acrossKey]bool, len(heads))
	for _, head := range heads {
		wanted[acrossKey{head.ProductID, head.VulnerabilityID, head.Fold}] = true
	}
	marks, err := s.labelsAcross(ctx, subject, products, all, wanted)
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
			MinimumSeverity{Word: deployment, ProductID: head.ProductID})
		group.Product, group.ProductName = row.Product, row.ProductName
		// One build of possibly several, so a row has somewhere to link to and
		// an action has a build to name. What says there are others is the
		// count beside it.
		group.Builds, group.BranchOrTag, group.Variant = row.Builds, row.BranchOrTag, row.Variant
		group.Labels = marks[acrossKey{head.ProductID, head.VulnerabilityID, head.Fold}]
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
var lineAt = rankCase(`COALESCE(NULLIF("p"."minimum_severity", ''), ?)`, 0)
