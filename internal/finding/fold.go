package finding

import "github.com/uptrace/bun"

// What a fold is, in SQL.
//
// The binary packages one source package was built at one version are one
// thing to a person: curl, libcurl4t64 and libcurl3t64 are one bump, and
// treating them as three is three acts that can disagree. `fold_key` on the
// component is that grouping, written once as the scan is applied — see the
// graph package for what goes into it and why the source package's name alone
// is not enough.
//
// This file holds the two expressions that read a fold *back* into words. They
// are spelled once here because they were spelled six times across four files,
// and a key that is spelled twice is a key that comes apart.

// FoldedOn is the grouping, over a component joined as "c".
//
// It replaces the source-package expression these queries used to group by.
// That expression could not see three of the collisions a real image contains:
// one source shipped at two versions in one build, and two ecosystems using
// one word for different packages.
const FoldedOn = "c.fold_key"

// GroupedOn is the grain the findings list, its hidden count and its
// cross-product form all group by: one issue at one fold.
//
// Spelled once because the empty-page fallback grouped one step finer than
// the page it belongs to, and the figure above the list then changed
// depending on which page was being looked at. The grain of a page and the
// grain of the number above it are one fact, and it was written out at five
// sites by hand.
const GroupedOn = "f.vulnerability_id, " + FoldedOn

// GroupedAcross is the same grain across products, where a row is an issue at
// a fold in one product.
const GroupedAcross = "st.product_id, " + GroupedOn

// SourceName and SourceVersion are what a fold is called and what it is at:
// what the producer said the component was built from, and the component's own
// where it said nothing.
//
// Read with an aggregate rather than grouped on. They are what the fold key
// was derived from, so they do not vary within a fold in any way a person can
// see — but the key folds capitals and the column does not, so grouping on
// them as well could split a fold that two producers spelled differently.
const (
	SourceName = `CASE WHEN COALESCE(c.upstream_name, '') <> '' THEN c.upstream_name
		ELSE c.name END`
	// The two fall back independently, which is the rule
	// ComponentUpstreamExpr already applies to the version a decision expires
	// on. One fold and one expiry disagreeing about which version a component
	// is at is the shape worth not having.
	SourceVersion = `CASE WHEN COALESCE(c.upstream_version, '') <> ''
		THEN c.upstream_version ELSE c.version END`
)

// PerFold puts one of those expressions under an aggregate, for a query that
// groups on the fold. MIN rather than MAX for no reason beyond having to pick
// one: within a fold every row answers the same.
func PerFold(expression string) string { return "MIN(" + expression + ")" }

// InTheFoldOf narrows to every finding in the fold the named component belongs
// to, for a query over finding AS "f" that joins component AS "c".
//
// The unit a judgment covers, and the unit the finding screen's rows already
// use. Three things reported beside those rows — who holds it, which rule
// placed it, what it is tagged with — asked about one component instead, so a
// guarantee written as "one name for the whole group, and empty where its
// places disagree" was a guarantee about a group the query could not see: a
// rule that placed a third of a fold reported as no rule at all under one
// name and as the whole thing under another.
func InTheFoldOf(q *bun.SelectQuery, componentID int64) *bun.SelectQuery {
	return q.Join(`JOIN component AS "c" ON c.id = f.component_id`).
		Where(FoldedOn+` = (SELECT "c2".fold_key FROM "component" AS "c2" WHERE "c2".id = ?)`,
			componentID)
}
