package finding

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
