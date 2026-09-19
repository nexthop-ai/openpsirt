package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// The narrowing applied to a list before it is paged.
//
// Every filter the findings list offers, and the one expression each becomes.
// Narrowing belongs here rather than in whatever displays the result: a filter
// applied to a page that has already been fetched answers a different question
// from the one it appears to — "exploited" over fifty rows means exploited
// among those fifty — and it makes the total meaningless, which is the number
// people quote.
//
// It already had its own test file, narrow_test.go, which is what says this
// seam is real rather than a line count.

// SortKey is a column somebody may order the findings list by.
//
// **An allowlist, and the allowlist is the only thing that reaches the
// statement**. A placeholder cannot bind a column name, so a sort
// column arriving from a query parameter is the one value that must reach the
// SQL text — which makes it the live hole in a codebase that parameterizes
// everything else. Nothing here is built from what a caller
// typed: a key that is not one of these is not a sort, and the answer is the
// default order rather than an error, because an unknown sort is a caller's
// mistake about a list rather than a refusal to show it.
//
// It is also what keeps a sort from exposing a column nobody was meant to
// order by, which is a quieter version of the same problem.
type SortKey string

const (
	// ByUrgency is the default and the one the list is designed around: what
	// somebody with an hour should look at first.
	ByUrgency SortKey = "urgency"
	// ByAge is how long this has been open here, which is the age a deadline
	// relates to.
	ByAge SortKey = "age"
	// ByDeadline is when it runs out. Findings with none sort last whichever
	// direction is asked for: "no deadline" is not early and not late.
	ByDeadline SortKey = "deadline"
	// ByPlaces is how far it reaches, which is what says whether one judgment
	// answers a lot or a little.
	ByPlaces SortKey = "places"
	// ByLikelihood is the published estimate that it will be exploited, which
	// ranks above severity and is how a batch of "worth doing now" is built.
	ByLikelihood SortKey = "epss"
	// BySeverity is the rating in force, as the number the ordering compares
	// rather than the word.
	BySeverity SortKey = "severity"
)

// order is the expression each key sorts by, and whether it needs the issue
// joined. Keyed by the constant rather than by a string a caller supplies:
// what reaches the statement is this map's value, never its lookup.
var order = map[SortKey]struct {
	expr  string
	issue bool
}{
	ByUrgency:    {expr: "urgency"},
	ByAge:        {expr: "MIN(f.opened_at)"},
	ByDeadline:   {expr: "MIN(f.due_at)"},
	ByPlaces:     {expr: "places"},
	ByLikelihood: {expr: "MAX(COALESCE(v.likelihood_ppm, 0))", issue: true},
	BySeverity:   {expr: "MAX(COALESCE(v.score_centi, 0))", issue: true},
}

// orderedBy is what an asked-for key sorts by, with the direction applied and
// nothing else — the tie-break that makes paging stable differs per list and
// is the caller's to append.
//
// One builder rather than one per list. Three lists sort on the same six keys
// and each had written out the same lookup, the same direction and the same
// null-last case, so a key that behaved differently on one of them was a
// difference nobody could see.
//
// The expression comes from the allowlist and never from the request. A
// caller's key that is not in it falls back to the one named here, which is
// each list's own default rather than a shared one.
//
// A finding with no deadline sorts last whichever way it is asked, because "no
// deadline" is not early and not late. That is spelled as a leading
// null-ordering column rather than as NULLS LAST, which two of the four
// engines do not have.
func orderedBy(filter Filter, fallback SortKey) string {
	by, known := order[filter.SortBy]
	if !known {
		by = order[fallback]
	}
	return directed(by.expr, filter.SortBy == ByDeadline, filter.Ascending)
}

// directed applies a direction to an expression the allowlist supplied, and
// puts what has no value last where the expression can have none.
//
// Sorting nothing last is spelled as a leading null-ordering column rather
// than as NULLS LAST, which two of the four engines do not have.
func directed(expr string, nothingLast, ascending bool) string {
	way := "DESC"
	if ascending {
		way = "ASC"
	}
	sorted := expr + " " + way
	if nothingLast {
		sorted = "CASE WHEN " + expr + " IS NULL THEN 1 ELSE 0 END, " + sorted
	}
	return sorted
}

// SortKeys are the orders somebody may ask for, in the order they are offered.
//
// One list. The query parameter's enum is built from this at registration and
// the interface's own union is generated from the document that enum produces,
// so an order added here is offered and an order removed here is refused —
// rather than the three agreeing because a test says they do. It said it was
// the one list while nothing but a test called it, which is the shape this
// exists to stop.
//
// The map above is keyed rather than ordered, which is why the ordering is
// written once here instead of being read back out of it.
func SortKeys() []SortKey {
	return []SortKey{ByUrgency, ByAge, ByDeadline, ByPlaces, ByLikelihood, BySeverity}
}

// Filter narrows what is open before it is paged.
//
// Narrowing belongs here rather than in whatever is displaying the result. A
// filter applied to a page that has already been fetched answers a different
// question from the one it appears to: "exploited" over fifty rows means
// exploited among those fifty, and paging with one on walks a different
// arbitrary subset each time. It also makes the total meaningless, which is the
// number people quote.
type Filter struct {
	// BundleSort is which order the fix-bundle list pages in, and is read by
	// that list alone: a bundle is a bump rather than a finding, so what it is
	// worth ordering by — how many issues it closes, how many builds hold it —
	// has no meaning on a list of findings, and the six the findings list
	// takes do not all have one on a bump. The direction below is shared.
	BundleSort BundleSortKey
	// MinSeverity keeps issues rated at this word or worse. Empty — or "low",
	// which excludes nothing — keeps everything, including issues carrying no
	// rating at all.
	MinSeverity string
	// Exploited keeps only issues somebody is known to be exploiting.
	Exploited bool
	// HasFix keeps only issues where an upstream fixed version is known, which
	// is the set where the answer is to take a version rather than to judge.
	HasFix bool
	// Components keeps only what is open against components of these
	// names. Matched by name and not by version, because "what is wrong
	// with openssl here" is a question about the package rather than about
	// one build of it, and a build that vendors it twice should answer
	// with both. Several names because a person reading a family of
	// packages reads them together, and one at a time is the same list
	// read three times.
	Components []string
	// Floor is what this product considers worth triaging, and BelowFloor
	// asks to see what it keeps out. The line is policy rather than
	// preference — somebody set it once for everybody — which is why what
	// it hides is counted and said rather than silently subtracted (the
	// line a deployment triages at, a list saying what it hid).
	Floor      Floor
	BelowFloor bool
	// Workable keeps the releases work can land in: which sort of release,
	// and whether it is still in support. Two questions kept apart, because
	// a tag can be in support and a branch can be past end-of-life.
	//
	// Applied where the builds are resolved rather than as a condition on
	// every row: the list reads its page from an index that leads with the
	// build, and joining the catalog into that statement would make the
	// engine reach a row to discover what it already knew from the key.
	Workable Workable
	// SortBy is which column to order by and Ascending which way. Empty sorts
	// by urgency, which is what the list is designed around. A key that is not
	// in the allowlist is not a sort and falls back to the same.
	SortBy    SortKey
	Ascending bool
	// Search keeps rows whose component name **or issue name** contains
	// this, without regard to capitals. It is how somebody finds a package
	// in a list of thousands, where Component above is the exact name and
	// answers a different question: "show me openssl" against "show me
	// anything ssl-ish".
	//
	// **The issue half is what an advisory landing actually asks for.** The
	// first question a PSIRT is asked is "where is CVE-2026-9079 in what we
	// ship", and matching component names alone answered nothing at all for
	// it — the box said it searched issues and returned an empty list, which
	// reads as "we do not ship it".
	//
	// Aliases count. An issue is one thing under several names, so
	// searching the name a reporter used has to reach the row filed under
	// the name a scanner used, or the answer depends on which feed got
	// there first.
	//
	// Matched here rather than in the browser for the reason every other
	// filter is: a search applied to the fifty rows already fetched
	// searches those fifty, and the total beside it would count something
	// else.
	Search string
	// Across says this query spans products, so the clauses keyed on one
	// product correlate on the row's own product instead of binding a number.
	// Set by the store rather than by a caller, for the same reason ProductID
	// is: a filter that said it spanned products while the query did not join
	// one would reach decisions made anywhere in the deployment.
	Across bool
	// ProductID is which product the query narrows inside, set by the store
	// rather than by a caller. A place identity carries no product, so
	// anything correlating a place to a decision has to supply one or it
	// matches every product in the deployment.
	ProductID int64
	// Ecosystems keeps components of these package kinds — deb, golang,
	// pypi. Read from the package identifier rather than stored beside it,
	// because the identifier is what says it and a second copy is a second
	// thing to keep true.
	//
	// It is the closest thing the data has to "userland and not the rest":
	// a kernel and its modules are Debian packages, a statically linked
	// service is Go, and somebody triaging one is usually not triaging the
	// other — which is a question about two or three kinds at once as
	// readily as one, so it is a set.
	Ecosystems []string
	// Under keeps what sits inside one container, by its name. UnderTheBuild
	// asks for the other case: what the build holds directly, which has no
	// consumer to name.
	Under         string
	UnderTheBuild bool
	// DeclaredAs keeps what a producer scoped one of these ways — "excluded",
	// "build", "optional". It is the only way to ask about the largest
	// defensible deferral class a vendor has, and it is a question rather than
	// an answer: nothing ranks by it, nothing prefills an outcome from it, and
	// nothing is hidden by it unless somebody asks for it here.
	//
	// **Asked of the component's incoming edges in the build, not of the
	// place.** A component reached from two consumers scoped differently
	// answers to both words, because the pair of columns a place is cannot be
	// compared against a set the same way on four engines. What it costs is
	// stated where the filter is: it is a question about a component in a
	// build rather than about one route to it.
	DeclaredAs []string
	// Beneath keeps what sits at a component or anywhere under it, by the
	// component's identifier: the same walk over the build's edges the
	// dependency tree's cumulative count makes, so the number the tree draws
	// and the list it opens agree. Nil is no narrowing.
	Beneath *int64
	// TargetID is which build the query is over, set by the store rather than
	// by a caller, for the same reason ProductID is: the walk beneath a
	// component is a walk over one build's edges.
	TargetID int64
	// State keeps groups by how far they have been decided. A group is an
	// issue in a component across every place it sits, and its places can
	// be in different states, so what a group's state *is* had to be
	// chosen:
	//
	//   undecided  no place has a decision of any kind
	//   waiting    a claim stands proposed at a place and nobody has agreed
	//   agreed     every place is answered by a standing decision
	//   lapsed     a decision here stopped applying and nothing replaced it
	//
	// Partly answered is deliberately not a state of its own: the row
	// already says "12 places · 3 answered", which is the more useful form
	// of the same fact, and a fifth word would be a filter for a number
	// people can read.
	//
	// **A set rather than one word.** "Undecided or waiting on approval" is
	// the working list of a triager who wants everything not yet settled, and
	// a single value could not ask it.
	States []string
	// Outcomes keeps groups a standing decision of one of these kinds covers —
	// the way to ask "what have we dismissed", which States cannot answer:
	// "agreed" says a judgment stands, not which judgment. Read against what
	// stands now, so a dismissal withdrawn last year does not answer for its
	// place.
	Outcomes []string
	// Assigned keeps groups by who is dealing with them: "me", "somebody"
	// or "nobody". A findings list that cannot say "mine" makes somebody
	// go to a second screen to find the work they already know is theirs.
	// Several, because "mine and whatever nobody has picked up" is one
	// question about a morning.
	Assigned []string
	// HeldBy is what "me" means: this subject's own name in the assignable
	// space and every team they are on, set by the store from the subject
	// rather than
	// by a caller — for the same reason ProductID is: a caller supplying it
	// could ask for somebody else's while saying "mine".
	HeldBy []int64
	// now is the store's clock, set where the store narrows. What the
	// deadline filters compare against, so that a frozen clock reaches them
	// and so that one request answers "is this overdue" and "is anything off
	// the clock" from the same moment.
	now func() time.Time
	// Reassessed keeps groups whose issue we rated differently from the
	// world. It is how somebody finds what has been re-prioritized here,
	// which is a question auditors ask and nothing else answers.
	Reassessed bool
	// Unconfirmed keeps groups a scanner reached only by comparing a published
	// identifier against an upstream version range, never against an advisory
	// for the package in its own ecosystem.
	//
	// This is the question somebody asks about a distribution's packages and
	// nothing else answers: a distribution backports fixes without moving the
	// upstream version, so busybox 1.37.0-r14 and 1.37.0-r15 are the same
	// release to an upstream range and one of them may carry the patch. These
	// are neither confirmed nor refuted — somebody has to look — and finding
	// them one at a time is not a thing anybody does.
	Unconfirmed bool
	// Exclude drops components of these names.
	//
	// This exists because one package can drown the list. Measured on a
	// switch operating-system image: 4,943 of 6,822 rows — 72% — were the
	// kernel, and the next largest contributor had 58. Hiding it is not a
	// preference about tidiness, it is the difference between a list
	// somebody reads and one they scroll past. What makes it safe is that
	// the total says so too: hiding is narrowing, and narrowing is
	// counted.
	Exclude []string
	// The filters a triager reaches for when assembling a batch.
	//
	// LikelihoodAtLeast keeps issues the published estimate rates at least
	// this likely to be exploited, in parts per million — the same unit
	// the row carries, so the screen and the filter compare the same
	// number.
	LikelihoodAtLeast int
	// OpenedBefore keeps what has been open here since before a moment,
	// which is how "everything older than a month" is asked. The finding's
	// own age, never the year in its identifier.
	OpenedBefore *time.Time
	// DueBefore keeps what runs out before a moment, and Overdue what already
	// has. Both read the deadline stored on the row, so the list and the
	// running-out report cannot disagree about what is late.
	DueBefore *time.Time
	Overdue   bool
	// FixStates keeps only what upstream has done one of these things
	// about. HasFix above is the same question asked as a flag and is kept
	// because it is what the screen's own control has always sent; this
	// answers the two it cannot — nothing released, and upstream declining
	// to fix, which is the population that needs a judgment rather than a
	// bump. Those two are one question asked together often enough that a
	// single value could not ask it.
	FixStates []FixState
	// Weaknesses keeps issues of these kinds of flaw, by CWE identifier. A
	// class of flaw is usually several identifiers — the memory-safety ones,
	// the injection ones — so one at a time is the wrong grain for the
	// question people ask with it.
	Weaknesses []string
	// Origin keeps only what a person entered here, or only what a scanner
	// reported. Empty asks for both.
	//
	// A word rather than a flag, because the question has three answers and a
	// flag has two: the screen offered "Scanner" and could only send the
	// absence of "entered by hand", so choosing it was indistinguishable from
	// choosing nothing while the panel went on showing it as chosen.
	Origin Origin
	// Planned keeps or drops what a promised upgrade covers.
	//
	// **Derived, never stored.** A finding is covered when a standing
	// `upgrade-needed` decision reaches it, which the decision already
	// records — so the mark is a join rather than a tag written across every
	// row an upgrade touches. A tag would be per product and could not say
	// "planned on master, not on 2.4", which is the case the whole per-build
	// target exists for.
	//
	// Three states rather than two, because "show me what is not planned"
	// is the working list once planning suppresses, and a bool cannot ask
	// it.
	Planned PlannedFilter
	// Tags keeps only what somebody marked with one of these words.
	// Matched folded, the way every other name people type is, so
	// "Waiting" and "waiting" are one tag rather than half an answer each.
	// Any of them rather than all of them: the words are a person's own
	// filing, and asking for two of somebody's labels means "either pile".
	Tags []string
	// SentBack keeps groups where a live claim is with its author, which is
	// the row a proposer is looking for and cannot ask for today.
	SentBack bool
	// DiffersBetweenBuilds keeps groups that are open in some builds of the
	// selection and not others — the rows a comparison is about. Meaningless
	// where the selection is one build, and ignored there rather than
	// answering nothing.
	DiffersBetweenBuilds bool
	// Builds is how many builds the selection holds, which is what
	// DiffersBetweenBuilds is measured against. Set by whoever resolved the
	// selection, because the filter cannot see it.
	Builds int
	// Publishers keeps only what a named VEX publisher has a statement
	// about, and VexStatus only what that statement says. Being able to
	// find that population is the point of taking the documents at all: on
	// a real image 1,113 of 1,125 no-fix findings are distribution
	// packages, and a distribution publishes machine-readable judgments
	// about exactly those. Found they are an afternoon; unfound they are
	// retyped one at a time.
	Publishers []string
	VexStatus  []string
	// OpenedAfter, ClosedAfter and ProposedAfter keep only what happened
	// after a moment. An operational convenience with no compliance claim
	// attached, which is the honest description of it: it is what the
	// `as_of` register the disposition register refuses was really being
	// reached for, at a fraction of the cost and without pretending to
	// reconstruct a day.
	OpenedAfter   *time.Time
	ClosedAfter   *time.Time
	ProposedAfter *time.Time
	// OpenedByRun keeps only what one scan run opened. A run says how much it
	// opened and at what severities, and the list it says that about could not
	// be reached: somebody looking at a build that jumped by four thousand
	// overnight is asking which of them matter, and "opened after a date" is
	// the wrong question when two runs landed the same day.
	OpenedByRun int64
}

// product is how a clause names the product a row belongs to: a bound number
// inside one product, and the row's own column across them.
//
// Returned with its argument rather than as a string alone, so a caller cannot
// build the fragment and forget the value that goes with it.
func (f Filter) product() (string, []any) {
	if f.Across {
		return "st.product_id", nil
	}
	return "?", []any{f.ProductID}
}

// severities returns the words a floor admits, or nil where it admits all of
// them and the filter should not be applied at all.
func (f Filter) severities() []string {
	// Compared without regard to capitals, like every other name somebody
	// types. Compared exactly, a caller sending "High" matched no word and
	// got no narrowing at all rather than a refusal — the filter silently
	// did nothing.
	wanted := strings.ToLower(strings.TrimSpace(f.MinSeverity))
	for i, word := range ranked {
		if word == wanted {
			if i == 0 {
				return nil
			}
			return ranked[i:]
		}
	}
	return nil
}

// narrow applies the filter to a grouped query over finding AS f.
//
// Nothing here needs vulnerability or component joined. Every condition on
// what an issue is rated or what a component is called is asked as a
// membership test against the table that holds the answer — "issues rated at
// least high", "components named openssl" — so the query being narrowed can
// walk finding's covering index and touch nothing else. The joins were the
// first version, and they were what put a row lookup behind every one of a
// build's open findings on every page: the engine had to read the row to
// find the key to join on, whether or not any filter used the joined table.
//
// Severity is a condition on a row and the fix is a condition on the group,
// so they land in different clauses. Putting either in the other place is
// wrong rather than slow: a fix known at one place and not another would drop
// the places that lack it out of the count, and a group would report a size
// smaller than it is.
func (f Filter) narrow(q *bun.SelectQuery) *bun.SelectQuery {
	if words := f.severities(); len(words) > 0 {
		// The rating in force here, not the published one. Being able to say
		// a published rating is wrong is pointless if the filter then ignores
		// us: a finding reassessed from low to critical had its urgency and
		// its deadline moved and then disappeared from the list it was now
		// at the top of. The same expression the floor and the deadline
		// compare, so the three cannot come to disagree.
		if f.Across {
			// A list spanning products joins each row's own product's rating
			// already, so the condition is asked of the row. Asked as a set
			// of issues there is no one set: an issue rated critical in one
			// product and low in another belongs to both answers.
			q = q.Where(rating.EffectiveExpr+" IN (?)", bun.List(words))
		} else {
			q = q.Where("f.vulnerability_id IN (?)",
				q.NewSelect().TableExpr(`"vulnerability" AS "v"`).
					Join(rating.Here, f.ProductID).
					Column("v.id").
					Where(rating.EffectiveExpr+" IN (?)", bun.List(words)))
		}
	}
	if f.Exploited {
		// Read off the urgency rather than the flag beside it. A place known
		// to be exploited ranks in a band of its own above everything else
		// (Ranked.Rank), and the urgency is in the index the grouping walks
		// where the flag is not.
		q = q.Having("MAX(f.urgency) >= ?", int64(exploitedBand))
	}
	if f.HasFix {
		// Unanimity, like the fix-state filter below, which the documentation
		// above calls the same question asked as a flag. A minimum skips
		// nulls, so one place with a fixed version admitted the whole group —
		// and a fold covering a package with a fix and one without answered
		// yes to this, no to fix_state=fixed and yes to fix_state=mixed:
		// three answers to one question.
		q = q.Having("MIN(f.fixed_in) IS NOT NULL AND MIN(f.fixed_in) <> ?"+
			" AND COUNT(*) = SUM(CASE WHEN f.fixed_in IS NULL OR f.fixed_in = ? THEN 0 ELSE 1 END)",
			"", "")
	}
	if f.Unconfirmed {
		// One place answers for the group. A group is an issue at a component,
		// every place of it comes from the same line of a scanner's report,
		// and the applier writes that line to all of them — so they cannot
		// disagree, and an aggregate guarding against it would be a condition
		// nothing can make false.
		q = q.Having("MIN(f.matched) = ?", ByIdentifier)
	}
	if names := trimmed(f.Components); len(names) > 0 {
		q = q.Where("f.component_id IN (?)",
			componentsWhere(q, "c.name IN (?)", bun.List(names)))
	}
	// Lowered on both sides rather than asked to compare loosely: the
	// engines do not agree on what a case-insensitive comparison is, and
	// one that is spelled the same way everywhere behaves the same way
	// everywhere.
	if term := strings.TrimSpace(f.Search); term != "" {
		like := "%" + containsTerm(term) + "%"
		// Either side matches. A person typing into one box does not say
		// which of the two they mean, and an identifier cannot be mistaken
		// for a package name in practice.
		q = q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				WhereOr("f.component_id IN (?)",
					componentsWhere(q, "c.name_folded LIKE ?"+database.LikeClause, like)).
				WhereOr("f.vulnerability_id IN (?)",
					q.NewSelect().TableExpr(`"vulnerability" AS "v"`).Column("v.id").
						Where("LOWER(v.identifier) LIKE ?"+database.LikeClause, like)).
				WhereOr("f.vulnerability_id IN (?)",
					q.NewSelect().TableExpr(`"vulnerability_alias" AS "va"`).
						Column("va.vulnerability_id").
						Where("LOWER(va.identifier) LIKE ?"+database.LikeClause, like))
		})
	}
	if names := trimmed(f.Exclude); len(names) > 0 {
		q = q.Where("f.component_id NOT IN (?)",
			componentsWhere(q, "c.name IN (?)", bun.List(names)))
	}
	if kinds := trimmed(f.Ecosystems); len(kinds) > 0 {
		// One subquery holding an OR rather than one per kind, because a
		// component has one identifier and is of one kind: asking for two
		// kinds as two IN clauses is asking a component to be both.
		where := q.NewSelect().TableExpr(`"component" AS "c"`).Column("c.id")
		where = where.WhereGroup(" AND ", func(g *bun.SelectQuery) *bun.SelectQuery {
			for _, kind := range kinds {
				g = g.WhereOr("LOWER(c.purl) LIKE ?"+database.LikeClause, "pkg:"+containsTerm(kind)+"/%")
			}
			return g
		})
		q = q.Where("f.component_id IN (?)", where)
	}
	// The producer's own name for it. Correlated on the build rather than bound
	// to one, so the cross-product list can ask it too, and the leading column
	// of the statement is the one the edge index leads with.
	if words := trimmed(f.DeclaredAs); len(words) > 0 {
		q = q.Where("f.component_id IN (?)",
			q.NewSelect().
				TableExpr(`"graph_edge" AS "ge"`).
				Join(`JOIN "graph_node" AS "gch" ON gch.id = ge.child_id`).
				ColumnExpr(`gch.component_id`).
				Where("ge.target_id = f.target_id").
				Where("ge.closed_scan_id IS NULL").
				Where("ge.kind IN (?)", bun.List(words)))
	}
	// The component holding it. A place records the one that pulls it in, so asking
	// what is inside a container is asking for places whose consumer is that
	// container — and what the build holds directly is the places with none.
	if f.UnderTheBuild {
		q = q.Where("f.consumer_id IS NULL")
	} else if under := strings.TrimSpace(f.Under); under != "" {
		q = q.Where("f.consumer_id IN (?)", componentsWhere(q, "c.name = ?", under))
	}
	// The party dealing with it. Set for the whole group at once, so a group is
	// held when its places are — asked as MIN and MAX rather than as one row,
	// because a group whose places disagree is not "mine" and saying so would
	// hand somebody work that is half theirs.
	// Several answers OR together, and each keeps its own meaning inside the
	// OR — which is why they are assembled as one condition rather than
	// applied one at a time. Applied one at a time they would AND, and "mine
	// or nobody's" would be a list of nothing.
	q = f.heldBy(q)
	// This product's own word on the issue, as against what was published. A
	// rating of its own is the record of a priority somebody changed here —
	// and a rating another product made is not, which is why the set is keyed
	// on the product rather than on the issue alone.
	if f.Reassessed {
		if f.Across {
			q = q.Where("ir.severity IS NOT NULL")
		} else {
			q = q.Where("f.vulnerability_id IN (?)",
				q.NewSelect().TableExpr(`"issue_rating" AS "ir"`).
					Column("ir.vulnerability_id").
					Where("ir.product_id = ?", f.ProductID))
		}
	}
	// An uploaded VEX document's statement about this, matched the way a
	// finding's own screen matches it: on the component's name and on every
	// name the issue is known by, because which identifier a publisher chose
	// is a preference of whichever database they consulted.
	//
	// **Resolved once and joined, never asked per row.** This was a correlated
	// EXISTS over three subqueries, evaluated for every candidate finding: on
	// a demo image of 281,884 findings it did not return inside five minutes
	// and it held a core for minutes after the request was abandoned, which
	// made every other request on the deployment look broken too. There are
	// far fewer statements than findings — 1,854 against 281,884 on that same
	// image — so the cheap direction is to work out which (component, issue)
	// pairs the statements name, once, and join the list to that. The same
	// answer arrives in 0.27s.
	//
	// **Distinct on the pair**, by UNION rather than UNION ALL, so joining
	// cannot multiply a finding by the number of statements about it — a
	// filter that changed the counts it narrows would be worse than a slow
	// one.
	q = f.sayingIt(q)
	if f.OpenedAfter != nil {
		q = q.Having("MIN(f.opened_at) > ?", *f.OpenedAfter)
	}
	if f.OpenedByRun > 0 {
		// A row-level condition rather than one over the group: a group is in
		// the list when any of its places was opened by that run, which is
		// what "what this run opened" means — one issue at a component can
		// appear at a place this run found and at forty it did not.
		q = q.Where("f.opened_run_id = ?", f.OpenedByRun)
	}
	if f.ClosedAfter != nil {
		// Closed rows are outside the list's own population, so this is the
		// one filter that changes what the list is about rather than
		// narrowing it. The caller says so by asking for it.
		q = q.Having("MAX(f.closed_at) > ?", *f.ClosedAfter)
	}
	if f.ProposedAfter != nil {
		q = q.Where(`EXISTS (SELECT 1 FROM "decision" AS "de"
			WHERE de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND de.proposed_at > ?)`, *f.ProposedAfter)
	}
	if f.LikelihoodAtLeast > 0 {
		q = q.Where("f.vulnerability_id IN (?)",
			q.NewSelect().TableExpr(`"vulnerability" AS "v"`).Column("v.id").
				Where("COALESCE(v.likelihood_ppm, 0) >= ?", f.LikelihoodAtLeast))
	}
	if f.OpenedBefore != nil {
		// The oldest place decides: a group open here for a month with one
		// place added yesterday has been somebody's problem for a month.
		q = q.Having("MIN(f.opened_at) < ?", *f.OpenedBefore)
	}
	if f.Overdue {
		q = q.Having("MIN(f.due_at) IS NOT NULL AND MIN(f.due_at) < ?", f.at())
	} else if f.DueBefore != nil {
		q = q.Having("MIN(f.due_at) IS NOT NULL AND MIN(f.due_at) < ?", *f.DueBefore)
	}
	q = f.whatUpstreamDid(q)
	if cwes := trimmed(f.Weaknesses); len(cwes) > 0 {
		// One indexed lookup against the table that holds them.
		//
		// The classification was a comma-joined column, which made a
		// membership test a substring match — and a bare LIKE answers CWE-79
		// for a search for CWE-7, so it took four escaped patterns per name
		// asked, none of which an index can be used for, over every issue.
		// Every other multi-valued attribute here is a table; this one is too.
		upper := make([]string, 0, len(cwes))
		for _, cwe := range cwes {
			upper = append(upper, strings.ToUpper(strings.TrimSpace(cwe)))
		}
		q = q.Where(`EXISTS (SELECT 1 FROM "vulnerability_weakness" AS "vw"
			WHERE vw.vulnerability_id = f.vulnerability_id
			  AND vw.cwe IN (?))`, bun.List(upper))
	}
	if words := foldedTags(f.Tags); len(words) > 0 {
		// One issue in one component of one product, which is the grain a tag
		// is put on and the grain this list groups by — so the membership test
		// is on the group's own key rather than on a place.
		where, args := f.product()
		q = q.Where(`EXISTS (SELECT 1 FROM "finding_tag" AS "ft"
			WHERE ft.product_id = `+where+`
			  AND ft.vulnerability_id = f.vulnerability_id
			  AND ft.component_id = f.component_id
			  AND ft.tag IN (?))`, append(args, bun.List(words))...)
	}
	// Something a person recorded here rather than a scanner reporting it
	// . Its own question rather than a shade of another: a recorded
	// flaw is the only kind a person may close by hand, and the screen that
	// records one had no way to list what had been recorded before.
	// What a promised upgrade covers, or what none does. A condition over the
	// group rather than over a place, like every other decision predicate
	// here: a group is planned when a promise reaches it, and unplanned when
	// none reaches any of it.
	if f.Planned != PlannedEither {
		if f.Planned == PlannedOnly {
			q = q.Having("SUM(COALESCE(dd.planned, 0)) > 0")
		} else {
			q = q.Having("SUM(COALESCE(dd.planned, 0)) = 0")
		}
	}
	switch f.Origin {
	case RecordedByHand:
		q = q.Where("f.kind = ?", Entered)
	case ReportedByAScanner:
		q = q.Where("f.kind <> ?", Entered)
	}
	if f.SentBack {
		// The same condition the row's own count is computed from, so the
		// filter and the row cannot disagree about what is with its author.
		where, args := f.product()
		q = q.Where(standsAs(where, claimSentBack),
			append(append([]any{}, args...), claimSentBack.args...)...)
	}
	// Open in some builds of the selection and not others, which is what a
	// comparison is about. Counted over the builds the selection holds rather
	// than over every build there is: "differs" is a statement about what is
	// being looked at.
	if f.DiffersBetweenBuilds && f.Builds > 1 {
		q = q.Having("COUNT(DISTINCT f.target_id) < ?", f.Builds)
	}
	if f.Beneath != nil {
		// The subtree as the engine walks it, not as a list of identifiers
		// bound back in: under a build's root that list is the whole build.
		q = q.Where("f.component_id IN (?)", graph.Within(q.DB(), f.TargetID, *f.Beneath))
	}
	q = f.byState(q)
	if !f.BelowFloor {
		q = f.Floor.narrow(q)
	}
	return q
}

// whatUpstreamDid keeps only the groups upstream has done one of these about.
//
// A condition on the group rather than on a row, for the reason the fix flag
// is: a state known at one place and not another would drop the places that
// lack it and report a group smaller than it is.
//
// Which leaves the group whose places genuinely disagree, and it has its own
// word. Asked for one state, unanimity is the question; asked for "mixed",
// the question is the opposite one — and a group that answered neither was a
// row no value of this filter could list, which is what a filter presented as
// covering what upstream did must not have.
//
// Several states asked at once are one condition holding an OR, and each keeps
// its own meaning inside it: "nothing released or upstream declined" is the
// population that needs a judgment rather than a bump, and it is two words for
// one question.
func (f Filter) whatUpstreamDid(q *bun.SelectQuery) *bun.SelectQuery {
	states := f.fixStates()
	if len(states) == 0 {
		return q
	}
	says := make([]string, 0, len(states))
	args := make([]any, 0, 2*len(states))
	for _, state := range states {
		if state == FixMixed {
			says = append(says, "MIN(f.fix_state) <> MAX(f.fix_state)")
			continue
		}
		says = append(says, "(MIN(f.fix_state) = ? AND MAX(f.fix_state) = ?)")
		args = append(args, state, state)
	}
	q = having(q, "("+strings.Join(says, " OR ")+")", args...)
	return q
}

// heldBy keeps only the groups whose places are held by who was asked about.
//
// One condition holding an OR rather than several applied in turn: "mine or
// whatever nobody has picked up" is one question, and applied one at a time
// these would AND and answer with nothing.
//
// A condition on the group, so "mine" means every place held and every one of
// them by one of my names. A group split between me and somebody else is not
// mine, and saying it is would hand somebody work that is half theirs.
func (f Filter) heldBy(q *bun.SelectQuery) *bun.SelectQuery {
	asked := trimmed(f.Assigned)
	if len(asked) == 0 {
		return q
	}
	says := make([]string, 0, len(asked))
	args := make([]any, 0, 2)
	for _, who := range asked {
		switch who {
		case "nobody":
			says = append(says, "COUNT(f.assigned_to) = 0")
		case "somebody":
			says = append(says, "COUNT(f.assigned_to) = COUNT(*)")
		case "me":
			// Mine or my team's, everywhere the phrase appears. A subject
			// holding no party names nobody, so the phrase contributes
			// nothing — which the guard below turns into an answer of nothing
			// where it is the only thing asked for.
			if len(f.HeldBy) == 0 {
				continue
			}
			says = append(says, "(COUNT(f.assigned_to) = COUNT(*)"+
				" AND MIN(f.assigned_to) IN (?) AND MAX(f.assigned_to) IN (?))")
			args = append(args, bun.List(f.HeldBy), bun.List(f.HeldBy))
		}
	}
	if len(says) == 0 {
		// Something was asked for and none of it could be turned into a
		// condition: a word this does not know, or "mine" from a subject that
		// holds no party. That is a narrowing that cannot be applied rather
		// than no narrowing, and dropping it answered with every finding there
		// is while the screen went on showing the filter as on.
		return having(q, "1 = 0")
	}
	return having(q, "("+strings.Join(says, " OR ")+")", args...)
}

// sayingIt keeps only what a VEX publisher has a standing statement about,
// and only where that statement says what was asked.
//
// Sixty lines of one idea, lifted out of narrow so that the rest of it reads
// as the thirty independent narrowings it is. Nothing about it changed: the
// statements are resolved into the (component, issue) pairs they name, once,
// and the list is joined to that.
func (f Filter) sayingIt(q *bun.SelectQuery) *bun.SelectQuery {
	publishers, saidIt := trimmed(f.Publishers), trimmed(f.VexStatus)
	if len(publishers) > 0 || len(saidIt) > 0 {
		// The statements being asked about, written once and used for
		// both arms of the union below.
		asked := []string{"ss.superseded_at IS NULL"}
		var about []any
		if len(publishers) > 0 {
			lowered := make([]string, 0, len(publishers))
			for _, name := range publishers {
				lowered = append(lowered, strings.ToLower(name))
			}
			asked = append(asked, "ss.publisher IN (?)")
			about = append(about, bun.List(lowered))
		}
		if len(saidIt) > 0 {
			asked = append(asked, "ss.status IN (?)")
			about = append(about, bun.List(saidIt))
		}
		narrowing := strings.Join(asked, " AND ")

		// The issue under its own name, and under every other name it
		// goes by: which identifier a publisher chose says nothing
		// about which issue they meant. Two arms rather than an OR
		// across two left joins, because one statement can match one
		// issue by name and another by alias, and folding those
		// together would drop one of them.
		//
		// Both sides of every comparison are folded on the way in, so
		// these are equalities the indexes can be used for rather than
		// functions of a column. That is not a tidiness point: with
		// LOWERon the issue's side the plan scanned the whole
		// vulnerability table, and the whole alias table, once per
		// statement.
		pairs := `(SELECT ss.product_id AS "product_id", vc.id AS "component_id",
			vv.id AS "vulnerability_id"
			FROM "vex_statement" AS "ss"
			JOIN "component" AS "vc" ON vc.name_folded = ss.component
			JOIN "vulnerability" AS "vv" ON vv.identifier_folded = ss.vulnerability
			WHERE ` + narrowing + `
			UNION
			SELECT ss.product_id, vc.id, vl.vulnerability_id
			FROM "vex_statement" AS "ss"
			JOIN "component" AS "vc" ON vc.name_folded = ss.component
			JOIN "vulnerability_alias" AS "vl" ON vl.identifier_folded = ss.vulnerability
			WHERE ` + narrowing + `)`

		where, args := f.product()
		joined := make([]any, 0, 2*len(about)+len(args))
		joined = append(joined, about...)
		joined = append(joined, about...)
		joined = append(joined, args...)
		q = q.Join("JOIN "+pairs+` AS "vx" ON vx.component_id = f.component_id`+
			" AND vx.vulnerability_id = f.vulnerability_id"+
			// Correlated on the row's own product where the list spans them,
			// so a statement in one product cannot answer for a finding in
			// another.
			" AND vx.product_id = "+where, joined...)
	}
	return q
}

// at is the moment the deadline filters compare against.
//
// The store's own clock where it set one, and the wall clock where nothing
// did — a method rather than a bare field so that a caller who forgets cannot
// get 1 January year one, which as a deadline reads as "everything is late".
//
// **Read through the store so a frozen clock reaches it.** Reading the wall
// clock directly is what left the overdue filter untestable, and it meant one
// request compared "is this overdue" against one moment and "is anything off
// the clock" against another.
func (f Filter) at() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now().UTC()
}

// componentsWhere is the identifiers of the components a condition selects,
// as a subquery for a membership test on a finding's component or consumer.
func componentsWhere(q *bun.SelectQuery, condition string, args ...any) *bun.SelectQuery {
	return q.NewSelect().TableExpr(`"component" AS "c"`).Column("c.id").Where(condition, args...)
}

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
		// The line's own condition, negated: not exploited, and rated
		// beneath the line. Both read the way Floor.narrow reads them.
		counted = counted.Where("f.urgency < ?", int64(exploitedBand)).
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

// KeyMatches says a decision row `de` was keyed on the versions a finding's
// component `c` and consumer `uc` hold now, as the versions are compared
// everywhere a decision is looked up for a finding. A decision stores no
// version where nothing stated one; the finding's expression reads that as
// empty, so the two absences are compared as the same absence.
//
// The three aliases are the caller's to join: a finding's own row carries
// only the identifiers, and the versions are on the components.
// Exported because the same question is asked outside this package: what is
// undecided is what the notification sweep means by work sitting still, and a
// second spelling of it would be a second definition of "decided".
const KeyMatches = "COALESCE(de.component_upstream_version, '') = " + ComponentUpstreamExpr +
	" AND COALESCE(de.consumer_upstream_version, '') = " + ConsumerUpstreamExpr

// PlannedFilter is whether a promised upgrade covers a finding.
type PlannedFilter string

const (
	// PlannedEither asks nothing, which is the default.
	PlannedEither PlannedFilter = ""
	// PlannedOnly keeps what an upgrade already covers.
	PlannedOnly PlannedFilter = "planned"
	// NotPlanned keeps what none covers, which is the working list once a
	// promise takes what it covers out of view.
	NotPlanned PlannedFilter = "unplanned"
)

// upgradeNeeded is the outcome that promises a move, named here so the
// filter and the triage package cannot drift on the spelling.
const upgradeNeeded = "upgrade-needed"

// coversHere says a decision row `de` is about the finding it was correlated
// with by issue and place, for the counts behind the state a row carries and
// the state filter that finds it.
//
// A live claim covers a place at the versions it was keyed on and no other:
// matched by place alone, a claim approved against libnl 3.7.0 in one build
// answered for libnl 3.9.0 at the same place in the next, while everything
// that asks whether a decision actually applies said it covered nothing there.
// A claim with no key has lapsed or been withdrawn, and by definition its
// versions no longer match — what it says about the place is history, and it
// is matched by place so that "lapsed" can be said at all.
const coversHere = "(de.live_key IS NULL OR (" + KeyMatches + "))"

// byState keeps groups by how far they have been decided.
//
// Every one of these is a condition over the *group* rather than over a place,
// so they are HAVING clauses: a group is undecided when none of its places has
// a decision, not when one of them does not.
//
// **These read the decision table and nothing else.** The first version read
// `suppressed_by`, which is not a decision of ours at all: it points at a
// suppression, and a suppression is a claim the *build* made in its own scan
// file (only internal/sbom ever writes one). So "agreed" meant "the vendor's
// SBOM argued this away", a claim by a different author that nobody here
// reviewed — and a decision actually approved by a second person matched none
// of the four states. What the build argued away is a real number and the row
// already carries it separately, as how many places are answered; it is not
// how far *we* have decided.
//
// **Read from the decisions outward, not from the findings inward.** What is
// joined is the set of open finding rows that have a decision of ours in this
// product, with what kind — built once from the decision table, which holds
// hundreds of rows where finding holds hundreds of thousands, and joined to
// the grouping by the finding's own identifier. The first version asked the
// question the other way round, as a correlated lookup per finding row, and
// that ran once for every open row in the build to say which groups had
// nothing: 241,479 probes to answer "undecided" on a build with no decisions
// at all. The counts are the same either way; a place with two decisions is
// one place, which is what folding to one row per finding keeps true.
//
// A decision belongs to a product and the two keys linking one to a finding do
// not: an issue is one row per identifier for the whole deployment, and a
// place identity is a hash of a consumer and a component with no product in it
// (see PlaceIdentity — deliberately, so a place is recognized across
// variants). Joined on those two alone this would match decisions in *every*
// product, which reports somebody else's triage as this product's state and
// tells a reader that a claim is pending in a product they cannot see; the
// product is a condition on the decision for that reason.
func (f Filter) byState(q *bun.SelectQuery) *bun.SelectQuery {
	states := trimmed(f.States)
	outcomes := trimmed(f.Outcomes)

	// The planned filter reads the same derived table, so asking for it is a
	// reason to build it even where no state or outcome was asked for.
	if len(states) == 0 && len(outcomes) == 0 && f.Planned == PlannedEither {
		return q
	}
	// Whether one was asked for, kept before the list is padded: an empty IN
	// list is a syntax error on two of the engines, so the column binds a
	// word no outcome equals — and reading the padded list as a request
	// would narrow every group to those answered "" everywhere, which is
	// none of them.
	askedOutcome := len(outcomes) > 0
	if !askedOutcome {
		outcomes = []string{""}
	}
	// The words are spelled here rather than taken from the triage
	// package, which imports this one — naming them there and reading them
	// here is a cycle. They are the values stored in the column either
	// way, and the enum on the endpoint is what keeps a caller from
	// inventing a fifth. Bound rather than spelled into the statement.
	// These are compile-time constants and nothing a caller supplies, so
	// there is nothing to inject — but a value in a placeholder is the
	// rule, and a literal here is the shape somebody copies to a place
	// where it does matter.
	const (
		proposed = "proposed"
		approved = "approved"
		lapsed   = "lapsed"
	)
	// One row per open finding that has a decision of ours in this product,
	// saying which kinds. "Waiting" and "lapsed" count a claim in that state
	// whether or not it still stands; "approved" counts only the claim that
	// currently stands, because without that a judgment withdrawn eighteen
	// months ago still answers for its place.
	//
	// The finding's component and consumer are joined for the versions: a
	// live claim is about the place at the versions it was keyed on, and
	// matching it by place alone reports a claim made about one build's
	// version as standing over a second build shipping another.
	standingHere, inForce := InForce()
	decided := q.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "finding" AS "f2" ON f2.vulnerability_id = de.vulnerability_id`+
			" AND f2.place_identity = de.place_identity").
		Join(`JOIN "component" AS "c" ON c.id = f2.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f2.consumer_id`).
		// The argument, which is where the outcome lives: one act is one
		// argument, and the rows underneath say where it lands.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`f2.id AS "finding_id"`).
		// Waiting, and standing: the row's own count requires the live key
		// and this did not, so a claim proposed and then withdrawn put its
		// group in the waiting bucket while the row drew no state word at
		// all. Both are the same question and have to be the same condition.
		ColumnExpr(`MAX(CASE WHEN de.state = ? AND de.live_key IS NOT NULL THEN 1 ELSE 0 END) AS "waiting"`,
			proposed).
		ColumnExpr(`MAX(CASE WHEN de.state = ? AND de.live_key IS NOT NULL THEN 1 ELSE 0 END) AS "approved"`,
			approved).
		ColumnExpr(`MAX(CASE WHEN de.state = ? THEN 1 ELSE 0 END) AS "lapsed"`, lapsed).
		// Whether a promise to upgrade stands over this place. Counted
		// only for the claim that currently stands, like "approved"
		// above: a promise that was withdrawn is not one, and a
		// finding it used to cover is unplanned again with nothing to
		// clean up. That is the whole argument for deriving this
		// rather than writing a tag.
		ColumnExpr("MAX(CASE WHEN de.live_key IS NOT NULL AND "+standingHere+
			` AND cl.outcome = ? THEN 1 ELSE 0 END) AS "planned"`,
			append(append([]any{}, inForce...), string(upgradeNeeded))...).
		// The kind of judgment standing here, counted only for the claim that
		// currently stands: a dismissal withdrawn eighteen months ago must not
		// answer for its place, which is the same rule "approved" above holds
		// — and neither must one still waiting for a second person, or asking
		// what has been dismissed answers with what somebody has merely
		// proposed dismissing.
		ColumnExpr("MAX(CASE WHEN de.live_key IS NOT NULL AND "+standingHere+
			` AND cl.outcome IN (?) THEN 1 ELSE 0 END) AS "this_outcome"`,
			append(append([]any{}, inForce...), bun.List(outcomes))...).
		Where("f2.closed_at IS NULL").
		Where(coversHere).
		GroupExpr("f2.id")
	if f.Across {
		// A joined derived table cannot reach the outer query's product, so
		// across products it carries its own: the decision has to belong to
		// the product the finding it answers for sits in, which is the same
		// rule the bound number states inside one product.
		decided = decided.
			Join(`JOIN "target" AS "tg2" ON tg2.id = f2.target_id`).
			Join(`JOIN "stream" AS "st2" ON st2.id = tg2.stream_id`).
			Where("de.product_id = st2.product_id")
	} else {
		decided = decided.Where("de.product_id = ?", f.ProductID)
	}
	q = q.Join(`LEFT JOIN (?) AS "dd" ON dd.finding_id = f.id`, decided)

	if askedOutcome {
		// Every place answered the same way, not merely one of them: a group
		// where one place is dismissed and the rest are open is not a
		// dismissal, and listing it under "dismissed" is how a number stops
		// being one somebody can act on.
		q = q.Having("SUM(COALESCE(dd.this_outcome, 0)) = COUNT(*)")
	}
	// Each state is a condition over the group's decision counts, so a set of
	// them is those conditions OR-ed — which is what a checkbox set means and
	// what one value could not ask. Asking for all four is asking for
	// everything, and reads as no narrowing at all rather than as four
	// conditions nothing can satisfy at once.
	wanted := make([]string, 0, len(states))
	for _, each := range states {
		if said := stateHaving(each); said != "" {
			wanted = append(wanted, "("+said+")")
		}
	}
	if len(wanted) > 0 {
		q = q.Having(strings.Join(wanted, " OR "))
	}
	return q
}

// stateHaving is the condition a group must satisfy to be in one state.
//
// Named apart from the switch that used it so several can be combined, and so
// each keeps the reasoning that made it what it is.
func stateHaving(state string) string {
	switch state {
	case "agreed":
		return "SUM(COALESCE(dd.approved, 0)) = COUNT(*)"
	case "waiting":
		return "SUM(COALESCE(dd.waiting, 0)) > 0"
	case "lapsed":
		// Lapsed means nothing replaced it: a claim made again at the place
		// after the old one lapsed is waiting, which is what the row says,
		// and the filter has to find the row by the word it reads.
		return "SUM(COALESCE(dd.lapsed, 0)) > 0 AND SUM(COALESCE(dd.approved, 0)) = 0" +
			" AND SUM(COALESCE(dd.waiting, 0)) = 0"
	case "undecided":
		// Nothing stands, rather than nothing was ever said. A claim that has
		// been withdrawn leaves a row that covers the place and says nothing
		// about it, so counting rows put the finding in no state at all: not
		// undecided, and not any of the three below either. It vanished from
		// every bucket and from the count above the list, and nothing ever
		// offered it as work again.
		return "SUM(COALESCE(dd.waiting, 0)) = 0" +
			" AND SUM(COALESCE(dd.approved, 0)) = 0" +
			" AND SUM(COALESCE(dd.lapsed, 0)) = 0"
	}
	return ""
}

// containsTerm prepares a term to be searched for literally.
//
// A search box is not a pattern language. Typing `50%` means a component whose
// name contains "50%", not every component containing "50" — and `a_b` means
// what it says rather than "a, anything, b". So the wildcards are escaped and
// the escape character is stated: every engine here takes `ESCAPE`, and SQLite
// has no default escape character at all, so leaving it out makes a backslash
// mean one thing on three engines and another on the fourth.
//
// **The escape character is `#`, and a backslash is what it must not be.**
// MySQL and MariaDB treat a backslash as an escape inside a string literal, so
// `ESCAPE '\'` is an unterminated string: a syntax error there, and parsed
// happily by the other two. Caught by the four-engine run, which is the whole
// reason that run exists.
//
// **Case is folded here and again by the engine**, which is a compromise worth
// naming. Folding the term in Go is Unicode-aware; `LOWER()` on the column is
// ASCII-only on SQLite — so a name carrying a non-ASCII capital is found on
// three engines and missed on the fourth, wherever the comparison is against a
// column with no folded copy.
//
// The component half has one — `component.name_folded`, which the search
// clause above compares against — so this applies to the issue half, where
// `vulnerability.identifier_folded` exists and `LOWER(v.identifier)` is what
// is still asked. Issue identifiers are ASCII in every scheme anybody
// publishes, which is why this is written down rather than fixed.
func containsTerm(term string) string {
	return database.LikeEscaped(strings.ToLower(term))
}

// fixStates is the fix statuses asked for, without the empty word. An empty
// word is "any", and left in it would be a state nothing is ever in — turning
// a filter that asks for nothing into one that answers nothing.
func (f Filter) fixStates() []FixState {
	kept := make([]FixState, 0, len(f.FixStates))
	for _, state := range f.FixStates {
		if strings.TrimSpace(string(state)) != "" {
			kept = append(kept, state)
		}
	}
	return kept
}

// foldedTags is a set of tags as they are stored, without the ones that fold
// to nothing. Folded rather than trimmed, because a tag is matched on the folded
// form everywhere else and a filter that skipped the folding would answer
// nothing for a word somebody typed with a capital.
func foldedTags(words []string) []string {
	kept := make([]string, 0, len(words))
	for _, word := range words {
		if tag := TagAs(word); tag != "" {
			kept = append(kept, tag)
		}
	}
	return kept
}

// having applies a condition assembled from however many answers were asked
// for, without handing the builder an empty argument list. A condition with no
// placeholders and an empty slice is warned about on every query — true and
// harmless, and printed once per read, which buries anything that matters.
func having(q *bun.SelectQuery, condition string, args ...any) *bun.SelectQuery {
	if len(args) == 0 {
		return q.Having(condition)
	}
	return q.Having(condition, args...)
}

// trimmed drops blanks from a list of names, so a stray separator in a query
// string does not become a name nothing matches — and so a repeated parameter
// carrying an empty member, which is what an unset control submits, does not
// narrow a set to nothing when it means everything.
func trimmed(names []string) []string {
	kept := make([]string, 0, len(names))
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			kept = append(kept, name)
		}
	}
	return kept
}

// sortedBy is the ORDER BY the list is paged with.
//
// Built from the allowlist alone. The only thing a caller decides is which of
// the fixed keys and which direction, and neither reaches the statement as
// text: the key selects a stored expression, and the direction selects one of
// two words written here.
func sortedBy(filter Filter) string {
	sorted := orderedBy(filter, ByUrgency)
	// Always the same tie-break, so that paging is stable: two rows equal on
	// the sorted column must not swap between pages, which drops one row and
	// repeats another across a boundary.
	//
	// The fold rather than a component, because that is what the rows are
	// grouped by — MySQL refuses an ordering on a column the grouping does not
	// determine, and it is right to: a tie-break on a column that varies
	// within a row is not a tie-break at all.
	return sorted + ", " + GroupedOn
}

// Origin is where a finding came from, as a narrowing.
//
// Three answers rather than two, which is why it is a word: a list can be
// asked for what a person recorded, for what a scanner reported, or for both.
// As a flag the middle answer was unsendable, so the screen offered it and
// filtered nothing.
type Origin string

const (
	// RecordedByHand keeps only what a person entered here. Those are the only
	// ones a person may close by hand.
	RecordedByHand Origin = "manual"
	// ReportedByAScanner keeps only what a scan found.
	ReportedByAScanner Origin = "scanner"
)

// Origins are the words the narrowing takes.
func Origins() []Origin { return []Origin{ReportedByAScanner, RecordedByHand} }

// Valid reports whether o is one of them.
func (o Origin) Valid() bool {
	for _, known := range Origins() {
		if o == known {
			return true
		}
	}
	return false
}
