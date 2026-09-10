package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Open returns the findings currently open against a target that this subject
// may read.
//
// The filtering happens here rather than in whatever asked. A check in a
// handler is a check somebody forgets the first time they add another handler,
// and the thing being forgotten is not a blank screen — it is somebody seeing
// an issue that has not been disclosed.
//
// Which product the target belongs to is read here too, rather than accepted
// from the caller. A caller that could name the product could name a different
// one, and then the check would be answering a question nobody asked.
func (s *Store) Open(ctx context.Context, subject access.Subject, targetID int64) ([]Finding, error) {
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	if !subject.Sees(productID) {
		// Not merely empty: a product somebody holds nothing on does not
		// exist as far as they are concerned, and an empty list is a
		// different statement from a refusal.
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	var rows []Finding
	err = s.db.NewSelect().Model(&rows).
		Where("target_id = ?", targetID).
		Where("closed_at IS NULL").
		Where("visibility IN (?)", bun.List(visible)).
		Order("id").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read open findings: %w", err)
	}
	return rows, nil
}

// productOf reads which product a build belongs to.
func productOf(ctx context.Context, db bun.IDB, targetID int64) (int64, error) {
	return catalog.NewStore(db).ProductOf(ctx, targetID)
}

// Group is one issue in one component, with the places it occupies.
//
// This is the unit somebody decides about. The places are what the decision is
// recorded against — one real image produced 335,021 findings and 305,487 of
// them were a single kernel across the modules built against it, so a list of
// places is six thousand screens of rows differing in a column nobody reads.
type Group struct {
	// Product and ProductName are filled only where the list spans
	// products . Inside one product every row would repeat it, and a
	// column every row agrees about is width the parts that differ need.
	Product     string
	ProductName string

	Vulnerability string
	Severity      string
	// Summary is the first line of what the issue says about itself, for a
	// list where fifty rows otherwise read "CVE-2026-74280 · linux-image"
	// fifty times. Somebody scanning for the one they care about is reading
	// the words, and without them telling two rows apart cost a click each.
	Summary   string
	Component string
	Version   string
	// Upstream is what a fork was made from, where it is one. A version nobody
	// recognizes needs it to be explainable.
	Upstream string
	// Source is the package this binary was built from, where the two differ.
	// The same issue at two binaries of one source is two rows here and one
	// piece of work everywhere else — it is decided once, upgraded once and
	// routed by one rule — and a reader with no way to see that is reading a
	// list a third of which is the same work said again.
	Source string
	// Ecosystem is the kind of package this is, as its identifier spells it.
	// Part of what tells one row from another: a name at a version is not
	// unique within a build, which can hold a source repository and the
	// package built from it under one name at one version.
	Ecosystem string
	FixState  FixState
	FixedIn   string
	// Fold is what the row is about: the source package at the version it was
	// built at, in the ecosystem and distribution it came from. It is what a
	// judgment, an assignment and an upgrade all name.
	Fold string
	// Packages is how many binaries of the fold sit here, and Consumers how
	// many things pull them in. These are the numbers a reader is shown,
	// counted in the units they act in: deciding on this row decides about
	// every package and every consumer under it, and a row that hid its size
	// would invite a judgment made about one being applied to sixty unseen.
	Packages  int
	Consumers int
	// Places is how many findings sit under it. What the bulk cap is measured
	// against and what the disposition register expands to, rather than a
	// number a reader is asked to reconcile with the two above.
	Places int
	// Answered counts the places the build has already argued about.
	Answered int
	// State is how far we have decided this group, in the same four words
	// the state filter takes and by the same definition: undecided when no
	// place has a decision of any kind, waiting when a claim stands proposed
	// and nobody has agreed, agreed when every place is answered by a
	// standing decision, lapsed when a decision here stopped applying and
	// nothing replaced it. Empty where none of the four holds — some places
	// approved and the rest never decided, with nothing waiting or lapsed.
	State string
	// SentBack says a live claim at one of the places is currently with its
	// author, which is the row the proposer is looking for in the list.
	SentBack bool
	// Undisclosed says nothing here has been announced, and DiscloseAt
	// when the embargo ends. Everything about disclosure existed in the
	// API and appeared nowhere a person could see it: an undisclosed
	// recorded flaw rendered identically to any other row.
	Undisclosed bool
	DiscloseAt  *time.Time
	// Tags are the words somebody put on this, as they were typed.
	Tags []string
	// OpenedAt is when the earliest of these places opened here, which is
	// the age a deadline relates to. Not the year in the identifier: an
	// issue assigned in 2019 that first appeared in this product last week
	// has been somebody's problem for a week.
	OpenedAt time.Time
	// DueAt is the earliest deadline across these places, and NoDeadline
	// says why there is none where there is none. Exactly two reasons,
	// both deliberate, and a blank cell would mean either.
	DueAt      *time.Time
	NoDeadline NoDeadline
	// Urgency is how far up the list this belongs, and Exploited says whether
	// it is there because somebody is using it. The flag is carried rather
	// than left to be inferred from the number: a position nobody can explain
	// is one people stop trusting and then work around.
	Urgency   int64
	Exploited bool
	// LikelihoodPPM is the published estimate that this will be exploited, in
	// parts per million. Carried because it ranks *above* severity: without it
	// on the row, a medium sitting above a high looks like the list is
	// unsorted, when it is sorted by something the list never showed.
	LikelihoodPPM int
	// ScoreCenti is what the ordering actually compares. The severity word
	// beside it comes from whichever scoring generation the source used — a
	// 2003 issue scored 10.0 reads "high" under CVSS v2 and "critical" under
	// v3 — so a row showing only the word looks mis-sorted when two tie.
	ScoreCenti int
	// Owner and Parent are the two ends of the way down to this component:
	// the part of the product it belongs to, and what directly pulls it in
	// . Those two are what differ between sibling rows — the top says
	// which part of the product this is, the bottom is what a decision is
	// about — and the steps between them rarely distinguish anything, so
	// Middle counts them rather than naming them.
	//
	// A group covers every place the component sits at, and those places
	// can come down different ways. Chains says how many distinct ways
	// there are, so a row can say "one of 4" rather than presenting one
	// route as though it were the only one.
	//
	// All four are empty where the selection spans more than one build . A
	// chain belongs to one build's graph, and a group that sits in three
	// builds is reached three ways, so filling these from whichever build
	// the row happened to name would present one route as the answer — the
	// thing the paragraph above says not to do, one level up.
	Owner  string
	Parent string
	Middle int
	Chains int
	// Builds is how many builds in the selection hold this group, and Stream
	// and Variant name **one** of them — not the only one. A screen needs
	// somewhere to link to and an action needs a build to name; what says
	// there are others is the count, so a screen can show that instead of
	// reading the named one as the whole answer. Both are empty where the
	// selection is a single build, since the row would only be repeating it.
	Builds  int
	Stream  string
	Variant string
	// Matched says how the scanner reached this. One answer for the whole
	// group: every place of it comes from the same line of a report. Empty
	// where the scanner said nothing.
	Matched Matched `bun:"matched"`
}

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

// SortKeys are the orders somebody may ask for.
//
// The list a caller sees is the enum on the query parameter, which a struct
// tag has to spell as a literal, and the interface's own union is generated
// from that — so this cannot be the single source by construction. It is the
// single source by test: one asserts the parameter offers exactly these, in
// this order, and that each is accepted. Written here as "one list, so the two
// cannot disagree" while nothing called it, it was neither.
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
	// Recorded keeps only what a person entered here rather than what a
	// scanner reported.
	Recorded bool
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
	for i, word := range ranked {
		if word == f.MinSeverity {
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
		q = q.Where("f.vulnerability_id IN (?)",
			q.NewSelect().TableExpr("vulnerability AS v").Column("v.id").
				Where("v.severity IN (?)", bun.List(words)))
	}
	if f.Exploited {
		// Read off the urgency rather than the flag beside it. A place known
		// to be exploited ranks in a band of its own above everything else
		// (Ranked.Rank), and the urgency is in the index the grouping walks
		// where the flag is not.
		q = q.Having("MAX(f.urgency) >= ?", int64(exploitedBand))
	}
	if f.HasFix {
		q = q.Having("MIN(f.fixed_in) IS NOT NULL AND MIN(f.fixed_in) <> ?", "")
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
		like := "%" + contains(term) + "%"
		// Either side matches. A person typing into one box does not say
		// which of the two they mean, and an identifier cannot be mistaken
		// for a package name in practice.
		q = q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.
				WhereOr("f.component_id IN (?)",
					componentsWhere(q, "c.name_folded LIKE ? ESCAPE '#'", like)).
				WhereOr("f.vulnerability_id IN (?)",
					q.NewSelect().TableExpr("vulnerability AS v").Column("v.id").
						Where("LOWER(v.identifier) LIKE ? ESCAPE '#'", like)).
				WhereOr("f.vulnerability_id IN (?)",
					q.NewSelect().TableExpr("vulnerability_alias AS va").
						Column("va.vulnerability_id").
						Where("LOWER(va.identifier) LIKE ? ESCAPE '#'", like))
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
		where := q.NewSelect().TableExpr("component AS c").Column("c.id")
		where = where.WhereGroup(" AND ", func(g *bun.SelectQuery) *bun.SelectQuery {
			for _, kind := range kinds {
				g = g.WhereOr("LOWER(c.purl) LIKE ? ESCAPE '#'", "pkg:"+contains(kind)+"/%")
			}
			return g
		})
		q = q.Where("f.component_id IN (?)", where)
	}
	// What holds it. A place records the component that pulls it in, so asking
	// what is inside a container is asking for places whose consumer is that
	// container — and what the build holds directly is the places with none.
	if f.UnderTheBuild {
		q = q.Where("f.consumer_id IS NULL")
	} else if under := strings.TrimSpace(f.Under); under != "" {
		q = q.Where("f.consumer_id IN (?)", componentsWhere(q, "c.name = ?", under))
	}
	// Who is dealing with it. Set for the whole group at once, so a group is
	// held when its places are — asked as MIN and MAX rather than as one row,
	// because a group whose places disagree is not "mine" and saying so would
	// hand somebody work that is half theirs.
	// Several answers OR together, and each keeps its own meaning inside the
	// OR — which is why they are assembled as one condition rather than
	// applied one at a time. Applied one at a time they would AND, and "mine
	// or nobody's" would be a list of nothing.
	if asked := trimmed(f.Assigned); len(asked) > 0 {
		says := make([]string, 0, len(asked))
		args := make([]any, 0, 2)
		for _, who := range asked {
			switch who {
			case "nobody":
				says = append(says, "COUNT(f.assigned_to) = 0")
			case "somebody":
				says = append(says, "COUNT(f.assigned_to) = COUNT(*)")
			case "me":
				// Mine or my team's, everywhere the phrase
				// appears. Every place held, and every one of
				// them by one of my names — a group whose
				// places are split between me and somebody
				// else is not mine, and saying it is would
				// hand somebody work that is half theirs.
				if len(f.HeldBy) == 0 {
					continue
				}
				says = append(says, "(COUNT(f.assigned_to) = COUNT(*)"+
					" AND MIN(f.assigned_to) IN (?) AND MAX(f.assigned_to) IN (?))")
				args = append(args, bun.List(f.HeldBy), bun.List(f.HeldBy))
			}
		}
		if len(says) > 0 {
			q = having(q, "("+strings.Join(says, " OR ")+")", args...)
		}
	}
	// What we said about the issue, as against what was published. A rating of
	// ours is the record of a priority somebody changed here.
	if f.Reassessed {
		q = q.Where("f.vulnerability_id IN (?)",
			q.NewSelect().TableExpr("vulnerability AS v").Column("v.id").
				Where("v.assessed_severity IS NOT NULL"))
	}
	// What an uploaded VEX document says about this, matched the way a
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
	publishers, saidIt := trimmed(f.Publishers), trimmed(f.VexStatus)
	if len(publishers) > 0 || len(saidIt) > 0 {
		// Which statements are being asked about, written once and used for
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
		pairs := `(SELECT ss.product_id AS product_id, vc.id AS component_id,
			vv.id AS vulnerability_id
			FROM "vex_statement" AS ss
			JOIN "component" AS vc ON vc.name_folded = ss.component
			JOIN "vulnerability" AS vv ON vv.identifier_folded = ss.vulnerability
			WHERE ` + narrowing + `
			UNION
			SELECT ss.product_id, vc.id, vl.vulnerability_id
			FROM "vex_statement" AS ss
			JOIN "component" AS vc ON vc.name_folded = ss.component
			JOIN "vulnerability_alias" AS vl ON vl.identifier_folded = ss.vulnerability
			WHERE ` + narrowing + `)`

		where, args := f.product()
		joined := make([]any, 0, 2*len(about)+len(args))
		joined = append(joined, about...)
		joined = append(joined, about...)
		joined = append(joined, args...)
		q = q.Join("JOIN "+pairs+" AS vx ON vx.component_id = f.component_id"+
			" AND vx.vulnerability_id = f.vulnerability_id"+
			// Correlated on the row's own product where the list spans them,
			// so a statement in one product cannot answer for a finding in
			// another.
			" AND vx.product_id = "+where, joined...)
	}
	if f.OpenedAfter != nil {
		q = q.Having("MIN(f.opened_at) > ?", *f.OpenedAfter)
	}
	if f.ClosedAfter != nil {
		// Closed rows are outside the list's own population, so this is the
		// one filter that changes what the list is about rather than
		// narrowing it. The caller says so by asking for it.
		q = q.Having("MAX(f.closed_at) > ?", *f.ClosedAfter)
	}
	if f.ProposedAfter != nil {
		q = q.Where(`EXISTS (SELECT 1 FROM "decision" AS de
			WHERE de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND de.proposed_at > ?)`, *f.ProposedAfter)
	}
	if f.LikelihoodAtLeast > 0 {
		q = q.Where("f.vulnerability_id IN (?)",
			q.NewSelect().TableExpr("vulnerability AS v").Column("v.id").
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
	if states := f.fixStates(); len(states) > 0 {
		// A condition on the group rather than on a row, for the reason the
		// fix flag is: a state known at one place and not another would drop
		// the places that lack it and report a group smaller than it is.
		//
		// Which leaves the group whose places genuinely disagree, and it has
		// its own word. Asked for one state, unanimity is the question; asked
		// for "mixed", the question is the opposite one — and a group that
		// answered neither was a row no value of this filter could list, which
		// is what a filter presented as covering what upstream did must not
		// have.
		//
		// Several states asked at once are one condition holding an OR, and
		// each keeps its own meaning inside it: "nothing released or upstream
		// declined" is the population that needs a judgment rather than a
		// bump, and it is two words for one question.
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
	}
	if cwes := trimmed(f.Weaknesses); len(cwes) > 0 {
		// The weaknesses are one comma-joined column, so this is a membership
		// test spelled as four exact shapes rather than as one padded LIKE.
		// Padding would want string concatenation, and `||` is logical OR on
		// two of the four engines — the operands coerce to numbers and the
		// whole condition collapses. Four patterns are portable and exact,
		// where a bare LIKE would match CWE-79 for CWE-7.
		q = q.Where("f.vulnerability_id IN (?)",
			q.NewSelect().TableExpr("vulnerability AS v").Column("v.id").
				WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
					for _, cwe := range cwes {
						name := strings.ToUpper(cwe)
						q = q.WhereGroup(" OR ", func(q *bun.SelectQuery) *bun.SelectQuery {
							return q.
								WhereOr("UPPER(v.weaknesses) = ?", name).
								WhereOr("UPPER(v.weaknesses) LIKE ?", name+",%").
								WhereOr("UPPER(v.weaknesses) LIKE ?", "%,"+name).
								WhereOr("UPPER(v.weaknesses) LIKE ?", "%,"+name+",%")
						})
					}
					return q
				}))
	}
	if words := foldedTags(f.Tags); len(words) > 0 {
		// One issue in one component of one product, which is the grain a tag
		// is put on and the grain this list groups by — so the membership test
		// is on the group's own key rather than on a place.
		where, args := f.product()
		q = q.Where(`EXISTS (SELECT 1 FROM "finding_tag" AS ft
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
	if f.Recorded {
		q = q.Where("f.kind = ?", Entered)
	}
	if f.SentBack {
		q = q.Where(`EXISTS (SELECT 1 FROM "decision" AS de
			WHERE de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND de.state = ?
			  AND de.live_key IS NOT NULL
			  AND de.sent_back_at IS NOT NULL)`, "proposed")
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

// at is the moment the deadline filters compare against. A method rather than
// a field so that a caller cannot forget to set one and get 1 January year one,
// which as a deadline reads as "everything is late".
func (f Filter) at() time.Time { return time.Now().UTC() }

// componentsWhere is the identifiers of the components a condition selects,
// as a subquery for a membership test on a finding's component or consumer.
func componentsWhere(q *bun.SelectQuery, condition string, args ...any) *bun.SelectQuery {
	return q.NewSelect().TableExpr("component AS c").Column("c.id").Where(condition, args...)
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
	_, visible, targets, err := s.inScope(ctx, subject, scope, &below)
	if err != nil {
		return 0, err
	}
	if len(targets) == 0 {
		return 0, nil
	}
	counted := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		ColumnExpr("f.vulnerability_id").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.vulnerability_id, " + FoldedOn)
	if words := filter.Floor.admits(); len(words) > 0 {
		// The line's own condition, negated: not exploited, and rated
		// beneath the line. Both read the way Floor.narrow reads them.
		counted = counted.Where("f.urgency < ?", int64(exploitedBand)).
			Where("f.vulnerability_id IN (?)",
				counted.NewSelect().TableExpr("vulnerability AS v").Column("v.id").
					Where(BandExpr+" NOT IN (?)", bun.List(words)))
	}
	n, err := s.db.NewSelect().
		TableExpr("(?) AS grouped", below.narrow(counted)).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count what the line keeps out: %w", err)
	}
	return n, nil
}

// stateWord says how far a group has been decided, from the same counts the
// state filter uses. The order is the filter's: a group every place of which
// is answered is agreed whatever else its history holds; one with a claim
// waiting is waiting; one where a decision lapsed and nothing stands is
// lapsed; one nobody ever decided about is undecided. Some places approved
// and the rest never decided, with nothing waiting or lapsed, is none of the
// four, and says so by saying nothing.
func stateWord(places, anyClaim, waiting, approved, lapsed int) string {
	switch {
	case places > 0 && approved == places:
		return "agreed"
	case waiting > 0:
		return "waiting"
	case lapsed > 0 && approved == 0:
		return "lapsed"
	case anyClaim == 0:
		return "undecided"
	}
	return ""
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
// worstBand is the highest severity among a set of counts, or empty where
// nothing was rated.
//
// Named rather than derived on the screen because two screens deriving it is
// two places for "worst" to come to mean different things — and because the
// order of these words is a fact about the domain, not a display choice.
func worstBand(counts map[string]int) string {
	for _, band := range []string{"critical", "high", "medium", "low"} {
		if counts[band] > 0 {
			return band
		}
	}
	return ""
}

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
		TableExpr(`"decision" AS de`).
		Join("JOIN finding AS f2 ON f2.vulnerability_id = de.vulnerability_id"+
			" AND f2.place_identity = de.place_identity").
		Join("JOIN component AS c ON c.id = f2.component_id").
		Join("LEFT JOIN component AS uc ON uc.id = f2.consumer_id").
		// The argument, which is where the outcome lives: one act is one
		// argument, and the rows underneath say where it lands.
		Join("JOIN claim AS cl ON cl.id = de.claim_id").
		ColumnExpr("f2.id AS finding_id").
		ColumnExpr("MAX(CASE WHEN de.state = ? THEN 1 ELSE 0 END) AS waiting", proposed).
		ColumnExpr("MAX(CASE WHEN de.state = ? AND de.live_key IS NOT NULL THEN 1 ELSE 0 END) AS approved",
			approved).
		ColumnExpr("MAX(CASE WHEN de.state = ? THEN 1 ELSE 0 END) AS lapsed", lapsed).
		// Whether a promise to upgrade stands over this place. Counted
		// only for the claim that currently stands, like "approved"
		// above: a promise that was withdrawn is not one, and a
		// finding it used to cover is unplanned again with nothing to
		// clean up. That is the whole argument for deriving this
		// rather than writing a tag.
		ColumnExpr("MAX(CASE WHEN de.live_key IS NOT NULL AND "+standingHere+
			" AND cl.outcome = ? THEN 1 ELSE 0 END) AS planned",
			append(append([]any{}, inForce...), string(upgradeNeeded))...).
		// Which kind of judgment stands here, counted only for the claim that
		// currently stands: a dismissal withdrawn eighteen months ago must not
		// answer for its place, which is the same rule "approved" above holds
		// — and neither must one still waiting for a second person, or asking
		// what has been dismissed answers with what somebody has merely
		// proposed dismissing.
		ColumnExpr("MAX(CASE WHEN de.live_key IS NOT NULL AND "+standingHere+
			" AND cl.outcome IN (?) THEN 1 ELSE 0 END) AS this_outcome",
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
			Join("JOIN target AS tg2 ON tg2.id = f2.target_id").
			Join("JOIN stream AS st2 ON st2.id = tg2.stream_id").
			Where("de.product_id = st2.product_id")
	} else {
		decided = decided.Where("de.product_id = ?", f.ProductID)
	}
	q = q.Join("LEFT JOIN (?) AS dd ON dd.finding_id = f.id", decided)

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

// contains prepares a term to be searched for literally.
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
// naming. matching a typed name without capitals says to normalize the stored value rather than ask an engine
// to compare loosely, and there is no folded column on a component to compare
// against — adding one is a migration and a backfill. Folding the term in Go
// is Unicode-aware; `LOWER()` on the column is ASCII-only on SQLite. So a
// component named with a non-ASCII capital is found on three engines and
// missed on the fourth. Component names are ASCII in every producer seen so
// far, which is why this is written down rather than fixed: the day that stops
// being true, the fix is a folded column.
func contains(term string) string {
	replacer := strings.NewReplacer("#", "##", "%", "#%", "_", "#_")
	return replacer.Replace(strings.ToLower(term))
}

// trimmed drops blanks from a list of names, so a stray separator in a query
// string does not become a name nothing matches — and so a repeated parameter
// carrying an empty member, which is what an unset control submits, does not
// narrow a set to nothing when it means everything.
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

// folded is a set of tags as they are stored, without the ones that fold to
// nothing. Folded rather than trimmed, because a tag is matched on the folded
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

func trimmed(names []string) []string {
	kept := make([]string, 0, len(names))
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			kept = append(kept, name)
		}
	}
	return kept
}

// inScope authorizes a selection and resolves it to the builds it covers.
//
// The three things every list over findings needs before it can read one:
// which product it is narrowing inside, what the reader may see there, and
// which builds the selection holds. Done once because two lists resolving them
// slightly differently would answer slightly different questions side by side.
func (s *Store) inScope(ctx context.Context, subject access.Subject, scope Scope,
	filter *Filter) (int64, []access.Visibility, []int64, error) {

	if scope.ProductID == nil {
		// Every list here correlates a decision by product and a place
		// identity carries none, so a selection without one would reach
		// decisions made in every product in the deployment.
		return 0, nil, nil, fmt.Errorf("read findings: the selection names no product")
	}
	productID := *scope.ProductID
	if !subject.Sees(productID) {
		return 0, nil, nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return 0, nil, nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	targets, err := s.buildsWorking(ctx, scope, filter.Workable)
	if err != nil {
		return 0, nil, nil, err
	}
	// Set here rather than trusted from the caller, for the reason above.
	filter.ProductID = productID
	// Who "mine" means, from the subject rather than from the request, and
	// their teams with them: the column holds a party.
	filter.HeldBy = subject.Mine()
	// How many builds the selection holds, which is what "differs between
	// builds" is measured against. The filter cannot see it.
	filter.Builds = len(targets)
	// A subtree is a walk over one build's edges, so it is answerable only
	// where the selection is one build. Asked across several it is refused
	// rather than answered from whichever build sorted first — which is what
	// leaving the identifier at zero would have done, silently and emptily.
	switch {
	case len(targets) == 1:
		filter.TargetID = targets[0]
	case filter.Beneath != nil:
		return 0, nil, nil, fmt.Errorf("read findings beneath a component: a subtree is a walk"+
			" over one build's edges, and %d builds are in scope", len(targets))
	}
	return productID, visible, targets, nil
}

// Groups returns what is open in a selection, as the things somebody decides
// about rather than as one row per place.
//
// The selection is not always one build. With the branch or the variant left
// at "all" the page answers for every build under the product: a row is one
// issue at one component still, and its places are counted across every build
// the group is in. What a row cannot carry there is the way down, because a
// chain belongs to one build's graph — so those columns are filled only where
// the selection is a single build, and across several the row names one of
// them and says how many hold it instead. Naming one as though it were the
// answer is the thing being avoided.
func (s *Store) Groups(ctx context.Context, subject access.Subject, scope Scope, limit, offset int,
	filter Filter) ([]Group, int, error) {
	productID, visible, targets, err := s.inScope(ctx, subject, scope, &filter)
	if err != nil {
		return nil, 0, err
	}
	if len(targets) == 0 {
		return nil, 0, nil
	}

	limit = database.AList.Of(limit)

	// The page in two statements: which groups, then what is known about
	// them.
	//
	// The first groups every open finding in the build by issue and component
	// and keeps the fifty most urgent. It reads four columns, all of them in
	// finding's covering index, so however large the build is this is one
	// walk of one index with nothing looked up. Everything else the row shows
	// — likelihood and score, how far it has been decided, how many ways
	// down there are, the fix — is read in a second statement over the fifty
	// groups on the page. The first version asked all of it in one statement,
	// and the five correlated decision lookups per row ran against every one
	// of a build's 240,945 open rows to produce fifty answers.
	heads, total, err := s.heads(ctx, targets, visible, limit, offset, filter)
	if err != nil {
		return nil, 0, err
	}

	known, err := s.decorate(ctx, targets, productID, visible, heads, filter)
	if err != nil {
		return nil, 0, err
	}
	rows := make([]decorated, 0, len(heads))
	for _, head := range heads {
		row := known[groupKey{head.VulnerabilityID, head.Fold}]
		row.groupHead = head
		rows = append(rows, row)
	}

	// Named in two more queries rather than two per row. A page of fifty was
	// a hundred and one round trips, every one of them a primary-key lookup —
	// and this is the screen somebody opens first, against the largest product
	// they have.
	//
	// The failures are reported rather than skipped. Each lookup used to be
	// ignored when it failed, so a database in trouble produced a findings
	// list with blank component names in it: a page that looks like data and
	// is not.
	issues := make([]int64, 0, len(rows))
	components := make([]int64, 0, len(rows))
	for _, row := range rows {
		issues = append(issues, row.VulnerabilityID)
		components = append(components, row.ComponentID)
		// The consumer too, so a row whose way down could not be walked can
		// still name what pulls it in.
		if row.ConsumerID != nil {
			components = append(components, *row.ConsumerID)
		}
	}
	named, err := issuesNamed(ctx, s.db, issues)
	if err != nil {
		return nil, 0, err
	}
	shipped, err := componentsNamed(ctx, s.db, components)
	if err != nil {
		return nil, 0, err
	}

	// Both ends of the way down to each row, in one pass over the page rather
	// than a walk per row. A row whose places are pulled in directly by the
	// build is asked about by the component itself, which lands on the same
	// answer with one step in it.
	oneBuild := len(targets) == 1
	var chains map[int64][]graph.Step
	var where map[int64]build
	if oneBuild {
		wanted := make([]int64, 0, len(rows))
		for _, row := range rows {
			if row.ConsumerID != nil {
				wanted = append(wanted, *row.ConsumerID)
			} else {
				wanted = append(wanted, row.ComponentID)
			}
		}
		if chains, err = graph.NewStore(s.db).Chains(ctx, subject, targets[0], wanted); err != nil {
			return nil, 0, err
		}
	} else {
		// Across builds a row names one of them, so that a screen has
		// somewhere to link to and an action has a build to name. Read for the
		// page's builds in one statement rather than per row.
		at := make([]int64, 0, len(rows))
		for _, row := range rows {
			at = append(at, row.TargetID)
		}
		if where, err = buildsNamed(ctx, s.db, at); err != nil {
			return nil, 0, err
		}
	}

	// The words somebody put on the page's rows, read in one statement
	// rather than per row: a tag is worth showing where the filter that
	// finds it lives, and a query per row is fifty queries for a page.
	marks, err := s.tagsFor(ctx, filter.ProductID, rows)
	if err != nil {
		return nil, 0, err
	}

	groups := make([]Group, 0, len(rows))
	for _, row := range rows {
		group := Group{
			Fold: row.Fold, Packages: row.Packages, Consumers: row.pullers(),
			Places: row.Places, Answered: row.Answered,
			Urgency: row.Urgency, Exploited: Rank(row.Urgency).Exploited(),
			LikelihoodPPM: row.LikelihoodPPM, ScoreCenti: row.ScoreCenti,
			FixState: FixState(row.FixState), FixedIn: row.FixedIn,
			Matched:  Matched(row.Matched),
			State:    stateWord(row.Places, row.AnyClaim, row.Waiting, row.Approved, row.Lapsed),
			SentBack: row.SentBack > 0,
			OpenedAt: row.OpenedAt, DueAt: row.DueAt,
			Undisclosed: access.AsVisibility(row.Visibility) == access.Private,
			DiscloseAt:  row.DiscloseAt,
		}
		if issue, held := named[row.VulnerabilityID]; held {
			group.Vulnerability, group.Severity = issue.Identifier, issue.Severity
			group.Summary = firstLineOf(issue.Description)
		}
		group.Tags = marks[markKey{row.VulnerabilityID, row.ComponentID}]
		// Why there is no deadline, said rather than left as a blank cell.
		// The two reasons are exhaustive, so whatever the line does not
		// account for is the other one: the line is a statement about the
		// rating, which is on the row, and everything else without a deadline
		// is in a release nothing is going to be fixed in.
		if group.DueAt == nil {
			group.NoDeadline = OutOfSupport
			if !filter.Floor.Admits(group.Exploited, group.Severity) {
				group.NoDeadline = BelowTheLine
			}
		}
		if component, held := shipped[row.ComponentID]; held {
			group.Component, group.Version = component.Name, component.Version
			group.Ecosystem = graph.EcosystemOf(component.Purl)
			if component.UpstreamVersion != "" {
				group.Upstream = component.UpstreamName + " " + component.UpstreamVersion
			}
			if component.UpstreamName != "" && component.UpstreamName != component.Name {
				group.Source = component.UpstreamName
			}
		}
		if oneBuild {
			// How many distinct ways down there are: the consumers this
			// component has here, plus one for the build pulling it in
			// directly.
			group.Chains = row.Consumers
			if row.Direct > 0 {
				group.Chains++
			}
			down := chains[row.ComponentID]
			if row.ConsumerID != nil {
				down = chains[*row.ConsumerID]
			}
			group.Owner, group.Parent, group.Middle = Ends(down)
			// A way down that could not be walked is not the same as nothing
			// pulling this in, and the row said the second when it meant the
			// first. The finding records its consumer whatever the graph did,
			// so name it: what is unknown is the route up to the build, not
			// what sits directly above.
			//
			// It happens where the inventory places a component under
			// something that is itself not reachable from the root — a
			// fragment the producer described and never attached — and the
			// honest answer is the half we hold rather than none of it.
			if group.Owner == "" && group.Parent == "" && row.ConsumerID != nil {
				if consumer, held := shipped[*row.ConsumerID]; held {
					group.Parent = consumer.Name
				}
			}
		} else if at, held := where[row.TargetID]; held {
			group.Builds = row.Builds
			// The way down is left empty rather than filled from this one
			// build: the group sits in every build the count names, and each
			// of them reaches it its own way.
			group.Stream, group.Variant = at.Stream, at.Variant
		}
		groups = append(groups, group)
	}
	return groups, total, nil
}

// build names one of the places a group sits, for a row that spans several.
type build struct {
	ID      int64  `bun:"id"`
	Stream  string `bun:"stream"`
	Variant string `bun:"variant"`
}

// buildsNamed names the builds a page's rows point at.
//
// One statement for the page rather than one per row, and the names are the
// ones somebody declared: a path resolves a name without regard to capitals ,
// so what was typed is both what reads correctly and what routes.
func buildsNamed(ctx context.Context, db bun.IDB, ids []int64) (map[int64]build, error) {
	named := make(map[int64]build, len(ids))
	if len(ids) == 0 {
		return named, nil
	}
	var rows []build
	if err := db.NewSelect().
		TableExpr("target AS tg").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN variant AS va ON va.id = tg.variant_id").
		ColumnExpr("tg.id AS id").
		ColumnExpr("st.display_name AS stream").
		ColumnExpr("va.display_name AS variant").
		Where("tg.id IN (?)", bun.List(ids)).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("name the builds a page sits in: %w", err)
	}
	for _, row := range rows {
		named[row.ID] = row
	}
	return named, nil
}

// groupHead is one group of the findings list as the covering index knows it:
// which issue in which component, at how many places, and the worst urgency
// among them. Everything the list is filtered, ordered and paged by.
type groupHead struct {
	VulnerabilityID int64 `bun:"vulnerability_id"`
	// Fold is what the row is about: the source package at the version it was
	// built at. Two binaries of one source are one row, because they are one
	// thing to decide about, one thing to upgrade and one rule to route.
	Fold string `bun:"fold"`
	// ComponentID is a representative of the fold — the lowest identifier —
	// so that everything read per row has a component to hang off. Which one
	// it is decides nothing a reader sees.
	ComponentID int64 `bun:"component_id"`
	// Places is how many findings sit under the row. What the cap is measured
	// against and what the disposition register expands to.
	//
	// How many packages and how many consumers — the numbers a reader is
	// shown — are counted in the second statement rather than here. They are
	// COUNT(DISTINCT), and **MariaDB answers a query with no rows at all when
	// a COUNT(DISTINCT) sits beside a window function**, silently: no error,
	// an empty page, and a total from the other statement that says there was
	// something. This one carries the window function that counts the whole
	// filtered set, so the distinct counts go where there is none.
	Places  int   `bun:"places"`
	Urgency int64 `bun:"urgency"`
	// Total is how many groups the filter admits, the same on every row.
	Total int `bun:"total"`
}

// NoDeadline is why a finding carries no deadline.
//
// There are exactly two reasons and both are deliberate — a deadline stored at
// ingest works out a deadline at ingest for everything else — so an empty cell
// would mean two intended things at once, on the one screen whose purpose is
// noticing what is running out.
type NoDeadline string

const (
	// BelowTheLine is a finding its product does not consider worth
	// triaging . Still recorded, still counted, and off the clock.
	BelowTheLine NoDeadline = "below-the-line"
	// OutOfSupport is a finding in a release that is past its end of life
	// . Nothing is going to be fixed there, so nothing is late.
	OutOfSupport NoDeadline = "out-of-support"
)

// groupKey names one group of the list.
type groupKey struct {
	vulnerabilityID int64
	fold            string
}

// pullers is how many things pull this fold's packages in here.
//
// The distinct consumers, plus the build itself where anything is pulled in
// directly: a null consumer is the product, which is one thing however many
// packages hang off it, and COUNT(DISTINCT) passes over nulls.
func (d decorated) pullers() int {
	return pullersOf(d.Consumers, d.Direct)
}

// decorated is a group of the list with what the page shows about it read in.
type decorated struct {
	groupHead
	Answered      int        `bun:"answered"`
	OpenedAt      time.Time  `bun:"opened_at"`
	DueAt         *time.Time `bun:"due_at"`
	Visibility    string     `bun:"visibility"`
	DiscloseAt    *time.Time `bun:"disclose_at"`
	LikelihoodPPM int        `bun:"likelihood_ppm"`
	ScoreCenti    int        `bun:"score_centi"`
	FixState      string     `bun:"fix_state"`
	FixedIn       string     `bun:"fixed_in"`
	Matched       string     `bun:"matched"`
	ConsumerID    *int64     `bun:"consumer_id"`
	Consumers     int        `bun:"consumers"`
	Direct        int        `bun:"direct"`
	// Packages is how many binaries of the fold sit here and ConsumerPlaces
	// how many things pull them in — the two numbers a reader is shown.
	Packages       int   `bun:"packages"`
	ConsumerPlaces int   `bun:"consumer_places"`
	Builds         int   `bun:"builds"`
	TargetID       int64 `bun:"target_id"`
	AnyClaim       int   `bun:"any_claim"`
	Waiting        int   `bun:"waiting_here"`
	Approved       int   `bun:"approved_here"`
	Lapsed         int   `bun:"lapsed_here"`
	SentBack       int   `bun:"sent_back_here"`
}

// heads reads one page of the findings list's groups, most urgent first, from
// finding's covering index and nothing else, and how many groups there are.
//
// The total rides on the page. It is counted through the same filter as the
// page — a total that ignores the narrowing is worse than no total: it
// reports how much there is to decide about, which is the figure people
// quote, while the list beside it shows something else — and it used to be
// a second statement making the same grouping over the same rows to count
// what the first had just grouped. `COUNT(*) OVER ()` is the number of rows
// the grouping produced after the HAVING clauses and before the limit,
// which is exactly that, on all four engines (window functions are in each
// of them), for the cost of nothing. Where the page comes back empty — an
// offset past the end — there is no row to carry it and it is counted
// separately.
func (s *Store) heads(ctx context.Context, targets []int64, visible []access.Visibility,
	limit, offset int, filter Filter) ([]groupHead, int, error) {

	var heads []groupHead
	page := s.db.NewSelect().
		TableExpr("finding AS f").
		// The fold, which is the unit a person acts in: two binaries of one
		// source package are one row, because upgrading them is one act,
		// deciding about them is one judgment and routing them is one rule.
		// A reader with no way to see that was reading a list a third of
		// which was the same work said again.
		Join("JOIN component AS c ON c.id = f.component_id").
		ColumnExpr("f.vulnerability_id AS vulnerability_id").
		ColumnExpr(FoldedOn+" AS fold").
		ColumnExpr("MIN(f.component_id) AS component_id").
		ColumnExpr("COUNT(*) AS places").
		// The most urgent place this issue sits at. A group is one decision
		// about one issue at one fold, so what should decide where that
		// decision appears is the worst of what it covers.
		ColumnExpr("MAX(f.urgency) AS urgency").
		ColumnExpr("COUNT(*) OVER () AS total").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.vulnerability_id, " + FoldedOn)
	// The issue is joined only where the order needs it. The default page
	// reads finding's covering index and nothing else, which is what makes it
	// a page rather than a scan, and a join added for everybody would pay for
	// a sort almost nobody asks for.
	if by, known := order[filter.SortBy]; known && by.issue {
		page = page.Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id")
	}
	page = page.
		// Ordered by urgency unless somebody asked otherwise. Urgency
		// rather than how widespread something is: sorting by place
		// count puts whatever ships in the most places at the top,
		// which on a real image is the kernel — everywhere, and not
		// therefore the thing to look at first. What somebody with an
		// hour needs at the top is what is being exploited.
		//
		// The expression comes from the allowlist and never from the
		// request , and the tie-break is always the same pair so that
		// paging is stable: two rows equal on the sorted column must
		// not swap between pages, or a page boundary drops one and
		// repeats another.
		OrderExpr(sortedBy(filter)).
		Limit(limit).Offset(offset)
	if err := filter.narrow(page).Scan(ctx, &heads); err != nil {
		return nil, 0, fmt.Errorf("read what is open: %w", err)
	}
	if len(heads) > 0 {
		return heads, heads[0].Total, nil
	}
	counted := s.db.NewSelect().
		TableExpr("finding AS f").
		ColumnExpr("f.vulnerability_id").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.vulnerability_id, f.component_id")
	total, err := s.db.NewSelect().
		TableExpr("(?) AS grouped", filter.narrow(counted)).
		Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what is open: %w", err)
	}
	return heads, total, nil
}

// sortedBy is the ORDER BY the list is paged with.
//
// Built from the allowlist alone. The only thing a caller decides is which of
// the fixed keys and which direction, and neither reaches the statement as
// text: the key selects a stored expression, and the direction selects one of
// two words written here.
//
// A finding with no deadline sorts last whichever way it is asked, because "no
// deadline" is not early and not late. That is spelled as a leading
// null-ordering column rather than as NULLS LAST, which two of the four
// engines do not have.
func sortedBy(filter Filter) string {
	by, known := order[filter.SortBy]
	if !known {
		by = order[ByUrgency]
	}
	way := "DESC"
	if filter.Ascending {
		way = "ASC"
	}
	sorted := by.expr + " " + way
	if filter.SortBy == ByDeadline {
		sorted = "CASE WHEN " + by.expr + " IS NULL THEN 1 ELSE 0 END, " + sorted
	}
	// Always the same tie-break, so that paging is stable: two rows equal on
	// the sorted column must not swap between pages, which drops one row and
	// repeats another across a boundary.
	//
	// The fold rather than a component, because that is what the rows are
	// grouped by — MySQL refuses an ordering on a column the grouping does not
	// determine, and it is right to: a tie-break on a column that varies
	// within a row is not a tie-break at all.
	return sorted + ", f.vulnerability_id, " + FoldedOn
}

// decorate reads what the page shows about each of its groups, in one
// statement over the groups named and no other.
//
// Narrowed through the same filter as the groups were chosen by, so every
// number here is over exactly the places the group was counted over: a list
// narrowed to what sits inside one container reports how many of *those*
// places are answered, not how many places there are anywhere.
func (s *Store) decorate(ctx context.Context, targets []int64, productID int64,
	visible []access.Visibility, heads []groupHead, filter Filter) (map[groupKey]decorated, error) {

	known := make(map[groupKey]decorated, len(heads))
	if len(heads) == 0 {
		return known, nil
	}
	issues := make([]int64, 0, len(heads))
	folds := make([]string, 0, len(heads))
	for _, head := range heads {
		issues = append(issues, head.VulnerabilityID)
		folds = append(folds, head.Fold)
	}

	// How far each group has been decided, counted the way the state filter
	// counts it, so the row and the filter cannot disagree. Four correlated
	// counts over our decisions in this product at each place and at the
	// versions the place holds, plus whether any live claim is with its
	// author.
	decided := func(alias, condition string) string {
		return `SUM(CASE WHEN EXISTS (SELECT 1 FROM "decision" AS de
			WHERE de.product_id = ?
			  AND de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND ` + coversHere + condition + `) THEN 1 ELSE 0 END) AS ` + alias
	}
	var rows []decorated
	q := s.db.NewSelect().
		TableExpr("finding AS f").
		// Joined for the likelihood and the score. Likelihood ranks above
		// severity, so a list that orders by it and does not show it looks
		// unsorted.
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		// And for the versions a decision is keyed on. Two primary-key
		// lookups per place on the page, so the correlated counts can ask
		// whether a claim is about the versions shipping here rather than
		// about the place at whatever versions it once held.
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("LEFT JOIN component AS uc ON uc.id = f.consumer_id").
		ColumnExpr("f.vulnerability_id AS vulnerability_id").
		ColumnExpr(FoldedOn+" AS fold").
		ColumnExpr("MIN(f.component_id) AS component_id").
		ColumnExpr("MAX(COALESCE(v.likelihood_ppm, 0)) AS likelihood_ppm").
		ColumnExpr("MAX(COALESCE(v.score_centi, 0)) AS score_centi").
		ColumnExpr("SUM(CASE WHEN f.suppressed_by IS NULL THEN 0 ELSE 1 END) AS answered").
		// When the earliest of these places opened, and the earliest deadline
		// any of them carries. The age a deadline relates to is this one, not
		// the year in the identifier.
		ColumnExpr("MIN(f.opened_at) AS opened_at").
		ColumnExpr("MIN(f.due_at) AS due_at").
		// Whether anything here is undisclosed, and when the earliest embargo
		// ends. MAX on the word rather than a flag: "private" sorts after
		// "public", so a group with one undisclosed place among fifty reads as
		// undisclosed — which is what it is, for anybody deciding what may be
		// said about it.
		ColumnExpr("MAX(f.visibility) AS visibility").
		ColumnExpr("MIN(f.disclose_at) AS disclose_at").
		ColumnExpr("MIN(f.fix_state) AS fix_state").
		ColumnExpr("MIN(f.fixed_in) AS fixed_in").
		// Any of them: a group is an issue at a component, every place of it
		// comes from one line of a scanner's report, and the applier writes
		// that line to all of them.
		ColumnExpr("MIN(COALESCE(f.matched, '')) AS matched").
		// One of the ways down, and how many there are. MIN passes over the
		// places the build pulls in directly, whose consumer is null, so those
		// are counted separately rather than being read as "no route at all".
		ColumnExpr("MIN(f.consumer_id) AS consumer_id").
		ColumnExpr("COUNT(DISTINCT f.consumer_id) AS consumers").
		// The other number a reader is shown, counted here rather than beside
		// the window function that pages the list — see groupHead. The
		// consumers are already counted just above, and a distinct count of
		// place identities would not do: a place is a package under a
		// consumer, so across a fold of three packages that is the place count
		// with a different word on it.
		ColumnExpr("COUNT(DISTINCT f.component_id) AS packages").
		ColumnExpr("SUM(CASE WHEN f.consumer_id IS NULL THEN 1 ELSE 0 END) AS direct").
		// How many builds in the selection hold this group, and one of them to
		// name. Both are one where the selection is a single build, which is
		// why the row says nothing about either there.
		ColumnExpr("COUNT(DISTINCT f.target_id) AS builds").
		ColumnExpr("MIN(f.target_id) AS target_id").
		ColumnExpr(decided("any_claim", ""), productID).
		ColumnExpr(decided("waiting_here", " AND de.state = ? AND de.live_key IS NOT NULL"),
			productID, "proposed").
		ColumnExpr(decided("approved_here", " AND de.state = ? AND de.live_key IS NOT NULL"),
			productID, "approved").
		ColumnExpr(decided("lapsed_here", " AND de.state = ?"), productID, "lapsed").
		ColumnExpr(decided("sent_back_here",
			" AND de.state = ? AND de.live_key IS NOT NULL AND de.sent_back_at IS NOT NULL"),
			productID, "proposed").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		// The page's issues and the page's folds, as two lists. That admits an
		// issue from one row at the fold of another, and those groups are read
		// and dropped; what it buys is the index. As fifty
		// `(issue = ? AND fold = ?)` pairs joined by OR, SQLite walked every
		// open row in the build against the fifty — 150 ms, half the page —
		// where two lists are fifty index seeks, 2 ms. A page is mostly one
		// package's issues, so the extra groups are few, and each is one seek
		// too.
		Where("f.vulnerability_id IN (?)", bun.List(issues)).
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		GroupExpr("f.vulnerability_id, " + FoldedOn)
	if err := filter.narrow(q).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read about what is open: %w", err)
	}
	for _, row := range rows {
		known[groupKey{row.VulnerabilityID, row.Fold}] = row
	}
	return known, nil
}

// ends reduces a way down to the two steps worth showing and a count of what
// was left out.
//
// The chain arrives build-first. The build itself is not one of the two: every
// row in a list scoped to one build shares it, so naming it in every row says
// nothing and costs the width that the parts which differ need.
// Ends returns the two ends of a way down and how many steps sit between
// them: the part of the product a component belongs to, and what directly
// pulls it in. Exported because a decision is described the same way
// wherever it is listed, and a second spelling of which step is which is how
// two screens disagree about where a component sits.
func Ends(down []graph.Step) (owner, parent string, middle int) {
	switch len(down) {
	case 0:
		// The inventory placed the component nowhere. Saying so is the honest
		// answer; claiming the product itself pulls it in is a comfortable
		// sentence and not a true one.
		return "", "", 0
	case 1:
		// The build pulls it in directly, so both ends are the build.
		return down[0].Name, down[0].Name, 0
	}
	owner = down[1].Name
	parent = down[len(down)-1].Name
	// Everything between the two named steps.
	if middle = len(down) - 3; middle < 0 {
		middle = 0
	}
	return owner, parent, middle
}

// firstLineOf is as much of a description as a row can carry: the first line
// or the first sentence, whichever ends sooner, and nothing where there is
// none.
//
// Cut here rather than on the screen, so that every reader of the list gets
// the same summary — an export and a row disagreeing about what an issue says
// would be two answers to one question — and so that a page of fifty does not
// carry fifty paragraphs in order to render one line each.
func firstLineOf(description string) string {
	said := strings.TrimSpace(description)
	if said == "" {
		return ""
	}
	if cut := strings.IndexAny(said, "\n\r"); cut > 0 {
		said = said[:cut]
	}
	// The stop and the space after it, rather than the stop alone: a version
	// number in the middle of a sentence is not the end of one.
	if stop := strings.Index(said, ". "); stop > 0 {
		said = said[:stop+1]
	}
	const most = 160
	if len(said) > most {
		if space := strings.LastIndex(said[:most], " "); space > 0 {
			return strings.TrimSpace(said[:space]) + "…"
		}
		return said[:most] + "…"
	}
	return strings.TrimSpace(said)
}

// issuesNamed reads what these issues are called and how bad they are said to be.
func issuesNamed(ctx context.Context, db *bun.DB, ids []int64) (map[int64]Vulnerability, error) {
	held := map[int64]Vulnerability{}
	if len(ids) == 0 {
		return held, nil
	}
	var issues []Vulnerability
	if err := db.NewSelect().Model(&issues).
		// The description too, for the one line the row shows of it. One
		// lookup for the page either way, and the row is already being read
		// for the identifier beside it.
		Column("id", "identifier", "severity", "description").
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these issues are: %w", err)
	}
	for _, issue := range issues {
		held[issue.ID] = issue
	}
	return held, nil
}

// componentsNamed reads what these components are, including the upstream they
// were cut from where one is known.
func componentsNamed(ctx context.Context, db *bun.DB, ids []int64) (map[int64]graph.Component, error) {
	held := map[int64]graph.Component{}
	if len(ids) == 0 {
		return held, nil
	}
	var components []graph.Component
	if err := db.NewSelect().Model(&components).
		Column("id", "purl", "name", "version", "upstream_name", "upstream_version").
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these components are: %w", err)
	}
	for _, component := range components {
		held[component.ID] = component
	}
	return held, nil
}

// AtComponent lists the open issues against one component of a build, with
// every place each one occupies.
//
// Every place, because a decision is keyed on one — so a claim built from a
// single arbitrary place would silence one consumer and leave the others open
// while reporting that it had covered them.
//
// The set somebody narrows before claiming something about all of it. What
// narrows it is theirs — a text match on what a report says is how a candidate
// is found, never why a claim is true.
func (s *Store) AtComponent(ctx context.Context, subject access.Subject, targetID,
	componentID int64, contains string, limit, offset int) ([]Deciding, int, error) {

	at, total, _, err := s.atComponent(ctx, subject, targetID, componentID, contains,
		limit, offset)
	return at, total, err
}

// SizeAtComponent is how large a claim over the whole narrowed set would be:
// how many issues, and how many findings those sit at.
//
// The second number is the one that matters and the one nothing showed. The
// bound on a bulk action is on rows written rather than on names typed , so a
// screen counting issues against a cap counting findings tells somebody 44
// when the answer is 2,000 — and it tells them after they have typed the
// reasoning.
func (s *Store) SizeAtComponent(ctx context.Context, subject access.Subject, targetID,
	componentID int64, contains string) (issues, places int, err error) {

	_, issues, places, err = s.atComponent(ctx, subject, targetID, componentID, contains, 1, 0)
	return issues, places, err
}

func (s *Store) atComponent(ctx context.Context, subject access.Subject, targetID,
	componentID int64, contains string, limit, offset int) ([]Deciding, int, int, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, 0, 0, err
	}
	visible := access.Visible(subject, productID)
	if !subject.Sees(productID) || len(visible) == 0 {
		return nil, 0, 0, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	limit = database.AComponentsWorth.Of(limit)

	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.TableExpr("finding AS f").
			Where("f.target_id = ?", targetID).
			Where("f.component_id = ?", componentID).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible))
		if contains != "" {
			// Matched against what a report says, which is all that is held
			// about where a flaw lives. Nothing here knows a kernel from a
			// font library. Asked as a membership test rather than a join so
			// the grouping stays on finding's covering index.
			q = q.Where("f.vulnerability_id IN (?)",
				q.NewSelect().TableExpr("vulnerability AS v").Column("v.id").
					Where("LOWER(v.description) LIKE ?", "%"+strings.ToLower(contains)+"%"))
		}
		return q
	}

	// The page in two statements, as the findings list is read: which issues,
	// off the covering index, and then what is shown about each. On a real
	// image one component holds most of the build's open rows — the kernel,
	// 222,435 of 272,539 — and grouping them with three joins under the
	// aggregate cost 0.35 s where the index alone answers in 0.04 s. The
	// total rides on the page, as the findings list's does.
	var heads []struct {
		VulnerabilityID int64 `bun:"vulnerability_id"`
		Places          int   `bun:"places"`
		Total           int   `bun:"total"`
	}
	// How many findings the whole narrowed set holds, which is what a bulk
	// action is bounded against and what a screen counting issues
	// cannot say. Counted over the same narrowing rather than summed from the
	// page: a page is fifty of eight hundred.
	reaching, err := narrow(s.db.NewSelect()).ColumnExpr("f.id").Count(ctx)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("count how far these reach: %w", err)
	}
	err = narrow(s.db.NewSelect()).
		ColumnExpr("f.vulnerability_id AS vulnerability_id").
		ColumnExpr("COUNT(*) AS places").
		ColumnExpr("COUNT(*) OVER () AS total").
		GroupExpr("f.vulnerability_id").
		OrderExpr("MAX(f.urgency) DESC, f.vulnerability_id").
		Limit(limit).Offset(offset).
		Scan(ctx, &heads)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read what is open against this component: %w", err)
	}
	total := 0
	if len(heads) > 0 {
		total = heads[0].Total
	} else {
		// Grouped and counted, not COUNT DISTINCT: with no GROUP BY, Count()
		// emits its own count(*) and the expression never reaches the
		// statement, so the total counted places while the list counts
		// issues.
		if total, err = s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`, narrow(s.db.NewSelect()).
				ColumnExpr("f.vulnerability_id").GroupExpr("f.vulnerability_id")).
			Count(ctx); err != nil {
			return nil, 0, 0, fmt.Errorf("count what is open against this component: %w", err)
		}
	}
	issues := make([]int64, 0, len(heads))
	for _, head := range heads {
		issues = append(issues, head.VulnerabilityID)
	}

	type shown struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Severity        int    `bun:"severity_centi"`
		FixedIn         string `bun:"fixed_in"`
	}
	about := map[int64]shown{}
	if len(issues) > 0 {
		var rows []shown
		err = s.db.NewSelect().
			TableExpr("finding AS f").
			Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
			ColumnExpr("f.vulnerability_id AS vulnerability_id").
			ColumnExpr("MIN(COALESCE(v.score_centi, 0)) AS severity_centi").
			ColumnExpr("MIN(COALESCE(f.fixed_in, '')) AS fixed_in").
			Where("f.target_id = ?", targetID).
			Where("f.component_id = ?", componentID).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible)).
			Where("f.vulnerability_id IN (?)", bun.List(issues)).
			GroupExpr("f.vulnerability_id").
			Scan(ctx, &rows)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("read about what is open against this component: %w", err)
		}
		for _, row := range rows {
			about[row.VulnerabilityID] = row
		}
	}

	// Every place, fetched for the page of issues rather than one arbitrary
	// place per issue. A decision is keyed on a place, so a claim built from
	// MIN(place_identity) covers one consumer and leaves the rest open while
	// reporting that it covered them.
	everywhere, err := s.placesOf(ctx, targetID, componentID, issues, visible)
	if err != nil {
		return nil, 0, 0, err
	}

	at := make([]Deciding, 0, len(heads))
	for _, head := range heads {
		row := about[head.VulnerabilityID]
		for _, place := range everywhere[head.VulnerabilityID] {
			place.ProductID = productID
			place.VulnerabilityID = head.VulnerabilityID
			place.SeverityCenti = row.Severity
			place.FixedIn = row.FixedIn
			place.Places = head.Places
			at = append(at, place)
		}
	}
	return at, total, reaching, nil
}

// placesOf reads every place a set of issues occupies at one component.
func (s *Store) placesOf(ctx context.Context, targetID, componentID int64, issues []int64,
	visible []access.Visibility) (map[int64][]Deciding, error) {

	everywhere := map[int64][]Deciding{}
	if len(issues) == 0 {
		return everywhere, nil
	}
	var rows []struct {
		VulnerabilityID   int64  `bun:"vulnerability_id"`
		PlaceIdentity     string `bun:"place_identity"`
		Visibility        string `bun:"visibility"`
		ComponentUpstream string `bun:"component_upstream"`
		ConsumerUpstream  string `bun:"consumer_upstream"`
	}
	err := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("LEFT JOIN component AS uc ON uc.id = f.consumer_id").
		ColumnExpr("f.vulnerability_id AS vulnerability_id").
		ColumnExpr("f.place_identity AS place_identity").
		ColumnExpr("f.visibility AS visibility").
		ColumnExpr(ComponentUpstreamExpr+" AS component_upstream").
		ColumnExpr(ConsumerUpstreamExpr+" AS consumer_upstream").
		Where("f.target_id = ?", targetID).
		Where("f.component_id = ?", componentID).
		Where("f.closed_at IS NULL").
		Where("f.vulnerability_id IN (?)", bun.List(issues)).
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.vulnerability_id, f.place_identity, f.visibility, c.upstream_version, c.version, uc.upstream_version, uc.version").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where these sit: %w", err)
	}
	for _, row := range rows {
		everywhere[row.VulnerabilityID] = append(everywhere[row.VulnerabilityID], Deciding{
			PlaceIdentity:     row.PlaceIdentity,
			Visibility:        access.AsVisibility(row.Visibility),
			ComponentUpstream: row.ComponentUpstream, ConsumerUpstream: row.ConsumerUpstream,
		})
	}
	return everywhere, nil
}

// ComponentGroup is one component at one version, with what is open against it
// counted rather than listed.
//
// The level above a findings list. A list of issues answers "what is wrong";
// this answers "where is the weight", which is the question somebody asks
// before deciding what to read and what to put aside. It is also how a person
// finds the one package worth hiding: on a real image the kernel carried 4,943
// of 6,822 rows, and no list of issues makes that visible — it just looks like
// a long list. Candidate is a version that would close some of what is open
// against a component, and how much of it.
//
// This is the fix-bundle grouping read per component rather than as a list of
// its own: a package at a version, and where it could go. It sat on a view of
// its own, which put the version bump — the thing somebody acts on — on a
// different screen from the package it belongs to.
type Candidate struct {
	To     string
	Issues int
}

type ComponentGroup struct {
	Component string
	Version   string
	// Upstream is what a fork was cut from, carried for the same reason it is
	// carried on a finding: a version nobody recognizes needs it.
	Upstream string
	// UpstreamName is the source package this was built from, where one is
	// recorded. It is what a routing rule matches on, and without it a
	// component row cannot say what a rule about it would have to name — so
	// somebody types the binary package's own name into a field matching
	// source packages and is told, truthfully and uselessly, that nothing is
	// called that.
	UpstreamName string
	// Ecosystem is the kind of package, carried for the same reason a
	// finding's row carries it: a name at a version does not tell two rows
	// apart on its own.
	Ecosystem string
	// BySeverity is those issues by how they were rated, and Worst the
	// highest band among them. Ranking by count alone answers the question
	// this view asks with the opposite of what somebody needs: a package with
	// forty-four issues outranks one with three criticals, and the count
	// beside it says nothing about which.
	BySeverity map[string]int
	Worst      string
	// Issues is how many distinct vulnerabilities are open against it, which
	// is how many rows it contributes to the findings list.
	Issues int
	// Places is how many times those sit somewhere in the build. The two
	// differ by orders of magnitude on shared code and the gap is the point:
	// one kernel issue reaching four hundred modules is one decision.
	Places int
	// Upgrades are the versions upstream has released that would close
	// some of what is open here, each with how many issues it would close.
	//
	// **Listed, never ordered.** Comparing two of these needs an ordering per
	// ecosystem that this does not have, so there is no "nearest"
	// and no "latest" — what there is, is every version the scanner named as
	// carrying a fix, and the count is what makes one of them obviously worth
	// taking. Most components have exactly one.
	Upgrades []Candidate
	// Exploited says whether any of them is known-exploited, which is what
	// stops a component being put aside on the strength of its size alone.
	Exploited bool
	Urgency   int64
}
