// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"
)

// KeyMatches says a decision occurrence `de` covers the versions a finding's
// component `c` and consumer `uc` hold now, as the versions are compared
// everywhere a decision is looked up for a finding. A row stores no
// version where nothing stated one; the finding's expression reads that as
// empty, so the two absences are compared as the same absence.
//
// A decision that the scanner matched something that is not here covers the
// occurrence whatever it now holds, because the versions are not what it is
// about. A decision about a lead does too, because a lead's occurrence is the
// lead. Their own version columns record what each was made against and are not
// compared.
//
// The four aliases are the caller's to join: a finding's own row carries only
// the identifiers, the versions are on the components, and the outcome is on
// the decision. Which outcome it is, rather than a copy of the answer on the
// decision occurrence: the outcome never moves once a decision is written —
// revising changes reasoning — so it is derivable at any moment, and a derived
// value is stored here only where a measurement asks for it. Exported because
// the same question is asked outside this package: what is undecided is what
// the notification sweep means by work sitting still, and a second spelling of
// it would be a second definition of "decided".
const KeyMatches = `("cl"."outcome" IN (` + anyVersionList + ") OR (" + VersionsMatch + "))"

// VersionsMatch says a decision occurrence `de` was written against the
// versions a finding's component `c` and consumer `uc` hold now, which is the
// half of KeyMatches every outcome but a wrong match is held to. A row stores
// no version where nothing stated one, and the finding's expression reads that
// as empty, so the two absences compare as the same absence.
const VersionsMatch = componentMatches + " AND " + consumerMatches

// componentMatches and consumerMatches are the two halves of VersionsMatch.
const (
	componentMatches = `COALESCE("de"."component_upstream_version", '') = ` + ComponentUpstreamExpr
	consumerMatches  = `COALESCE("de"."consumer_upstream_version", '') = ` + ConsumerUpstreamExpr
)

// keyMatchesOn is KeyMatches over a decision occurrence under another alias,
// with the decision's outcome given as an expression, for a statement that asks
// it before the decision is joined or of a second decision occurrence beside
// the first.
//
// Derived from KeyMatches by renaming its two references rather than written
// out again, so the rule has one spelling. KeyMatches stays a constant because
// other constants are built from it.
func keyMatchesOn(occurrence, outcome string) string {
	return strings.NewReplacer(`"cl"."outcome"`, outcome, `"de".`, `"`+occurrence+`".`).Replace(KeyMatches)
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

// DecisionAt is the one spelling of a decision occurrence `de`, read beside
// `dv` through Decisions, being about the finding `f`: the same product, the
// same issue and the same occurrence.
//
// The same issue is asked of `dv.issue_id`, because a decision occurrence filed
// under an issue that later merged into the finding's is about the finding's
// issue. An occurrence identity carries no product, so the product is named
// too: without it a decision made in every other product that ships the same
// component under the same consumer would match.
//
// product is how the query names the finding's product: a bound number, the
// stream it has joined, or the decision's own product where the query is
// already narrowed to it. Anything else is a programming error, because it is
// placed in the statement as written.
func DecisionAt(product string) string {
	switch product {
	case "?", `"st"."product_id"`, `"de"."product_id"`:
	default:
		panic("finding.DecisionAt: " + product + " is not a product the statement names")
	}
	return `"de"."product_id" = ` + product + " AND " + DecisionAtOccurrence("f")
}

// DecisionAtOccurrence is the issue and the occurrence of DecisionAt without
// the product, for a statement that holds the product another way: the
// finding's build joined to the decision's product, a build of it bound, or the
// decision's product compared beside it. A statement holding the product in no
// way matches decision occurrences of every product that ships the occurrence.
//
// finding is the alias the statement gives the finding, from the ones code
// names. Anything else is a programming error, because it is placed in the
// statement as written.
func DecisionAtOccurrence(finding string) string {
	return decidedOccurrenceIn(`"dv"."issue_id"`, `"de"."occurrence_identity"`, finding)
}

// DecisionFiledAt is DecisionAtOccurrence for a statement that reads a decision
// occurrence without the issue it is filed under, so the issue is asked through
// SameIssue. occurrence is `de` or `dc`, the aliases code gives a decision
// occurrence.
func DecisionFiledAt(occurrence, finding string) string {
	switch occurrence {
	case "de", "dc":
	default:
		panic("finding.DecisionFiledAt: " + occurrence + " is not a decision occurrence the statement names")
	}
	findingAlias(finding)
	return SameIssue(`"`+finding+`"."vulnerability_id"`, `"`+occurrence+`"."vulnerability_id"`) +
		` AND "` + occurrence + `"."occurrence_identity" = "` + finding + `"."occurrence_identity"`
}

// decidedOccurrenceIn is the issue and the occurrence of a decision occurrence,
// under the columns given, being the finding's.
func decidedOccurrenceIn(issue, occurrence, finding string) string {
	findingAlias(finding)
	return issue + ` = "` + finding + `"."vulnerability_id" AND ` + occurrence + ` = "` + finding + `"."occurrence_identity"`
}

// findingAlias refuses a finding alias that no statement here gives one.
func findingAlias(finding string) {
	switch finding {
	case "f", "f2", "g", "fc", "cf", "bf", "pf":
	default:
		panic("finding: " + finding + " is not a finding the statement names")
	}
}

// coversHere says a decision occurrence `de` is about the finding it was
// correlated with by issue and occurrence, for the counts behind the state a
// row carries and the state filter that finds it.
//
// A live decision covers an occurrence at the versions it was keyed on and no
// other: matched by occurrence alone, a decision approved against libnl 3.7.0
// in one build answers for libnl 3.9.0 at the same occurrence in the next,
// while everything that asks whether a decision actually applies says it covers
// nothing there. A decision with no key has lapsed or been withdrawn, and by
// definition its versions no longer match — what it says about the occurrence
// is history, and it is matched by occurrence so that "lapsed" can be said at
// all.
const coversHere = `("de"."live_key" IS NULL OR (` + KeyMatches + "))"

// byState joins what each occurrence has been decided as, for the conditions
// statesHaving asks of a group.
//
// Every one of those is a condition over the *group* rather than over an
// occurrence, so they are HAVING clauses: a group is undecided when none of its
// occurrences has a decision, not when one of them does not. This half is the
// join, which is asked of each occurrence and so sits wherever the occurrences
// are read. The list's own groups count the decided occurrences beside their
// first level instead (see decidedBeside), a page's rows need neither (see
// ofPage), and this join serves the groups another view keeps where the filter
// needs a decision (see Filter.listed).
//
// These read the decision table and nothing else. `suppressed_by` is not a
// decision of ours at all: it points at a suppression, and a suppression is a
// claim the *build* made in its own scan file (only internal/sbom ever writes
// one), so reading it would make "agreed" mean "the vendor's SBOM argued this
// away" — a claim by a different author that nobody here reviewed — and would
// leave a decision actually approved by a second person matching none of the
// four states. What the build argued away is a real number and the row already
// carries it separately, as how many occurrences are answered; it is not how
// far *we* have decided.
//
// Read from the decision occurrences outward, not from the findings inward.
// What is joined is the set of open finding rows that have a decision of ours
// in this product, with what kind — built once from the decision occurrences,
// which holds hundreds of rows where finding holds hundreds of thousands, and
// joined to the grouping by the finding's own identifier. Asked the other way
// round, as a correlated lookup per finding row, it runs once for every open
// row in the build to say which groups have nothing: 241,479 probes to answer
// "undecided" on a build with no decision occurrences at all. The counts are
// the same either way; an occurrence with two decisions is one occurrence,
// which is what folding to one row per finding keeps true.
//
// A decision occurrence belongs to a product and the two keys linking one to a
// finding do not: an issue is one row per identifier for the whole deployment,
// and an occurrence identity is a hash of a consumer and a component with no
// product in it (see OccurrenceIdentity — deliberately, so an occurrence is
// recognized across variants). Joined on those two alone this would match
// decision occurrences in *every* product, which reports somebody else's triage
// as this product's state and tells a reader that a decision is pending in a
// product they cannot see; the product is a condition on the decision
// occurrence for that reason.
func (f Filter) byState(q *bun.SelectQuery) *bun.SelectQuery {
	// The planned filter reads the same derived table, so asking for it is a
	// reason to build it even where no state or outcome was asked for. Where
	// the first level counts the decided occurrences beside itself, nothing is
	// joined to the occurrences here.
	if !f.asksDecided() || f.decidedApart {
		return q
	}
	// Built on decisionsOutward, which matches a decision occurrence to the
	// occurrences it covers at the versions they hold now, and bound to the one
	// product the view narrows inside. A list spanning products counts its
	// decided occurrences beside its first level, so it never reaches this
	// join.
	decided := f.flagColumns(decisionsOutward(q))
	if f.decidedIssues != nil {
		// On the decision occurrences, for the reason decidedBeside gives.
		decided = f.amongDecidedIssues(decided, `"dv"."issue_id"`)
	}
	decided = decided.Where(`"de"."product_id" = ?`, f.ProductID)
	return q.Join(`LEFT JOIN (?) AS "dd" ON "dd"."finding_id" = "f"."id"`, decided)
}

// asksDecided is whether any condition the filter asks of a group reads the
// decision flags.
func (f Filter) asksDecided() bool {
	return len(trimmed(f.States)) > 0 || len(trimmed(f.Outcomes)) > 0 || f.Planned != PlannedEither
}

// decidedFlags is the flags flagColumns computes per occurrence, in the order
// they are selected.
var decidedFlags = []string{"waiting", "approved", "lapsed", "planned", "this_outcome"}

// flagColumns adds to a statement over decision occurrences reaching
// occurrences, read as decisionsOver reads them, one column per flag saying
// whether a decision occurrence covering the occurrence has it.
func (f Filter) flagColumns(q *bun.SelectQuery) *bun.SelectQuery {
	// A request for one, kept before the list is padded: an empty IN
	// list is a syntax error on two of the engines, so the column binds a
	// word no outcome equals — and reading the padded list as a request
	// would narrow every group to those answered "" everywhere, which is
	// none of them.
	outcomes := trimmed(f.Outcomes)
	if len(outcomes) == 0 {
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
		lapsed   = "lapsed"
	)
	// "Waiting" and "lapsed" count a decision in that state whether or not it
	// still stands; "approved" counts only the decision that currently stands,
	// because without that a decision withdrawn eighteen months ago still
	// answers for its occurrence.
	standingHere, inForce := InForce()
	return q.
		// Waiting, and standing: the row's own count requires the live key
		// and this did not, so a decision proposed and then withdrawn put its
		// group in the waiting bucket while the row drew no state word at
		// all. Both are the same question and have to be the same condition.
		// A proposal that needs nobody is in force rather than waiting, and
		// counts with the agreed ones, as the row's own counts do.
		ColumnExpr(`MAX(CASE WHEN "de"."state" = ? AND "de"."needs_approval" = ? AND "de"."live_key" IS NOT NULL`+
			` THEN 1 ELSE 0 END) AS "waiting"`, proposed, true).
		ColumnExpr(`MAX(CASE WHEN `+standingHere+` AND "de"."live_key" IS NOT NULL`+
			` THEN 1 ELSE 0 END) AS "approved"`, inForce...).
		ColumnExpr(`MAX(CASE WHEN "de"."state" = ? THEN 1 ELSE 0 END) AS "lapsed"`, lapsed).
		// A promise to upgrade standing over this occurrence. Counted only for
		// the decision that currently stands, like "approved" above: a promise
		// that was withdrawn is not one, and a finding it covered is unplanned
		// again with nothing to clean up. That is the whole argument for
		// deriving this rather than writing a tag.
		ColumnExpr(`MAX(CASE WHEN "de"."live_key" IS NOT NULL AND `+standingHere+
			` AND "cl"."outcome" = ? THEN 1 ELSE 0 END) AS "planned"`,
			append(append([]any{}, inForce...), OutcomeUpgradeNeeded)...).
		// The kind of decision standing here, counted only for the decision
		// that currently stands: a dismissal withdrawn eighteen months ago must
		// not answer for its occurrence, which is the same rule "approved"
		// above holds — and neither must one still waiting for a second person,
		// or asking what has been dismissed answers with what somebody has
		// merely proposed dismissing.
		ColumnExpr(`MAX(CASE WHEN "de"."live_key" IS NOT NULL AND `+standingHere+
			` AND "cl"."outcome" IN (?) THEN 1 ELSE 0 END) AS "this_outcome"`,
			append(append([]any{}, inForce...), bun.List(outcomes))...)
}

// decisionNeeded is a condition over a decision occurrence "de" that some
// decision at one of a group's occurrences meets wherever the group passes the
// filter, with the words it binds. Empty where a group can pass with no
// decision at all, which is the case whenever "undecided" is among the states
// asked.
//
// Each state but undecided needs a decision in that state: lapsed a lapsed
// one, waiting one waiting on a second person, agreed one in force. An outcome
// or a promised upgrade needs one in force too. The conditions a group must
// meet are joined by AND, so any one of them is a condition a passing group
// meets; the states are joined by OR, so it is all of theirs, OR-ed.
func (f Filter) decisionNeeded() (string, []any) {
	if states := trimmed(f.States); len(states) > 0 {
		if needed, args, every := neededByEach(states); every {
			return needed, args
		}
	}
	if len(trimmed(f.Outcomes)) > 0 || f.Planned == PlannedOnly {
		return strings.TrimPrefix(decisionApproved.condition, " AND "), decisionApproved.args
	}
	return "", nil
}

// neededByEach is the decision occurrences any one of these states needs,
// OR-ed, and whether each of them needs one.
func neededByEach(states []DecisionStanding) (string, []any, bool) {
	conditions := make([]string, 0, len(states))
	var args []any
	for _, state := range states {
		var needed decisionState
		switch state {
		case StandingLapsed:
			needed = decisionLapsed
		case StandingWaiting:
			needed = decisionWaiting
		case StandingAgreed:
			needed = decisionApproved
		default:
			return "", nil, false
		}
		conditions = append(conditions, "("+strings.TrimPrefix(needed.condition, " AND ")+")")
		args = append(args, needed.args...)
	}
	return "(" + strings.Join(conditions, " OR ") + ")", args, true
}

// decidedIssuesFor sets the issues a group passing the filter can be filed
// under, where the filter needs a decision to pass: the issues of the decision
// occurrences in these products meeting decisionNeeded. All is every product.
//
// The decision side is read first, because it is the small side. With 59,762
// lapsed decision occurrences among 133,549 in one product, the lapsed ones'
// issues are 1,330 of the 7,549 its open findings name, read in 19 ms. Stated
// on the list's occurrences and on the decision occurrences, they hold both to
// those issues, and the lapsed tile takes 0.44 s where it took 1.0 s. A
// decision occurrence's own versions are not compared here, so one that covers
// nothing open still names its issue: the set is a superset, and the conditions
// over a group decide what passes.
//
// Where the filter asks how far a group has been decided and a group can pass
// with no decision, undecided among the states asked, it sets the issues of
// every decision occurrence that can mark an occurrence instead: a lapsed one,
// or one holding its key. Only the decided occurrences are read among them (see
// decidedBeside).
func (s *Store) decidedIssuesFor(ctx context.Context, filter *Filter, products []int64, all bool) error {
	needed, args := filter.decisionNeeded()
	into := &filter.decidedIssues
	if needed == "" {
		if !filter.asksDecided() {
			return nil
		}
		// Every flag flagColumns computes needs one of the two: lapsed is the
		// state, and the rest require the key.
		needed, args, into = `("de"."state" = ? OR "de"."live_key" IS NOT NULL)`, []any{"lapsed"}, &filter.placedIssues
	}
	q := s.db.NewSelect().TableExpr(Decisions).
		ColumnExpr(`"dv"."issue_id"`).Distinct().
		Where(needed, args...)
	if !all {
		if len(products) == 0 {
			*into = []int64{}
			return nil
		}
		q = q.Where(`"de"."product_id" IN (?)`, bun.List(products))
	}
	issues := []int64{}
	if err := q.Scan(ctx, &issues); err != nil {
		return fmt.Errorf("read the issues decided in this way: %w", err)
	}
	*into = issues
	return nil
}

// amongDecidedIssues holds a column naming an issue to decidedIssues.
func (f Filter) amongDecidedIssues(q *bun.SelectQuery, column string) *bun.SelectQuery {
	if len(f.decidedIssues) == 0 {
		// An empty list is a syntax error on two of the engines, and an empty
		// set holds nothing.
		return q.Where("1 = 0")
	}
	return q.Where(column+" IN (?)", bun.List(f.decidedIssues))
}

// statesHaving keeps groups by how far they have been decided, over the
// derived table byState joins, at the grain g names.
func (f Filter) statesHaving(q *bun.SelectQuery, g grain) *bun.SelectQuery {
	if len(trimmed(f.Outcomes)) > 0 {
		// Every occurrence answered the same way, not merely one of them: a
		// group where one occurrence is dismissed and the rest are open is not
		// a dismissal, and listing it under "dismissed" is how a number stops
		// being one somebody can act on.
		q = q.Having(g.decided("this_outcome") + " >= " + g.occurrences())
	}
	// Each state is a condition over the group's decision counts, so a set of
	// them is those conditions OR-ed — which is what a checkbox set means and
	// what one value could not ask. Asking for all four is asking for
	// everything, and reads as no narrowing at all rather than as four
	// conditions nothing can satisfy at once.
	states := trimmed(f.States)
	wanted := make([]string, 0, len(states))
	for _, each := range states {
		if said := stateHaving(each, g); said != "" {
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
//
// Each count is a sum of flags over the group's occurrences, so it is never
// negative and never more than the occurrences. The conditions are written as
// ranges over those sums — "none" as below one, "every occurrence" as at least
// the occurrences, several "none" as one sum below one — because a planner
// estimates a range over an aggregate at a third of the groups and an equality
// at a two hundredth, and multiplies the estimates of conditions joined by AND
// as though they were independent. Undecided spelled as three equalities was
// estimated at one group of 10,283 where 6,196 pass on PostgreSQL.
func stateHaving(state DecisionStanding, g grain) string {
	waiting, approved, lapsed := g.decided("waiting"), g.decided("approved"), g.decided("lapsed")
	switch state {
	case StandingAgreed:
		return approved + " >= " + g.occurrences()
	case StandingWaiting:
		return waiting + " > 0"
	case StandingLapsed:
		// Lapsed means nothing replaced it: a decision made again at the
		// occurrence after the old one lapsed is waiting, which is what the row
		// says, and the filter has to find the row by the word it reads.
		return lapsed + " > 0 AND " + approved + " + " + waiting + " < 1"
	case StandingUndecided:
		// Nothing stands, rather than nothing was ever said. A decision that
		// has been withdrawn leaves a row that covers the occurrence and says
		// nothing about it, so a count of rows would put the finding in no
		// state at all, out of every bucket and the count above the list.
		return waiting + " + " + approved + " + " + lapsed + " < 1"
	default:
		return ""
	}
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
