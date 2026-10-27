// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

// Waiting is one decision somebody has to look at, with what an approver needs in
// order to judge it.
//
// Everything here is carried rather than left to be fetched per row. A
// reviewer works down a list, and a list where judging each row means opening
// it is a list that gets approved without being read — which is the failure
// the queue exists to prevent, arriving by a different route.
//
// One of these is one decision — one proposer's action — however many rows
// it wrote. DecisionOccurrence is a representative row: the earliest, which is the same
// on every engine and every run.
type Waiting struct {
	Decision           Decision
	DecisionOccurrence DecisionOccurrence
	// Reasoning is what the proposer wrote, as it currently stands on the
	// representative row.
	Reasoning string
	// PreviouslyApproved says this was agreed to before and came back — either
	// because the reasoning was revised under the approval or because the code
	// moved. Somebody meeting it again should know they are re-reading rather
	// than seeing it for the first time.
	PreviouslyApproved bool
	// DeferredSoFar is the total time this finding has been put off, across
	// every deferral. What decides whether a deferral needs agreement is the
	// cumulative time, not the length of the one being asked about.
	DeferredSoFar time.Duration
	// Rows, Issues and Occurrences are how big the decision is: rows written,
	// distinct issues, distinct occurrences.
	Rows, Issues, Occurrences int
	// Builds names every build the decision's rows currently cover, as the
	// branch or tag and variant display names joined with a middle dot.
	Builds []string
	// Outliers is what in a bulk set does not look like the rest. Only for a
	// decision over many issues; nil otherwise.
	Outliers *Outliers
	// Counter is what would argue against agreeing: what has been decided
	// about the same issue elsewhere, and how much else at the same occurrence
	// nobody has answered.
	Counter Counter
}

// Outliers is what an approver of a bulk decision checks instead of reading every
// row: the handful that contradict the shape of the decision.
type Outliers struct {
	// Incident, Exploited, Severe, Fixable and Unmatched count the
	// distinct issues in the decision with that property. Incident is this
	// product's own standing incident through the issue;
	// Severe is critical or high; Unmatched is an issue whose description
	// does not contain the term the set was narrowed by, where that term is
	// known.
	Incident, Exploited, Severe, Fixable, Unmatched int
	// Rows are the issues that stood out, attacked here first, then
	// exploited, then by severity. Capped, except that no issue this product
	// was attacked through is ever left off: agreeing to the decision is refused
	// while one is in it, so it is the row an approver has to set aside.
	Rows []Outlier
}

// Outlier is one issue in a bulk decision that does not look like the rest.
type Outlier struct {
	DecisionOccurrenceID int64
	// DecisionOccurrenceIDs is every row of the decision about this issue: one per occurrence.
	// Setting the issue aside sets aside all of them, because agreeing to any
	// one of its occurrences is agreeing to the issue.
	DecisionOccurrenceIDs []int64
	Vulnerability         string
	Severity              string
	Incident              bool
	Exploited             bool
	FixedIn               string
	Description           string
	// Why names which of the things made it stand out.
	Why []string
}

// outlierRows is how many outliers a queue card carries. Enough to read;
// the counts say how many there are.
const outlierRows = 20

// WaitingIn counts the decisions about one product waiting for a second person.
//
// The same population the queue lists, narrowed to one product: a number
// beside a product that counted something else from the screen it links to is
// worse than no number. Somebody asking how a product is doing is asking
// partly whether the work is stuck on somebody else.
func (s *Store) WaitingIn(ctx context.Context, subject access.Subject,
	productID int64) (int, error) {

	// The queue's own statement, so the two cannot count different things.
	q := s.waitingDecisions(subject, QueueFilter{ProductID: productID})
	total, err := s.db.NewSelect().TableExpr(`(?) AS "waiting_here"`, q).Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count what is waiting here: %w", err)
	}
	return int(total), nil
}

// waitingDecisions is the decisions with a row waiting for the reason the filter
// names, one row per decision with the newest of its rows. Grouped in the
// statement rather than afterwards, so a page is a page of decisions and a count
// counts decisions.
//
// Who is shown what depends on the reason. An approval is somebody else's
// decision the reader may agree to, and never their own: approving your own is
// refused. An expired deferral or a missed fix date asks for a new decision,
// which anybody who may decide in the product can make, the proposer
// included. In each case a decision is shown only where the reader may act on
// every row of it, because acting on a decision acts on the whole argument.
func (s *Store) waitingDecisions(subject access.Subject, filter QueueFilter) *bun.SelectQuery {
	q := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`MAX("de"."id") AS "newest"`).
		GroupExpr(`"de"."decision_id"`)
	q = waiting(q, filter.Reason, s.now())
	if filter.Reason == FixDateMissed {
		// A promise is missed only while a finding it covers is still open
		// where the reader may see it. A kept promise closes its findings and
		// leaves its date and its rows as they were.
		q = q.Where("EXISTS (?)", readableFindings(openUnder(q), subject, "f", `"st"."product_id"`))
	}
	// One product where the caller named one, and whatever else the reader
	// narrowed by. A decision is decided in a product, so this narrows the same
	// way every other list does — and zero is every product, which is what the
	// queue screen asks for.
	q = filter.narrow(q, subject)
	if filter.Reason.decides() {
		if filter.Mine {
			q = q.Where(`"de"."proposed_by" = ?`, subject.ID)
		}
		outOfReach, args := notDecidableWhere(subject, "other")
		return s.reachableDecisions(decidableBy(q, subject, "de"), outOfReach, args)
	}
	q = approvableBy(q, subject, "de")
	// Mine asks for the reader's own decisions waiting on somebody else, in the
	// same statement, so the count and the page cannot disagree about which
	// question was asked.
	//
	// Otherwise the decisions the second-person rule lets the reader agree to:
	// none of whose rows they proposed and none of whose reasoning they wrote.
	// Offered one they may not agree to, Approve refuses it for a reason the
	// list never showed.
	if filter.Mine {
		q = q.Where(`"de"."proposed_by" = ?`, subject.ID)
	} else {
		q = q.Where(`NOT EXISTS (SELECT 1 FROM "decision_occurrence" AS "own"
			WHERE "own"."decision_id" = "de"."decision_id" AND "own"."proposed_by" = ?)`, subject.ID).
			Where(`NOT EXISTS (SELECT 1 FROM "decision_revision" AS "wrote"
			WHERE "wrote"."decision_id" = "de"."decision_id" AND "wrote"."written_by" = ?)`, subject.ID)
	}
	outOfReach, args := notApprovableWhere(subject, "other")
	return s.reachableDecisions(q, outOfReach, args)
}

// reachableDecisions keeps the decisions of the grouped statement with no row
// meeting outOfReach, a condition on decision_occurrence AS "other", and reads the
// grouped statement's two columns.
//
// Whether any row of a decision is out of the reader's reach is a question about
// the decision, so it is asked of each decision once the rows are grouped: a decision
// covering three hundred occurrences would otherwise ask it three hundred times and
// get the same answer.
//
// It is asked by the statement over the grouping, as a join that finds no row.
// PostgreSQL prices a correlated condition in a HAVING once per group at the
// cost of running it alone, which puts a 30 ms statement past the price at
// which it compiles the plan before running it. A NOT EXISTS over the grouping
// MySQL answers by reading every row to build the set of decisions with a
// row out of reach; the join it answers from an index.
func (s *Store) reachableDecisions(grouped *bun.SelectQuery, outOfReach string, args []any) *bun.SelectQuery {
	return s.db.NewSelect().TableExpr(`(?) AS "waiting"`, grouped).
		ColumnExpr(`"waiting"."decision_id" AS "decision_id"`).
		ColumnExpr(`"waiting"."newest" AS "newest"`).
		Join(`LEFT JOIN "decision_occurrence" AS "other" ON "other"."decision_id" = "waiting"."decision_id" AND (`+
			outOfReach+`)`, args...).
		Where(`"other"."id" IS NULL`)
}

// QueueReason is why a decision waits in the review queue. Each reason is its own
// list, with its own audience and its own acts.
type QueueReason string

const (
	// ForApproval is a decision waiting for a second person to agree to it.
	ForApproval QueueReason = "approval"
	// DeferralExpired is a deferral whose date has passed.
	DeferralExpired QueueReason = "expired-deferral"
	// FixDateMissed is a promise of an upgrade or a patch whose date has
	// passed with the finding still open.
	FixDateMissed QueueReason = "missed-fix-date"
)

// QueueReasons is every reason, in the order the queue offers them.
func QueueReasons() []QueueReason { return []QueueReason{ForApproval, DeferralExpired, FixDateMissed} }

// decides reports whether the reason asks for a new decision rather than an
// agreement.
func (r QueueReason) decides() bool { return r == DeferralExpired || r == FixDateMissed }

// QueueFilter narrows the review queue. The zero value is every decision waiting
// on the reader, in every product they may approve in.
type QueueFilter struct {
	// Reason is which list: the zero value is decisions waiting for approval.
	Reason QueueReason
	// Mine asks for what the reader proposed instead of what waits on them.
	Mine bool
	// ProductID is one product, or zero for every one.
	ProductID int64
	// ProposedBy keeps the decisions these people made. Nil asks nothing; an
	// empty, non-nil list is a name that resolved to nobody and keeps
	// nothing, so a filter that could not be applied never widens the list.
	ProposedBy []int64
	// ProposedBefore keeps decisions older than this moment, on the clock the
	// age beside each entry is read from.
	ProposedBefore *time.Time
	// Severities keeps decisions covering an issue rated one of these words in
	// its own product, which is the rating in force there.
	Severities []string
	// Outcomes keeps decisions of these kinds.
	Outcomes []Outcome
	// BranchOrTag keeps decisions that currently cover an open finding in a
	// branch or tag of this name, matched the way a build's own names are.
	BranchOrTag string
}

// narrow applies the filter to a grouped query over decision_occurrence AS de.
//
// Every condition is on a row, so a decision is kept where one of its waiting
// rows satisfies all of them. The rows a decision is shown with are read
// afterwards and whole, so narrowing never shows part of a decision.
func (f QueueFilter) narrow(q *bun.SelectQuery, subject access.Subject) *bun.SelectQuery {
	if f.ProductID != 0 {
		q = q.Where(`"de"."product_id" = ?`, f.ProductID)
	}
	if f.ProposedBy != nil {
		if len(f.ProposedBy) == 0 {
			return q.Where("1 = 0")
		}
		q = q.Where(`"de"."proposed_by" IN (?)`, bun.List(f.ProposedBy))
	}
	if f.ProposedBefore != nil {
		q = q.Where(`"de"."proposed_at" <= ?`, *f.ProposedBefore)
	}
	if len(f.Severities) > 0 {
		// The product's own rating where it has stated one, as the findings
		// list reads it, joined on the row's product so a decision is judged
		// by the rating in force where it was made.
		// Asked of the issue each row is read as, which is where a rating
		// stands once one issue has merged into another.
		q = q.Where(`"de"."vulnerability_id" IN (?)`,
			q.NewSelect().TableExpr(`"vulnerability" AS "mv"`).
				Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "mv"."issue_id"`).
				Join(rating.For(rating.OnDecisionOccurrence)).
				Column("mv.id").
				Where(rating.EffectiveExpr+" IN (?)", bun.List(f.Severities)))
	}
	if len(f.Outcomes) > 0 {
		q = q.Where(`"de"."decision_id" IN (?)`,
			q.NewSelect().TableExpr(`"decision" AS "qc"`).Column("qc.id").
				Where(`"qc"."outcome" IN (?)`, bun.List(f.Outcomes)))
	}
	if named := typedname.Matching(f.BranchOrTag); named != "" {
		// An open finding the row covers, in a build of the named branch or tag.
		covers := openUnder(q).Where(`"st"."name" = ?`, named)
		q = q.Where("EXISTS (?)", readableFindings(covers, subject, "f", `"st"."product_id"`))
	}
	return q
}

// openUnder selects the open findings a row of decision_occurrence AS de covers: at the
// row's occurrence, at the versions the row was written against, in the row's
// product. The match buildsCovered makes, asked as a condition.
func openUnder(q *bun.SelectQuery) *bun.SelectQuery {
	return q.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr("1").
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		Where(finding.DecisionOccurrenceFiledAt("de", "f")).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Where(`"st"."product_id" = "de"."product_id"`).
		Where(finding.KeyMatches)
}

// Queue returns what is waiting for somebody, newest first, one entry per
// decision.
//
// Narrowed to what the asker may act on, in the query. A reviewer who cannot
// triage a product should not be shown its decisions at all — a queue is a work
// list, and one containing work somebody cannot do teaches them to skip rows.
//
// A decision is shown only where the reader may act on every row in it. Acting on
// a decision is acting on the argument, which does not come in halves: shown the
// part they may approve, a reader would agree to words whose other half stays
// waiting on somebody else, and the count beside the card would be wrong.
//
// The filter's reason picks the list, and waitingDecisions says who is shown
// each. `mine` keeps the reader's own decisions: for approvals, what they
// proposed and nobody has agreed to yet, which is a different question from
// what is waiting on them.
func (s *Store) Queue(ctx context.Context, subject access.Subject, filter QueueFilter,
	limit, offset int) ([]Waiting, int, error) {

	waitingDecisions := func() *bun.SelectQuery { return s.waitingDecisions(subject, filter) }
	// A limit of zero asks how much is waiting and nothing else, which is
	// what a badge polled once a minute needs.
	if limit == 0 {
		total, err := s.countDecisions(ctx, waitingDecisions, "what is waiting")
		return nil, total, err
	}
	limit = database.AList.Of(limit)

	page, err := s.decisionsOn(ctx, waitingDecisions, limit, offset, "what is waiting")
	if err != nil {
		return nil, 0, err
	}
	if len(page.Order) == 0 {
		return nil, page.Total, nil
	}
	total, ids, byID := page.Total, page.Order, page.Decisions

	// The representative is the earliest row; the sizes are counted over all
	// of them.
	sizes, err := s.decisionSizes(ctx, subject, ids, "what is waiting")
	if err != nil {
		return nil, 0, err
	}
	representatives := make([]DecisionOccurrence, 0, len(ids))
	for _, id := range ids {
		representatives = append(representatives, sizes[id].First)
	}
	reasoning, err := s.currentReasoning(ctx, representatives)
	if err != nil {
		return nil, 0, err
	}
	seenBefore, err := s.everApproved(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	builds, err := s.buildsCovered(ctx, subject, ids)
	if err != nil {
		return nil, 0, err
	}

	deferred, err := s.deferredSoFar(ctx, representatives)
	if err != nil {
		return nil, 0, err
	}
	// Every decision that is an act over many issues, including rows set aside
	// from one and one re-made after it lapsed: each is refused over an
	// attacked issue the same way, so each needs the table to set it aside.
	var bulk []Decision
	for _, id := range ids {
		decision := byID[id]
		many, err := s.overMany(ctx, decision)
		if err != nil {
			return nil, 0, err
		}
		if many {
			bulk = append(bulk, decision)
		}
	}
	outliers, err := s.outliersFor(ctx, subject, bulk)
	if err != nil {
		return nil, 0, err
	}
	// The case against agreeing. Read for the whole page in two
	// statements, because a card that costs two round trips is a card that
	// ends up carrying less than it should.
	against, err := s.counters(ctx, subject, representatives)
	if err != nil {
		return nil, 0, err
	}

	out := make([]Waiting, 0, len(ids))
	for _, id := range ids {
		decision := byID[id]
		representative := sizes[id].First
		// Agreed to before and back in the queue: an approver meeting it again
		// should know they are re-reading something. Asked of the decision, which
		// is what an agreement is given for.
		before := seenBefore[id]
		one := Waiting{
			Decision: decision, DecisionOccurrence: representative,
			Reasoning:          reasoning[representative.ID],
			PreviouslyApproved: before,
			DeferredSoFar:      deferred[representative.ID],
			Rows:               sizes[id].Rows,
			Issues:             sizes[id].Issues,
			Occurrences:        sizes[id].Occurrences,
			Builds:             builds[id],
			Counter:            against[representative.ID],
		}
		// Present for every decision read as an act over many issues above,
		// and absent otherwise.
		one.Outliers = outliers[decision.ID]
		out = append(out, one)
	}
	return out, total, nil
}

// buildsCovered names the builds each decision's rows currently cover: every
// open finding at the row's occurrence, at the versions the row was written
// against — the same match a finding makes when it asks whether a decision
// applies to it.
//
// Narrowed to the findings the reader may see. A build named here is a
// statement that the build holds the issue, and a decision somebody may read
// can match findings they may not.
func (s *Store) buildsCovered(ctx context.Context, subject access.Subject, decisions []int64) (map[int64][]string, error) {
	var rows []struct {
		DecisionID  int64  `bun:"decision_id"`
		BranchOrTag string `bun:"branch_or_tag"`
		Variant     string `bun:"variant"`
	}
	query := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		// The decision occurrence on the outside of the join, for the reason Describe
		// gives: SQLite otherwise starts from every open finding.
		Join(finding.DecisionOccurrenceIssue).
		Join(`CROSS JOIN "finding" AS "f"`).
		Where(finding.DecisionOccurrenceOf("f")).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		// Grouped on the names and shown in the spelling somebody declared:
		// the list is text a person reads, and one build is one entry
		// however it was spelled.
		ColumnExpr(`MIN(`+catalog.ShownExpr("st")+`) AS "branch_or_tag"`).
		ColumnExpr(`MIN(`+catalog.ShownExpr("va")+`) AS "variant"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(decisions)).
		// Live rows only, as a decision's reach is counted.
		Where(`"de"."live_key" IS NOT NULL`).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Where(`"st"."product_id" = "de"."product_id"`).
		Where(finding.KeyMatches)
	err := readableFindings(query, subject, "f", `"st"."product_id"`).
		GroupExpr(`"de"."decision_id", "st"."name", "va"."name"`).
		OrderExpr(`"de"."decision_id", "st"."name", "va"."name"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which builds these cover: %w", err)
	}
	builds := map[int64][]string{}
	for _, row := range rows {
		builds[row.DecisionID] = append(builds[row.DecisionID], row.BranchOrTag+" \u00b7 "+row.Variant)
	}
	return builds, nil
}

// outliersFor reads the outliers of every bulk decision on a page, in three
// statements for the page rather than three per decision: which issues each
// decision covers, what those issues are, and where a fix is known.
func (s *Store) outliersFor(ctx context.Context, subject access.Subject, decisions []Decision) (map[int64]*Outliers, error) {
	out := make(map[int64]*Outliers, len(decisions))
	if len(decisions) == 0 {
		return out, nil
	}
	decisionIDs := make([]int64, 0, len(decisions))
	for _, decision := range decisions {
		decisionIDs = append(decisionIDs, decision.ID)
		out[decision.ID] = &Outliers{Rows: []Outlier{}}
	}

	var heads []struct {
		DecisionID           int64 `bun:"decision_id"`
		VulnerabilityID      int64 `bun:"vulnerability_id"`
		DecisionOccurrenceID int64 `bun:"decision_occurrence_id"`
		// ProductID is which product the decision was made in. A rating
		// belongs to a product, so an outlier is picked out against
		// what *this* product rates these issues rather than against a
		// word somebody in another one chose.
		ProductID int64 `bun:"product_id"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		Join(finding.DecisionOccurrenceIssue).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`"dv"."issue_id" AS "vulnerability_id"`).
		ColumnExpr(`"de"."id" AS "decision_occurrence_id"`).
		ColumnExpr(`"de"."product_id" AS "product_id"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(decisionIDs)).
		OrderExpr(`"de"."decision_id", "dv"."issue_id", "de"."id"`).
		Scan(ctx, &heads); err != nil {
		return nil, fmt.Errorf("read what a bulk decision covers: %w", err)
	}
	if len(heads) == 0 {
		return out, nil
	}
	// One identifier per issue and per product, never one per row. A bulk
	// decision covering one kernel issue holds a row at each of its
	// occurrences, which is a hundred thousand rows, and a list carrying each of
	// them is a statement past the size one engine accepts.
	var issueIDs, productIDs []int64
	seenIssue, seenProduct := map[int64]bool{}, map[int64]bool{}
	inProduct := map[int64]map[int64]bool{}
	// Every row per issue, earliest first: the first stands for the issue
	// and all of them are what setting it aside sets aside.
	covers := map[int64]map[int64][]int64{}
	within := map[int64]int64{}
	byProduct := map[int64][]int64{}
	for _, head := range heads {
		if !seenIssue[head.VulnerabilityID] {
			seenIssue[head.VulnerabilityID] = true
			issueIDs = append(issueIDs, head.VulnerabilityID)
		}
		if !seenProduct[head.ProductID] {
			seenProduct[head.ProductID] = true
			productIDs = append(productIDs, head.ProductID)
			inProduct[head.ProductID] = map[int64]bool{}
		}
		within[head.DecisionID] = head.ProductID
		if !inProduct[head.ProductID][head.VulnerabilityID] {
			inProduct[head.ProductID][head.VulnerabilityID] = true
			byProduct[head.ProductID] = append(byProduct[head.ProductID], head.VulnerabilityID)
		}
		if covers[head.DecisionID] == nil {
			covers[head.DecisionID] = map[int64][]int64{}
		}
		covers[head.DecisionID][head.VulnerabilityID] = append(
			covers[head.DecisionID][head.VulnerabilityID], head.DecisionOccurrenceID)
	}
	// Which of these issues each product records being attacked through.
	attacked := map[int64]map[int64]bool{}
	for productID, issues := range byProduct {
		standing, err := finding.Incident(ctx, s.db, productID, issues)
		if err != nil {
			return nil, err
		}
		attacked[productID] = standing
	}

	var issues []finding.Vulnerability
	if err := s.db.NewSelect().Model(&issues).
		Where(`"id" IN (?)`, bun.List(issueIDs)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the issues a bulk decision covers: %w", err)
	}
	// A flaw recorded where this reader may not read it wrote its summary
	// onto the issue row every product shares.
	withheld, err := finding.RecordedOutOfReach(ctx, s.db, subject, issueIDs)
	if err != nil {
		return nil, err
	}
	byIssue := make(map[int64]finding.Vulnerability, len(issues))
	for _, issue := range issues {
		if withheld[issue.ID] {
			issue.WithholdRecorded()
		}
		byIssue[issue.ID] = issue
	}
	rated, err := finding.RatingsIn(ctx, s.db, productIDs, issueIDs)
	if err != nil {
		return nil, err
	}

	// fixes is where a fix is known, from the open findings the decision's
	// rows are about: the same match a row makes when a finding asks
	// whether it applies — the product, the occurrence and both versions — and
	// only the findings the reader may see, since a fix version is read
	// off the finding. A decision covers one component, so one answer per
	// issue is the ordinary case and the smallest stated version stands in
	// otherwise.
	var fixes []struct {
		DecisionID      int64  `bun:"decision_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		FixedIn         string `bun:"fixed_in"`
	}
	known := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		// The decision occurrence on the outside, as buildsCovered has it.
		Join(finding.DecisionOccurrenceIssue).
		Join(`CROSS JOIN "finding" AS "f"`).
		Where(finding.DecisionOccurrenceOf("f")).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`MIN("f"."fixed_in") AS "fixed_in"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(decisionIDs)).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Where(`"st"."product_id" = "de"."product_id"`).
		Where(finding.KeyMatches).
		Where(`"f"."fixed_in" <> ''`)
	if err := readableFindings(known, subject, "f", `"st"."product_id"`).
		GroupExpr(`"de"."decision_id", "f"."vulnerability_id"`).
		Scan(ctx, &fixes); err != nil {
		return nil, fmt.Errorf("read which of these have a fix: %w", err)
	}
	fixedIn := map[int64]map[int64]string{}
	for _, fix := range fixes {
		if fixedIn[fix.DecisionID] == nil {
			fixedIn[fix.DecisionID] = map[int64]string{}
		}
		fixedIn[fix.DecisionID][fix.VulnerabilityID] = fix.FixedIn
	}

	for _, decision := range decisions {
		out[decision.ID] = outliersOf(decision, within[decision.ID], covers[decision.ID], byIssue,
			rated, fixedIn[decision.ID], attacked[within[decision.ID]])
	}
	return out, nil
}

// outliersOf picks, from the issues one bulk decision covers, the rows that do
// not look like the rest.
func outliersOf(decision Decision, productID int64, occurrencesOf map[int64][]int64,
	byIssue map[int64]finding.Vulnerability, rated map[finding.RatedKey]string,
	fixedIn map[int64]string, attacked map[int64]bool) *Outliers {

	// The term the list was actually narrowed by, where the act recorded one,
	// and the proposer's prose only where it did not.
	//
	// The structured record is the one the check reads. A proposer who
	// narrowed by one word and wrote a sentence phrasing it differently would
	// get no "does not mention" flag from the prose, and the field they write
	// is asked for in their own words, which invites exactly that.
	term := orEmpty(decision.SelectedWhere)
	if term == "" {
		term = narrowingTerm(orEmpty(decision.SelectedBy))
	}
	out := &Outliers{Rows: []Outlier{}}
	candidates := make([]Outlier, 0, len(occurrencesOf))
	// Walked in issue order so the result is the same on every engine and
	// every run, whatever order a map hands them out in.
	issueIDs := make([]int64, 0, len(occurrencesOf))
	for id := range occurrencesOf {
		issueIDs = append(issueIDs, id)
	}
	sort.Slice(issueIDs, func(i, j int) bool { return issueIDs[i] < issueIDs[j] })
	for _, id := range issueIDs {
		issue, known := byIssue[id]
		if !known {
			continue
		}
		// This product's rating where it has one, the published word
		// otherwise — the rule every list follows, asked of the product the
		// decision was made in.
		word := issue.RatedIn(rated[finding.RatedKey{ProductID: productID,
			VulnerabilityID: issue.ID}]).InForce()
		if word == "" && issue.ScoreCenti != nil {
			word = finding.SeverityWord(*issue.ScoreCenti)
		}
		one := Outlier{
			DecisionOccurrenceID: occurrencesOf[issue.ID][0], DecisionOccurrenceIDs: occurrencesOf[issue.ID],
			Vulnerability: issue.Identifier, Severity: word,
			Incident: attacked[issue.ID], Exploited: issue.Exploited,
			FixedIn: fixedIn[issue.ID], Description: clip(issue.Description, 200),
		}
		if one.Incident {
			out.Incident++
			one.Why = append(one.Why, "this product was attacked through it")
		}
		if issue.Exploited {
			out.Exploited++
			one.Why = append(one.Why, "known to be exploited")
		}
		if word == "critical" || word == "high" {
			out.Severe++
			one.Why = append(one.Why, "rated "+word)
		}
		if one.FixedIn != "" {
			out.Fixable++
			one.Why = append(one.Why, "a fix is available in "+one.FixedIn)
		}
		if term != "" && !strings.Contains(strings.ToLower(issue.Description), strings.ToLower(term)) {
			out.Unmatched++
			one.Why = append(one.Why, "does not mention \""+term+"\"")
		}
		if len(one.Why) > 0 {
			candidates = append(candidates, one)
		}
	}
	// Attacked here first, then exploited, then the worst rated, then by name
	// so the order is the same on every engine.
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.Incident != b.Incident {
			return a.Incident
		}
		if a.Exploited != b.Exploited {
			return a.Exploited
		}
		if finding.Ranks(a.Severity) != finding.Ranks(b.Severity) {
			return finding.Ranks(a.Severity) > finding.Ranks(b.Severity)
		}
		return a.Vulnerability < b.Vulnerability
	})
	// Past the cap only where the rows past it are attacked here, which sort
	// first: those are the ones agreeing is refused over.
	keep := max(outlierRows, out.Incident)
	if len(candidates) > keep {
		candidates = candidates[:keep]
	}
	out.Rows = candidates
	return out
}

// narrowingTerm reads the term a bulk set was narrowed by, where the record
// of how it was narrowed names one as `contains "term"`.
func narrowingTerm(selectedBy string) string {
	found := containsTerm.FindStringSubmatch(selectedBy)
	if len(found) < 2 {
		return ""
	}
	return strings.TrimSpace(found[1])
}

var containsTerm = regexp.MustCompile(`contains\s+"([^"]+)"`)

// clip shortens text to n characters for a card, on a rune boundary.
func clip(text string, n int) string {
	runes := []rune(strings.TrimSpace(text))
	if len(runes) <= n {
		return string(runes)
	}
	return string(runes[:n]) + "\u2026"
}

// ReasoningFor returns the reasoning each decision occurrence currently rests on, keyed
// by row, leaving out the reasoning of a decision that holds a row this
// subject may not read.
//
// Read through the decision, which is where the words are: a row of a decision rests
// on the decision's argument, and asking per row is asking the same question
// once per occurrence. The argument is about every occurrence of the decision, so a reader
// of only part of it is not given it.
func (s *Store) ReasoningFor(ctx context.Context, subject access.Subject, occurrences []DecisionOccurrence) (map[int64]string, error) {
	reasoning, err := s.currentReasoning(ctx, occurrences)
	if err != nil {
		return nil, err
	}
	return reasoning, s.withholdPartReasoning(ctx, subject, occurrences, reasoning)
}

func (s *Store) currentReasoning(ctx context.Context, occurrences []DecisionOccurrence) (map[int64]string, error) {
	said, err := s.reasoningPerDecision(ctx, decisionsOf(occurrences))
	if err != nil {
		return nil, err
	}
	byOccurrence := make(map[int64]string, len(occurrences))
	for _, occurrence := range occurrences {
		if body, held := said[occurrence.DecisionID]; held {
			byOccurrence[occurrence.ID] = body
		}
	}
	return byOccurrence, nil
}

// reasoningPerDecision is the words each of these decisions currently rests on.
func (s *Store) reasoningPerDecision(ctx context.Context, ids []int64) (map[int64]string, error) {
	if len(ids) == 0 {
		return map[int64]string{}, nil
	}
	var rows []struct {
		DecisionID int64  `bun:"decision_id"`
		Body       string `bun:"body"`
	}
	if err := s.db.NewSelect().Model((*Decision)(nil)).
		Join(`JOIN "decision_revision" AS "dr" ON "dr"."id" = "cl"."revision_id"`).
		ColumnExpr(`"cl"."id" AS "decision_id"`).
		ColumnExpr(`"dr"."body" AS "body"`).
		Where(`"cl"."id" IN (?)`, bun.List(ids)).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the reasoning: %w", err)
	}
	said := make(map[int64]string, len(rows))
	for _, row := range rows {
		said[row.DecisionID] = row.Body
	}
	return said, nil
}

// decisionsOf is the decisions a set of rows belongs to, each once.
func decisionsOf(occurrences []DecisionOccurrence) []int64 {
	seen := make(map[int64]bool, len(occurrences))
	ids := make([]int64, 0, len(occurrences))
	for _, occurrence := range occurrences {
		if !seen[occurrence.DecisionID] {
			seen[occurrence.DecisionID] = true
			ids = append(ids, occurrence.DecisionID)
		}
	}
	return ids
}

// everApproved reports which of these decisions were agreed to at some point.
func (s *Store) everApproved(ctx context.Context, ids []int64) (map[int64]bool, error) {
	if len(ids) == 0 {
		return map[int64]bool{}, nil
	}
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where(`"decision_id" IN (?)`, bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what has been agreed to before: %w", err)
	}
	seen := make(map[int64]bool, len(approvals))
	for _, approval := range approvals {
		seen[approval.DecisionID] = true
	}
	return seen, nil
}

// waiting narrows a query to the rows waiting for one reason.
//
// A decision that needed nobody — a short deferral — waits for no approval. A
// row the code moved out from under is not here: it is its author's to
// re-affirm, and that list is its own.
func waiting(query *bun.SelectQuery, reason QueueReason, now time.Time) *bun.SelectQuery {
	switch reason {
	case DeferralExpired:
		// The date is on the decision. An EXISTS rather than a join, because
		// this narrows a query that already groups over the rows.
		return query.Where(`"de"."state" IN (?, ?)`, Proposed, Approved).
			Where(`EXISTS (SELECT 1 FROM "decision" AS "wc" WHERE "wc"."id" = "de"."decision_id"
		AND "wc"."outcome" = ? AND "wc"."deferred_until" IS NOT NULL AND "wc"."deferred_until" <= ?)`,
				Deferred, now)
	case FixDateMissed:
		// A promise has no expiry of its own and goes on suppressing the
		// finding after its date, so a passed date is the only sign it did not
		// hold.
		return query.Where(`"de"."state" IN (?, ?)`, Proposed, Approved).
			Where(`EXISTS (SELECT 1 FROM "decision" AS "wp" WHERE "wp"."id" = "de"."decision_id"
		AND "wp"."outcome" IN (?) AND "wp"."committed_to" IS NOT NULL AND "wp"."committed_to" <= ?)`,
				bun.List([]Outcome{UpgradeNeeded, PatchNeeded}), now)
	default:
		return query.Where(`"de"."state" = ? AND "de"."needs_approval" = ? AND "de"."sent_back_at" IS NULL`,
			Proposed, true)
	}
}
