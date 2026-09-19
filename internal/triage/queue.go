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
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Waiting is one claim somebody has to look at, with what an approver needs in
// order to judge it.
//
// Everything here is carried rather than left to be fetched per row. A
// reviewer works down a list, and a list where judging each row means opening
// it is a list that gets approved without being read — which is the failure
// the queue exists to prevent, arriving by a different route.
//
// One of these is one claim — one proposer's action — however many decisions
// it wrote. Decision is a representative row: the earliest, which is the same
// on every engine and every run.
type Waiting struct {
	Claim    Claim
	Decision Decision
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
	// Decisions, Issues and Places are how big the claim is: rows written,
	// distinct issues, distinct places.
	Decisions, Issues, Places int
	// Builds names every build the claim's rows currently cover, as the
	// stream and variant display names joined with a middle dot.
	Builds []string
	// Outliers is what in a bulk set does not look like the rest. Only for a
	// claim over many issues; nil otherwise.
	Outliers *Outliers
	// Counter is what would argue against agreeing: what has been decided
	// about the same issue elsewhere, and how much else at the same place
	// nobody has answered.
	Counter Counter
}

// Outliers is what an approver of a bulk claim checks instead of reading every
// row: the handful that contradict the shape of the claim.
type Outliers struct {
	// Exploited, Severe, Fixable and Unmatched count the distinct issues in
	// the claim with that property. Severe is critical or high; Unmatched is
	// an issue whose description does not contain the term the set was
	// narrowed by, where that term is known.
	Exploited, Severe, Fixable, Unmatched int
	// Rows are the issues that stood out, exploited first and then by
	// severity, capped.
	Rows []Outlier
}

// Outlier is one issue in a bulk claim that does not look like the rest.
type Outlier struct {
	DecisionID    int64
	Vulnerability string
	Severity      string
	Exploited     bool
	FixedIn       string
	Description   string
	// Why is why says which of the four things made it stand out.
	Why []string
}

// outlierRows is how many outliers a queue card carries. Enough to read;
// the counts say how many there are.
const outlierRows = 20

// WaitingIn counts the claims about one product waiting for a second person.
//
// The same population the queue lists, narrowed to one product: a number
// beside a product that counted something else from the screen it links to is
// worse than no number. Somebody asking how a product is doing is asking
// partly whether the work is stuck on somebody else.
func (s *Store) WaitingIn(ctx context.Context, subject access.Subject,
	productID int64) (int, error) {

	q := s.db.NewSelect().Model((*Decision)(nil)).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		GroupExpr("de.claim_id").
		Where("de.product_id = ?", productID)
	q = approvableBy(waiting(q, s.now()), subject, "de")
	// Their own claims are not waiting on them, which is what the queue means
	// by waiting: approving your own is refused, so counting them would be
	// counting work nobody can do.
	q = q.Where("de.proposed_by <> ?", subject.ID)
	q = q.Where("NOT EXISTS (?)", notApprovableBy(
		s.db.NewSelect().TableExpr(`"decision" AS "other"`).ColumnExpr("1").
			Where(`"other".claim_id = de.claim_id`), subject, `"other"`))
	total, err := s.db.NewSelect().TableExpr(`(?) AS "waiting_here"`, q).Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count what is waiting here: %w", err)
	}
	return total, nil
}

// Queue returns what is waiting for somebody, newest first, one entry per
// claim.
//
// Narrowed to what the asker may act on, in the query. A reviewer who cannot
// triage a product should not be shown its claims at all — a queue is a work
// list, and one containing work somebody cannot do teaches them to skip rows.
//
// A claim is shown only where the reader may act on every row in it. Acting on
// a claim is acting on the argument, which does not come in halves: shown the
// part they may approve, a reader would agree to words whose other half stays
// waiting on somebody else, and the count beside the card would be wrong.
//
// And not their own. Approving your own claim is refused, because a control
// one person completes alone is not one — so a queue containing them
// is a work list of things the reader cannot do, which teaches them to skip
// rows. `mine` asks for exactly those instead: somebody wants to find what they
// proposed and nobody has agreed to yet, and that is a different question from
// what is waiting on them.
func (s *Store) Queue(ctx context.Context, subject access.Subject, mine bool,
	productID int64, limit, offset int) ([]Waiting, int, error) {

	limit = database.AList.Of(limit)

	// The claims with a waiting row this person may act on, ordered by the
	// newest row in each. Grouped in the statement rather than here, so a
	// page is a page of claims and the count counts claims.
	waitingClaims := func() *bun.SelectQuery {
		q := s.db.NewSelect().Model((*Decision)(nil)).
			ColumnExpr(`de.claim_id AS "claim_id"`).
			ColumnExpr(`MAX(de.id) AS "newest"`).
			GroupExpr("de.claim_id")
		q = approvableBy(waiting(q, s.now()), subject, "de")
		// One product where the caller named one. A claim is decided in a
		// product, so this narrows the same way every other list does — and
		// zero is every product, which is what the queue screen asks for.
		if productID != 0 {
			q = q.Where("de.product_id = ?", productID)
		}
		// Whose claims. The same statement either way, so the count and the
		// page cannot disagree about which question was asked.
		if mine {
			q = q.Where("de.proposed_by = ?", subject.ID)
		} else {
			q = q.Where("de.proposed_by <> ?", subject.ID)
		}
		return q.Where("NOT EXISTS (?)", notApprovableBy(
			s.db.NewSelect().TableExpr(`"decision" AS "other"`).ColumnExpr("1").
				Where(`"other".claim_id = de.claim_id`), subject, `"other"`))
	}

	page, err := s.pageClaims(ctx, subject, waitingClaims, limit, offset, "what is waiting")
	if err != nil {
		return nil, 0, err
	}
	if len(page.Order) == 0 {
		return nil, page.Total, nil
	}
	total, ids, byID, rows := page.Total, page.Order, page.Claims, page.Rows

	// The representative is the earliest row; the sizes are counted over all
	// of them.
	first := map[int64]Decision{}
	issues := map[int64]map[int64]bool{}
	places := map[int64]map[string]bool{}
	count := map[int64]int{}
	for _, row := range rows {
		if _, seen := first[row.ClaimID]; !seen {
			first[row.ClaimID] = row
			issues[row.ClaimID] = map[int64]bool{}
			places[row.ClaimID] = map[string]bool{}
		}
		issues[row.ClaimID][row.VulnerabilityID] = true
		places[row.ClaimID][row.PlaceIdentity] = true
		count[row.ClaimID]++
	}

	representatives := make([]Decision, 0, len(ids))
	for _, id := range ids {
		representatives = append(representatives, first[id])
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
	var bulk []Claim
	for _, id := range ids {
		if claim := byID[id]; claim.Kind == TogetherClaim {
			bulk = append(bulk, claim)
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
		claim := byID[id]
		representative := first[id]
		// Agreed to before and back in the queue: an approver meeting it again
		// should know they are re-reading something. Asked of the claim, which
		// is what an agreement is given for.
		before := seenBefore[id]
		one := Waiting{
			Claim: claim, Decision: representative,
			Reasoning:          reasoning[representative.ID],
			PreviouslyApproved: before,
			DeferredSoFar:      deferred[representative.ID],
			Decisions:          count[id],
			Issues:             len(issues[id]),
			Places:             len(places[id]),
			Builds:             builds[id],
			Counter:            against[representative.ID],
		}
		if claim.Kind == TogetherClaim {
			one.Outliers = outliers[claim.ID]
		}
		out = append(out, one)
	}
	return out, total, nil
}

// buildsCovered names the builds each claim's rows currently cover: every
// open finding at the row's place, at the versions the row was written
// against — the same match a finding makes when it asks whether a decision
// applies to it.
//
// Narrowed to the findings the reader may see. A build named here is a
// statement that the build holds the issue, and a decision somebody may read
// can match findings they may not.
func (s *Store) buildsCovered(ctx context.Context, subject access.Subject, claims []int64) (map[int64][]string, error) {
	var rows []struct {
		ClaimID int64  `bun:"claim_id"`
		Stream  string `bun:"stream"`
		Variant string `bun:"variant"`
	}
	query := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		// The decision on the outside of the join, for the reason Describe
		// gives: SQLite otherwise starts from every open finding.
		Join(`CROSS JOIN "finding" AS "f"`).
		Where("f.vulnerability_id = de.vulnerability_id AND f.place_identity = de.place_identity").
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`st.display_name AS "stream"`).
		ColumnExpr(`va.display_name AS "variant"`).
		Where("de.claim_id IN (?)", bun.List(claims)).
		Where("f.closed_at IS NULL").
		Where("st.product_id = de.product_id").
		Where("COALESCE(de.component_upstream_version, '') = " + finding.ComponentUpstreamExpr).
		Where("COALESCE(de.consumer_upstream_version, '') = " + finding.ConsumerUpstreamExpr)
	err := readableFindings(query, subject, "f", "st.product_id").
		GroupExpr("de.claim_id, st.display_name, va.display_name").
		OrderExpr("de.claim_id, st.display_name, va.display_name").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which builds these cover: %w", err)
	}
	builds := map[int64][]string{}
	for _, row := range rows {
		builds[row.ClaimID] = append(builds[row.ClaimID], row.Stream+" \u00b7 "+row.Variant)
	}
	return builds, nil
}

// outliersFor reads the outliers of every bulk claim on a page, in three
// statements for the page rather than three per claim: which issues each
// claim covers, what those issues are, and where a fix is known.
func (s *Store) outliersFor(ctx context.Context, subject access.Subject, claims []Claim) (map[int64]*Outliers, error) {
	out := make(map[int64]*Outliers, len(claims))
	if len(claims) == 0 {
		return out, nil
	}
	claimIDs := make([]int64, 0, len(claims))
	for _, claim := range claims {
		claimIDs = append(claimIDs, claim.ID)
		out[claim.ID] = &Outliers{Rows: []Outlier{}}
	}

	var heads []struct {
		ClaimID         int64 `bun:"claim_id"`
		VulnerabilityID int64 `bun:"vulnerability_id"`
		DecisionID      int64 `bun:"decision_id"`
		// ProductID is which product the claim was made in. A rating
		// belongs to a product, so an outlier is picked out against
		// what *this* product rates these issues rather than against a
		// word somebody in another one chose.
		ProductID int64 `bun:"product_id"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`MIN(de.id) AS "decision_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		Where("de.claim_id IN (?)", bun.List(claimIDs)).
		GroupExpr("de.claim_id, de.vulnerability_id, de.product_id").
		Scan(ctx, &heads); err != nil {
		return nil, fmt.Errorf("read what a bulk claim covers: %w", err)
	}
	if len(heads) == 0 {
		return out, nil
	}
	issueIDs := make([]int64, 0, len(heads))
	productIDs := make([]int64, 0, len(heads))
	covers := map[int64]map[int64]int64{}
	within := map[int64]int64{}
	for _, head := range heads {
		issueIDs = append(issueIDs, head.VulnerabilityID)
		productIDs = append(productIDs, head.ProductID)
		within[head.ClaimID] = head.ProductID
		if covers[head.ClaimID] == nil {
			covers[head.ClaimID] = map[int64]int64{}
		}
		covers[head.ClaimID][head.VulnerabilityID] = head.DecisionID
	}

	var issues []finding.Vulnerability
	if err := s.db.NewSelect().Model(&issues).
		Where("id IN (?)", bun.List(issueIDs)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the issues a bulk claim covers: %w", err)
	}
	byIssue := make(map[int64]finding.Vulnerability, len(issues))
	for _, issue := range issues {
		byIssue[issue.ID] = issue
	}
	rated, err := finding.RatingsIn(ctx, s.db, productIDs, issueIDs)
	if err != nil {
		return nil, err
	}

	// fixes is where a fix is known, from the open findings the claim's
	// rows are about: the same match a row makes when a finding asks
	// whether it applies — the product, the place and both versions — and
	// only the findings the reader may see, since a fix version is read
	// off the finding. A claim covers one component, so one answer per
	// issue is the ordinary case and the smallest stated version stands in
	// otherwise.
	var fixes []struct {
		ClaimID         int64  `bun:"claim_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		FixedIn         string `bun:"fixed_in"`
	}
	known := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		// The decision on the outside, as buildsCovered has it.
		Join(`CROSS JOIN "finding" AS "f"`).
		Where("f.vulnerability_id = de.vulnerability_id AND f.place_identity = de.place_identity").
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`MIN(f.fixed_in) AS "fixed_in"`).
		Where("de.claim_id IN (?)", bun.List(claimIDs)).
		Where("f.closed_at IS NULL").
		Where("st.product_id = de.product_id").
		Where("COALESCE(de.component_upstream_version, '') = " + finding.ComponentUpstreamExpr).
		Where("COALESCE(de.consumer_upstream_version, '') = " + finding.ConsumerUpstreamExpr).
		Where("f.fixed_in <> ''")
	if err := readableFindings(known, subject, "f", "st.product_id").
		GroupExpr("de.claim_id, f.vulnerability_id").
		Scan(ctx, &fixes); err != nil {
		return nil, fmt.Errorf("read which of these have a fix: %w", err)
	}
	fixedIn := map[int64]map[int64]string{}
	for _, fix := range fixes {
		if fixedIn[fix.ClaimID] == nil {
			fixedIn[fix.ClaimID] = map[int64]string{}
		}
		fixedIn[fix.ClaimID][fix.VulnerabilityID] = fix.FixedIn
	}

	for _, claim := range claims {
		out[claim.ID] = outliersOf(claim, within[claim.ID], covers[claim.ID], byIssue,
			rated, fixedIn[claim.ID])
	}
	return out, nil
}

// outliersOf picks, from the issues one bulk claim covers, the rows that do
// not look like the rest.
func outliersOf(claim Claim, productID int64, decisionOf map[int64]int64,
	byIssue map[int64]finding.Vulnerability, rated map[finding.RatedKey]string,
	fixedIn map[int64]string) *Outliers {

	// The term the list was actually narrowed by, where the act recorded one,
	// and the claimant's prose only where it did not.
	//
	// The structured record is the one the check reads. Reading the prose
	// meant a claimant who narrowed by one word and wrote a sentence phrasing
	// it differently got no "does not mention" flag at all — and the field
	// they write is asked for in their own words, which invites exactly that.
	term := orEmpty(claim.SelectedWhere)
	if term == "" {
		term = narrowingTerm(orEmpty(claim.SelectedBy))
	}
	out := &Outliers{Rows: []Outlier{}}
	candidates := make([]Outlier, 0, len(decisionOf))
	// Walked in issue order so the result is the same on every engine and
	// every run, whatever order a map hands them out in.
	issueIDs := make([]int64, 0, len(decisionOf))
	for id := range decisionOf {
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
		// claim was made in.
		word := issue.RatedIn(rated[finding.RatedKey{ProductID: productID,
			VulnerabilityID: issue.ID}]).InForce()
		if word == "" && issue.ScoreCenti != nil {
			word = finding.SeverityWord(*issue.ScoreCenti)
		}
		one := Outlier{
			DecisionID: decisionOf[issue.ID], Vulnerability: issue.Identifier,
			Severity: word, Exploited: issue.Exploited, FixedIn: fixedIn[issue.ID],
			Description: clip(issue.Description, 200),
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
	// Exploited first, then the worst rated, then by name so the order is the
	// same on every engine.
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.Exploited != b.Exploited {
			return a.Exploited
		}
		if finding.Ranks(a.Severity) != finding.Ranks(b.Severity) {
			return finding.Ranks(a.Severity) > finding.Ranks(b.Severity)
		}
		return a.Vulnerability < b.Vulnerability
	})
	if len(candidates) > outlierRows {
		candidates = candidates[:outlierRows]
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

// ReasoningFor returns the reasoning each decision currently rests on, keyed
// by decision.
//
// Read through the claim, which is where the words are: a row of a claim rests
// on the claim's argument, and asking per row is asking the same question
// once per place.
func (s *Store) ReasoningFor(ctx context.Context, decisions []Decision) (map[int64]string, error) {
	return s.currentReasoning(ctx, decisions)
}

func (s *Store) currentReasoning(ctx context.Context, decisions []Decision) (map[int64]string, error) {
	said, err := s.reasoningPerClaim(ctx, claimsOf(decisions))
	if err != nil {
		return nil, err
	}
	byDecision := make(map[int64]string, len(decisions))
	for _, decision := range decisions {
		if body, held := said[decision.ClaimID]; held {
			byDecision[decision.ID] = body
		}
	}
	return byDecision, nil
}

// reasoningPerClaim is the words each of these claims currently rests on.
func (s *Store) reasoningPerClaim(ctx context.Context, ids []int64) (map[int64]string, error) {
	if len(ids) == 0 {
		return map[int64]string{}, nil
	}
	var rows []struct {
		ClaimID int64  `bun:"claim_id"`
		Body    string `bun:"body"`
	}
	if err := s.db.NewSelect().Model((*Claim)(nil)).
		Join(`JOIN "claim_revision" AS "dr" ON dr.id = cl.revision_id`).
		ColumnExpr(`cl.id AS "claim_id"`).
		ColumnExpr(`dr.body AS "body"`).
		Where("cl.id IN (?)", bun.List(ids)).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the reasoning: %w", err)
	}
	said := make(map[int64]string, len(rows))
	for _, row := range rows {
		said[row.ClaimID] = row.Body
	}
	return said, nil
}

// claimsOf is the claims a set of decisions belongs to, each once.
func claimsOf(decisions []Decision) []int64 {
	seen := make(map[int64]bool, len(decisions))
	ids := make([]int64, 0, len(decisions))
	for _, decision := range decisions {
		if !seen[decision.ClaimID] {
			seen[decision.ClaimID] = true
			ids = append(ids, decision.ClaimID)
		}
	}
	return ids
}

// everApproved reports which of these claims were agreed to at some point.
func (s *Store) everApproved(ctx context.Context, ids []int64) (map[int64]bool, error) {
	if len(ids) == 0 {
		return map[int64]bool{}, nil
	}
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where("claim_id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what has been agreed to before: %w", err)
	}
	seen := make(map[int64]bool, len(approvals))
	for _, approval := range approvals {
		seen[approval.ClaimID] = true
	}
	return seen, nil
}

// waiting narrows a query to what somebody has to look at.
//
// Three things, not one. A claim awaiting agreement is the obvious case. The
// other two are what happens when a judgment stops covering anything:
//
// A deferral that has run out has said what it was going to say. The finding
// is back, and if it does not appear here it simply reappears as new with the
// reasoning stranded behind it — which is the outcome marking a lapse exists
// to prevent.
//
// A decision the code moved out from under is the same shape: somebody made a
// judgment, it no longer applies, and they are the person who should be told.
//
// A promise whose date has gone by is the third of that shape. The work was
// to be done by then and the finding is still open, so the promise did not
// hold — and nothing else notices, because a commitment has no expiry: it goes
// on suppressing the finding, and the deadline the finding had passes behind
// it in silence.
//
// A claim that needed nobody — a short deferral — is not here at all. A work
// list containing work nobody has to do teaches people to skip rows.
func waiting(query *bun.SelectQuery, now time.Time) *bun.SelectQuery {
	// The run-out deferral asks the claim, which is where the outcome and the
	// date are. An EXISTS rather than a join, because this narrows queries
	// that already group and count over the decision and a join would multiply
	// nothing here but would have to be repeated at every caller.
	ranOut := `EXISTS (SELECT 1 FROM "claim" AS "wc" WHERE wc.id = de.claim_id
		AND wc.outcome = ? AND wc.deferred_until IS NOT NULL AND wc.deferred_until <= ?)`
	// The promise that came due, asked the same way of the same table.
	cameDue := `EXISTS (SELECT 1 FROM "claim" AS "wp" WHERE wp.id = de.claim_id
		AND wp.outcome IN (?) AND wp.committed_to IS NOT NULL AND wp.committed_to <= ?)`
	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.
			WhereOr("de.state = ? AND de.needs_approval = ? AND de.sent_back_at IS NULL", Proposed, true).
			WhereOr("de.state = ?", LapsedState).
			WhereOr("de.state IN (?, ?) AND "+ranOut, Proposed, Approved, Deferred, now).
			WhereOr("de.state IN (?, ?) AND "+cameDue, Proposed, Approved,
				bun.List([]Outcome{UpgradeNeeded, PatchNeeded}), now)
	})
}
