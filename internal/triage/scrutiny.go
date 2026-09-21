package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Scrutiny is how much a second pair of eyes actually did.
//
// It is not a list of people who broke the rule. The rule cannot be
// broken: an approval refuses the proposer and refuses the author of the
// revision being agreed to, and the write is conditional on that revision
// still being current. What it reports is where the rule did not apply, and
// where it applied in form only — which is what an auditor is asking about
// when they ask whether approvals mean anything here.
type Scrutiny struct {
	// Alone is risk standing with nobody's agreement, by what was claimed.
	Alone []Unagreed
	// Bulk is agreements given as one act over many claims.
	Bulk []BulkApproval
	// Pairs is the same two people, over and over.
	Pairs []Pairing
	// Lapsed is agreements standing from somebody who no longer holds the
	// right to give them. Correct behavior — an approval is a fact about a
	// moment — and still a list somebody wants.
	Lapsed []LapsedApproval
	// Grew is what was agreed to against what it covers now.
	Grew []Grown
	// Capped says a section reached the ceiling, so what is shown is the
	// worst of it rather than all of it.
	//
	// Said rather than implied. Every section here is a control reporting on
	// itself, and a capped list that reads as complete is the one thing a
	// report like this must not be — a compliance reader is exactly who would
	// be misled.
	Capped bool
}

// Unagreed is risk hidden with no second person, grouped by what was claimed.
type Unagreed struct {
	Outcome Outcome
	// Claims and Rows are the same population in the two units: how many acts,
	// and how many decisions those acts wrote.
	Claims int
	Rows   int
}

// BulkApproval is one act of agreement covering many claims.
type BulkApproval struct {
	Batch      string
	ApprovedBy string
	ApprovedAt time.Time
	Claims     int
	Rows       int
}

// Pairing is one proposer and one approver, and how much has passed between
// them.
type Pairing struct {
	Proposer string
	Approver string
	Claims   int
	Rows     int
}

// LapsedApproval is an agreement still standing from somebody who has since
// lost the right to give one.
type LapsedApproval struct {
	ClaimID    int64
	ApprovedBy string
	ApprovedAt time.Time
	Product    string
	Outcome    Outcome
	Rows       int
}

// Grown is a claim covering more now than when somebody agreed to it.
type Grown struct {
	ClaimID    int64
	ApprovedBy string
	ApprovedAt time.Time
	Outcome    Outcome
	// Covered is what the approver was agreeing to, recorded then. CoversNow
	// is what the same claim reaches today, having reached it by matching
	// rather than by anybody acting.
	Covered   int
	CoversNow int
}

// standingAlone is risk that applies now with nobody's agreement behind it.
//
// Written as a test of the record rather than of a stored flag, the way the
// record's own question is: no approval row from anybody other than the
// proposer, and none that has been taken back. A flag would report what
// something asserted about itself.
const standingAlone = `NOT EXISTS (SELECT 1 FROM "claim_approval" AS "ex"` +
	` WHERE ex.claim_id = de.claim_id AND ex.withdrawn_at IS NULL` +
	` AND ex.approved_by <> de.proposed_by)`

// Scrutinize reports how the second-person rule is holding.
//
// Narrowed by what the asker may see, like every other count here. A report
// about a control that answered more than the screens it summarizes would be
// a way around the control it is reporting on.
func (s *Store) Scrutinize(ctx context.Context, subject access.Subject,
	productIDs []int64, since, until time.Time, limit int) (*Scrutiny, error) {

	// Every section bounded, like every other read in this package. None of
	// them was: a deployment that has been triaging for a while answered one
	// row per approved claim in force, and the last of them then issued three
	// more round trips each — thirty thousand of them in one request on ten
	// thousand claims, with nothing checking whether the caller was still
	// there.
	limit = database.AList.Of(limit)
	out := &Scrutiny{}
	// One more than the ceiling, so that reaching it is distinguishable from
	// landing on it exactly.
	room := limit + 1
	capped := func(n int) bool { return n >= room }
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = readableBy(q, subject, "de")
		if len(productIDs) > 0 {
			q = q.Where("de.product_id IN (?)", bun.List(productIDs))
		}
		// Dated by when the claim was proposed, which is what every section
		// here is about: a judgment belongs to when it was argued, and dating
		// it by its agreement would move it out of the period whenever an
		// approval came late — the ordinary case.
		if !since.IsZero() {
			q = q.Where("de.proposed_at >= ?", since)
		}
		if !until.IsZero() {
			q = q.Where("de.proposed_at < ?", until)
		}
		return q
	}

	standing, held := finding.InForce()

	// alone is what stands with one signature on it, by what was claimed.
	// Grouped by outcome because the answer is different for each: a short
	// deferral standing alone is the exception working, and a dismissal
	// standing alone is a control that failed.
	var alone []struct {
		Outcome string `bun:"outcome"`
		Claims  int    `bun:"claims"`
		Rows    int    `bun:"written"`
	}
	err := narrow(s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`cl.outcome AS "outcome"`).
		ColumnExpr(`COUNT(DISTINCT de.claim_id) AS "claims"`).
		ColumnExpr(`COUNT(*) AS "written"`).
		Where("cl.outcome <> ?", Affected).
		Where(standing, held...).
		Where(standingAlone).
		GroupExpr("cl.outcome").
		Limit(room)).Scan(ctx, &alone)
	if err != nil {
		return nil, fmt.Errorf("count what stands with one person behind it: %w", err)
	}
	if capped(len(alone)) {
		out.Capped, alone = true, alone[:limit]
	}
	for _, row := range alone {
		out.Alone = append(out.Alone, Unagreed{
			Outcome: Outcome(row.Outcome), Claims: row.Claims, Rows: row.Rows,
		})
	}

	// Agreements given as one act. An approver may agree to a batch, which is
	// the control working at the grain the proposer acted at — and a batch of
	// two hundred is a different thing from a batch of two.
	var bulk []struct {
		Batch      string    `bun:"batch"`
		Identity   string    `bun:"identity"`
		ApprovedAt time.Time `bun:"approved_at"`
		Claims     int       `bun:"claims"`
		Rows       int       `bun:"written"`
	}
	err = narrow(s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim_approval" AS "ap" ON ap.claim_id = de.claim_id`).
		Join(`JOIN "person" AS "pe" ON pe.id = ap.approved_by`).
		ColumnExpr(`ap.batch AS "batch"`).
		ColumnExpr(`pe.identity AS "identity"`).
		ColumnExpr(`MIN(ap.approved_at) AS "approved_at"`).
		ColumnExpr(`COUNT(DISTINCT de.claim_id) AS "claims"`).
		ColumnExpr(`COUNT(*) AS "written"`).
		Where("ap.batch IS NOT NULL").
		Where("ap.withdrawn_at IS NULL").
		GroupExpr("ap.batch, pe.identity").
		OrderExpr("written DESC").
		Limit(room)).Scan(ctx, &bulk)
	if err != nil {
		return nil, fmt.Errorf("read which agreements were given in bulk: %w", err)
	}
	if capped(len(bulk)) {
		out.Capped, bulk = true, bulk[:limit]
	}
	for _, row := range bulk {
		out.Bulk = append(out.Bulk, BulkApproval{
			Batch: row.Batch, ApprovedBy: row.Identity, ApprovedAt: row.ApprovedAt,
			Claims: row.Claims, Rows: row.Rows,
		})
	}

	// pairs is who agrees with whom. Concentration is the signal: two
	// people covering everything between them is a control that exists on
	// paper.
	var pairs []struct {
		Proposer string `bun:"proposer"`
		Approver string `bun:"approver"`
		Claims   int    `bun:"claims"`
		Rows     int    `bun:"written"`
	}
	err = narrow(s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim_approval" AS "ap" ON ap.claim_id = de.claim_id`).
		Join(`JOIN "person" AS "pr" ON pr.id = de.proposed_by`).
		Join(`JOIN "person" AS "ape" ON ape.id = ap.approved_by`).
		ColumnExpr(`pr.identity AS "proposer"`).
		ColumnExpr(`ape.identity AS "approver"`).
		ColumnExpr(`COUNT(DISTINCT de.claim_id) AS "claims"`).
		ColumnExpr(`COUNT(*) AS "written"`).
		Where("ap.withdrawn_at IS NULL").
		GroupExpr("pr.identity, ape.identity").
		OrderExpr("written DESC").
		Limit(room)).Scan(ctx, &pairs)
	if err != nil {
		return nil, fmt.Errorf("read who agrees with whom: %w", err)
	}
	if capped(len(pairs)) {
		out.Capped, pairs = true, pairs[:limit]
	}
	for _, row := range pairs {
		out.Pairs = append(out.Pairs, Pairing{
			Proposer: row.Proposer, Approver: row.Approver,
			Claims: row.Claims, Rows: row.Rows,
		})
	}

	// Agreements standing from somebody who has since lost the right to give
	// one. An approval is a fact about a moment, so it is right that this
	// stands — and it is still the first thing an auditor asks after a
	// reorganization.
	var lapsed []struct {
		ClaimID    int64     `bun:"claim_id"`
		Identity   string    `bun:"identity"`
		ApprovedAt time.Time `bun:"approved_at"`
		Product    string    `bun:"product"`
		Outcome    string    `bun:"outcome"`
		Rows       int       `bun:"written"`
	}
	err = narrow(s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Join(`JOIN "claim_approval" AS "ap" ON ap.claim_id = de.claim_id`).
		Join(`JOIN "person" AS "pe" ON pe.id = ap.approved_by`).
		Join(`JOIN "product" AS "pd" ON pd.id = de.product_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`pe.identity AS "identity"`).
		ColumnExpr(`MIN(ap.approved_at) AS "approved_at"`).
		ColumnExpr(`pd.name AS "product"`).
		ColumnExpr(`cl.outcome AS "outcome"`).
		ColumnExpr(`COUNT(*) AS "written"`).
		Where("ap.withdrawn_at IS NULL").
		Where(standing, held...).
		// The right they used, checked against what they hold now rather than
		// against what they held then: the question is whether the person who
		// agreed could agree today. A grant made inactive by a change of mode
		// is kept so the change can be undone, and it grants nothing while it
		// sits there — so it is not a right somebody still holds.
		Where(`NOT EXISTS (SELECT 1 FROM "role_grant" AS "rg"`+
			` WHERE rg.person_id = ap.approved_by AND rg.product_id = de.product_id`+
			` AND rg.active = ? AND rg.role = ?)`, true, access.Approver).
		// Nor one held across every product, which is the same right reached
		// by the other grant. Without this an approver holding it that way
		// had every approval they ever gave reported as lapsed.
		Where(`NOT EXISTS (SELECT 1 FROM "role_grant_all" AS "rga"`+
			` WHERE rga.person_id = ap.approved_by`+
			` AND rga.active = ? AND rga.role = ?)`, true, access.Approver).
		// An administrator reaches every product, so one is never in this list
		// however their grants read.
		Where(`NOT EXISTS (SELECT 1 FROM "person" AS "ad"`+
			` WHERE ad.id = ap.approved_by AND ad.is_admin = ?)`, true).
		GroupExpr("de.claim_id, pe.identity, pd.name, cl.outcome").
		OrderExpr("written DESC").
		Limit(room)).Scan(ctx, &lapsed)
	if err != nil {
		return nil, fmt.Errorf("read which approvers have lost the right: %w", err)
	}
	if capped(len(lapsed)) {
		out.Capped, lapsed = true, lapsed[:limit]
	}
	for _, row := range lapsed {
		out.Lapsed = append(out.Lapsed, LapsedApproval{
			ClaimID: row.ClaimID, ApprovedBy: row.Identity, ApprovedAt: row.ApprovedAt,
			Product: row.Product, Outcome: Outcome(row.Outcome), Rows: row.Rows,
		})
	}

	// grew is what somebody agreed to, against what the same claim reaches
	// now. A claim reaches by matching, so a build appearing afterwards is
	// covered with nobody acting — and nobody having agreed to the larger
	// number.
	var grew []struct {
		ClaimID    int64     `bun:"claim_id"`
		Identity   string    `bun:"identity"`
		ApprovedAt time.Time `bun:"approved_at"`
		Outcome    string    `bun:"outcome"`
		Covered    int       `bun:"covered"`
	}
	err = narrow(s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Join(`JOIN "claim_approval" AS "ap" ON ap.claim_id = de.claim_id`).
		Join(`JOIN "person" AS "pe" ON pe.id = ap.approved_by`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`pe.identity AS "identity"`).
		ColumnExpr(`MIN(ap.approved_at) AS "approved_at"`).
		ColumnExpr(`cl.outcome AS "outcome"`).
		ColumnExpr(`MIN(ap.covered) AS "covered"`).
		Where("ap.withdrawn_at IS NULL").
		Where("ap.covered IS NOT NULL").
		Where(standing, held...).
		GroupExpr("de.claim_id, pe.identity, cl.outcome").
		OrderExpr("de.claim_id").
		Limit(room)).Scan(ctx, &grew)
	if err != nil {
		return nil, fmt.Errorf("read what was agreed to: %w", err)
	}
	if capped(len(grew)) {
		out.Capped, grew = true, grew[:limit]
	}
	// Each one's present reach, asked the way a finding asks whether a
	// decision applies to it — in one statement over the whole page. It was
	// three round trips per claim, in a loop, with nothing between them: on
	// ten thousand claims that is thirty thousand sequential statements in one
	// request, and the work carried on after the caller had gone.
	claims := make([]int64, 0, len(grew))
	for _, row := range grew {
		claims = append(claims, row.ClaimID)
	}
	now, err := s.coveringEach(ctx, subject, claims)
	if err != nil {
		return nil, err
	}
	for _, row := range grew {
		if now[row.ClaimID] <= row.Covered {
			continue
		}
		out.Grew = append(out.Grew, Grown{
			ClaimID: row.ClaimID, ApprovedBy: row.Identity, ApprovedAt: row.ApprovedAt,
			Outcome: Outcome(row.Outcome), Covered: row.Covered,
			CoversNow: now[row.ClaimID],
		})
	}

	return out, nil
}

// coveringEach counts what each of these claims covers right now.
//
// One statement for the page rather than three round trips per claim. The
// visibilities are read once over the whole set rather than per claim: where a
// set spans products the answer is the narrower one, which discloses less
// rather than more, and that is the same rule the per-claim read followed.
func (s *Store) coveringEach(ctx context.Context, subject access.Subject,
	claims []int64) (map[int64]int, error) {

	covered := map[int64]int{}
	if len(claims) == 0 {
		return covered, nil
	}
	var ids []int64
	if err := readableBy(s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		ColumnExpr("de.id").
		Where("de.claim_id IN (?)", bun.List(claims)), subject, "de").
		Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("read which rows these claims wrote: %w", err)
	}
	if len(ids) == 0 {
		return covered, nil
	}
	readable := readableVisibilities(subject, ids, s, ctx)

	var rows []struct {
		ClaimID int64 `bun:"claim_id"`
		Covers  int   `bun:"covers"`
	}
	err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "finding" AS "f" ON f.vulnerability_id = de.vulnerability_id`+
			" AND f.place_identity = de.place_identity").
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id AND st.product_id = de.product_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`COUNT(*) AS "covers"`).
		Where("de.id IN (?)", bun.List(ids)).
		Where("f.closed_at IS NULL").
		Where("COALESCE(de.component_upstream_version, '') = "+finding.ComponentUpstreamExpr).
		Where("COALESCE(de.consumer_upstream_version, '') = "+finding.ConsumerUpstreamExpr).
		Where("f.visibility IN (?)", bun.List(readable)).
		GroupExpr("de.claim_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("count what these cover: %w", err)
	}
	for _, row := range rows {
		covered[row.ClaimID] = row.Covers
	}
	return covered, nil
}

// HiddenWithNobodyAgreeing counts the claims that hide risk with no second
// person behind them, and the decisions they wrote.
//
// This should answer zero, and a number is a control that did not hold. The
// outcomes that claim something needs no further work — it does not apply, the
// match is wrong, it will not be fixed, the fix is already here — each require
// a second person, so a claim of one of them standing alone is not a backlog
// item. It is
// the write path having been got around, and it is the one failure the record
// cannot find on its own afterwards.
//
// A deferral and a promise to act are here too, but only where the gate
// caught them. Both hide risk and both are approved conditionally, on where
// the date sits against the deadline already set — so a short deferral
// standing alone is the rule working rather than failing. What tells the two
// apart is the gate's own verdict, written onto the decision as it was
// proposed: a deferral past the threshold needed a second person as surely as
// a dismissal did, and left standing with nobody agreeing it is the same write
// path got around. Asked as the outcome alone this saw none of them, and said
// so in a design document.
//
// An agreement is asked of the record, never of a flag. No
// approval from anybody other than the proposer, and none taken back, which is
// the same question the report that shows these rows asks — the test that
// matters writes a self-approval straight to the table, and a flag would be
// the row's own account of itself.
//
// The gate's verdict is a flag, and it is read for the opposite half on
// purpose. Nothing a caller passes reaches it: a proposal's own answer is
// re-worked against the policy in force when the write lands. And the ones
// that dismiss are counted whatever it says, so a write path that got around
// the gate by clearing it is still caught — the flag only ever widens the
// question and never narrows it.
//
// Counted rather than listed, and unnarrowed. What it feeds is a condition told
// to administrators, which carries the fact and a link and never the rows —
// which is also why no subject is taken: administering grants no reading, so a
// narrowed count would answer about whichever products an administrator
// happened to hold.
func (s *Store) HiddenWithNobodyAgreeing(ctx context.Context) (claims, rows int, err error) {
	standing, held := finding.InForce()
	var counted struct {
		Claims int `bun:"claims"`
		Rows   int `bun:"written"`
	}
	err = s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`COUNT(DISTINCT de.claim_id) AS "claims"`).
		ColumnExpr(`COUNT(*) AS "written"`).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr("cl.outcome IN (?)", bun.List(OutcomesDismissing())).
				WhereOr("de.needs_approval = ?", true)
		}).
		Where(standing, held...).
		Where(standingAlone).
		Scan(ctx, &counted)
	if err != nil {
		return 0, 0, fmt.Errorf("count what hides risk with nobody agreeing: %w", err)
	}
	return counted.Claims, counted.Rows, nil
}
