package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Scrutiny is how much a second pair of eyes actually did.
//
// **It is not a list of people who broke the rule.** The rule cannot be
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
const standingAlone = `NOT EXISTS (SELECT 1 FROM "claim_approval" AS ex` +
	` WHERE ex.claim_id = de.claim_id AND ex.withdrawn_at IS NULL` +
	` AND ex.approved_by <> de.proposed_by)`

// Scrutinize reports how the second-person rule is holding.
//
// Narrowed by what the asker may see, like every other count here. A report
// about a control that answered more than the screens it summarizes would be
// a way around the control it is reporting on.
func (s *Store) Scrutinize(ctx context.Context, subject access.Subject,
	productIDs []int64, since time.Time) (*Scrutiny, error) {

	out := &Scrutiny{}
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = readableBy(q, subject, "de")
		if len(productIDs) > 0 {
			q = q.Where("de.product_id IN (?)", bun.List(productIDs))
		}
		if !since.IsZero() {
			q = q.Where("de.proposed_at >= ?", since)
		}
		return q
	}

	standing, held := finding.InForce()

	// What stands with one signature on it, by what was claimed. Grouped by
	// outcome because the answer is different for each: a short deferral
	// standing alone is the exception working, and a dismissal standing alone
	// is a control that failed.
	var alone []struct {
		Outcome string `bun:"outcome"`
		Claims  int    `bun:"claims"`
		Rows    int    `bun:"written"`
	}
	err := narrow(s.db.NewSelect().
		TableExpr("decision AS de").
		Join(`JOIN "claim" AS cl ON cl.id = de.claim_id`).
		ColumnExpr("cl.outcome AS outcome").
		ColumnExpr("COUNT(DISTINCT de.claim_id) AS claims").
		ColumnExpr("COUNT(*) AS written").
		Where("cl.outcome <> ?", Affected).
		Where(standing, held...).
		Where(standingAlone).
		GroupExpr("cl.outcome")).Scan(ctx, &alone)
	if err != nil {
		return nil, fmt.Errorf("count what stands with one person behind it: %w", err)
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
		TableExpr("decision AS de").
		Join(`JOIN "claim_approval" AS ap ON ap.claim_id = de.claim_id`).
		Join(`JOIN "person" AS pe ON pe.id = ap.approved_by`).
		ColumnExpr("ap.batch AS batch").
		ColumnExpr("pe.identity AS identity").
		ColumnExpr("MIN(ap.approved_at) AS approved_at").
		ColumnExpr("COUNT(DISTINCT de.claim_id) AS claims").
		ColumnExpr("COUNT(*) AS written").
		Where("ap.batch IS NOT NULL").
		Where("ap.withdrawn_at IS NULL").
		GroupExpr("ap.batch, pe.identity").
		OrderExpr("written DESC")).Scan(ctx, &bulk)
	if err != nil {
		return nil, fmt.Errorf("read which agreements were given in bulk: %w", err)
	}
	for _, row := range bulk {
		out.Bulk = append(out.Bulk, BulkApproval{
			Batch: row.Batch, ApprovedBy: row.Identity, ApprovedAt: row.ApprovedAt,
			Claims: row.Claims, Rows: row.Rows,
		})
	}

	// Who agrees with whom. Concentration is the signal: two people covering
	// everything between them is a control that exists on paper.
	var pairs []struct {
		Proposer string `bun:"proposer"`
		Approver string `bun:"approver"`
		Claims   int    `bun:"claims"`
		Rows     int    `bun:"written"`
	}
	err = narrow(s.db.NewSelect().
		TableExpr("decision AS de").
		Join(`JOIN "claim_approval" AS ap ON ap.claim_id = de.claim_id`).
		Join(`JOIN "person" AS pr ON pr.id = de.proposed_by`).
		Join(`JOIN "person" AS ape ON ape.id = ap.approved_by`).
		ColumnExpr("pr.identity AS proposer").
		ColumnExpr("ape.identity AS approver").
		ColumnExpr("COUNT(DISTINCT de.claim_id) AS claims").
		ColumnExpr("COUNT(*) AS written").
		Where("ap.withdrawn_at IS NULL").
		GroupExpr("pr.identity, ape.identity").
		OrderExpr("written DESC")).Scan(ctx, &pairs)
	if err != nil {
		return nil, fmt.Errorf("read who agrees with whom: %w", err)
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
		TableExpr("decision AS de").
		Join(`JOIN "claim" AS cl ON cl.id = de.claim_id`).
		Join(`JOIN "claim_approval" AS ap ON ap.claim_id = de.claim_id`).
		Join(`JOIN "person" AS pe ON pe.id = ap.approved_by`).
		Join(`JOIN "product" AS pd ON pd.id = de.product_id`).
		ColumnExpr("de.claim_id AS claim_id").
		ColumnExpr("pe.identity AS identity").
		ColumnExpr("MIN(ap.approved_at) AS approved_at").
		ColumnExpr("pd.name AS product").
		ColumnExpr("cl.outcome AS outcome").
		ColumnExpr("COUNT(*) AS written").
		Where("ap.withdrawn_at IS NULL").
		Where(standing, held...).
		// The right they used, checked against what they hold now rather than
		// against what they held then: the question is whether the person who
		// agreed could agree today. A grant made inactive by a change of mode
		// is kept so the change can be undone, and it grants nothing while it
		// sits there — so it is not a right somebody still holds.
		Where(`NOT EXISTS (SELECT 1 FROM "role_grant" AS rg`+
			` WHERE rg.person_id = ap.approved_by AND rg.product_id = de.product_id`+
			` AND rg.active = ? AND rg.role = ?)`, true, access.Approver).
		// An administrator reaches every product, so one is never in this list
		// however their grants read.
		Where(`NOT EXISTS (SELECT 1 FROM "person" AS ad`+
			` WHERE ad.id = ap.approved_by AND ad.is_admin = ?)`, true).
		GroupExpr("de.claim_id, pe.identity, pd.name, cl.outcome").
		OrderExpr("written DESC")).Scan(ctx, &lapsed)
	if err != nil {
		return nil, fmt.Errorf("read which approvers have lost the right: %w", err)
	}
	for _, row := range lapsed {
		out.Lapsed = append(out.Lapsed, LapsedApproval{
			ClaimID: row.ClaimID, ApprovedBy: row.Identity, ApprovedAt: row.ApprovedAt,
			Product: row.Product, Outcome: Outcome(row.Outcome), Rows: row.Rows,
		})
	}

	// What somebody agreed to, against what the same claim reaches now. A
	// claim reaches by matching, so a build appearing afterwards is covered
	// with nobody acting — and nobody having agreed to the larger number.
	var grew []struct {
		ClaimID    int64     `bun:"claim_id"`
		Identity   string    `bun:"identity"`
		ApprovedAt time.Time `bun:"approved_at"`
		Outcome    string    `bun:"outcome"`
		Covered    int       `bun:"covered"`
	}
	err = narrow(s.db.NewSelect().
		TableExpr("decision AS de").
		Join(`JOIN "claim" AS cl ON cl.id = de.claim_id`).
		Join(`JOIN "claim_approval" AS ap ON ap.claim_id = de.claim_id`).
		Join(`JOIN "person" AS pe ON pe.id = ap.approved_by`).
		ColumnExpr("de.claim_id AS claim_id").
		ColumnExpr("pe.identity AS identity").
		ColumnExpr("MIN(ap.approved_at) AS approved_at").
		ColumnExpr("cl.outcome AS outcome").
		ColumnExpr("MIN(ap.covered) AS covered").
		Where("ap.withdrawn_at IS NULL").
		Where("ap.covered IS NOT NULL").
		Where(standing, held...).
		GroupExpr("de.claim_id, pe.identity, cl.outcome")).Scan(ctx, &grew)
	if err != nil {
		return nil, fmt.Errorf("read what was agreed to: %w", err)
	}
	for _, row := range grew {
		// What it covers now, asked the way a finding asks whether a decision
		// applies to it. One statement per claim rather than per row.
		ids, err := s.decisionsOf(ctx, subject, row.ClaimID)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			continue
		}
		now, err := s.covering(ctx, subject, ids)
		if err != nil {
			return nil, err
		}
		if now <= row.Covered {
			continue
		}
		out.Grew = append(out.Grew, Grown{
			ClaimID: row.ClaimID, ApprovedBy: row.Identity, ApprovedAt: row.ApprovedAt,
			Outcome: Outcome(row.Outcome), Covered: row.Covered, CoversNow: now,
		})
	}

	return out, nil
}

// decisionsOf is which rows a claim wrote, narrowed to what the asker may see.
func (s *Store) decisionsOf(ctx context.Context, subject access.Subject,
	claimID int64) ([]int64, error) {

	var ids []int64
	err := readableBy(s.db.NewSelect().
		TableExpr("decision AS de").
		ColumnExpr("de.id").
		Where("de.claim_id = ?", claimID), subject, "de").Scan(ctx, &ids)
	if err != nil {
		return nil, fmt.Errorf("read which rows a claim wrote: %w", err)
	}
	return ids, nil
}
