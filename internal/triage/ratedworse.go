// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// ratedWorse reports whether an issue now sits in a higher band than it did
// when a claim was made about it.
//
// A band rather than the score. A rescoring from 7.5 to 7.6 is the same
// judgment about the same issue; high becoming critical is not.
//
// An issue nobody had rated when the claim was made is read as a medium, the
// way a deadline reads one: unknown is not harmless, and not the lowest either.
func ratedWorse(baseline *int, now int) bool {
	was := finding.SeverityScore("medium")
	if baseline != nil && *baseline > 0 {
		was = band(*baseline)
	}
	return band(now) > was
}

// band is a score folded to the midpoint of the band it falls in, which
// orders the bands.
func band(centi int) int {
	if centi <= 0 {
		return finding.SeverityScore("medium")
	}
	return finding.SeverityScore(finding.SeverityWord(centi))
}

// RatedWorseWhere narrows a sweep for claims a severity rise has outgrown.
// Zero values ask about everything.
type RatedWorseWhere struct {
	ProductID int64
	// Vulnerabilities is the issues whose rating may have moved.
	Vulnerabilities []int64
	// OpenIn is a build whose open issues may have moved, which is what a
	// scan says about the issues it reported.
	OpenIn int64
}

// LapseRatedWorse marks the standing claims an issue's severity has risen past
// (REQ-25).
//
// A claim that an issue does not matter much is not a claim about what it has
// become, where the judgment is one a severity bears on. The claim lapses the
// way a version move lapses it: it stops standing, the finding is open again,
// and the proposer is told, so re-affirming it is the proposer's to do and a
// second person's to agree to.
//
// Proposed claims lapse as well as approved ones. Agreed to afterwards, a
// claim made against the lower rating would stand on a baseline that is
// already wrong.
//
// Asked of the rating in force in each claim's own product, compared by band
// in Go, because the rule for the rating in force is written there once.
func (s *Store) LapseRatedWorse(ctx context.Context, where RatedWorseWhere) (Lapsed, error) {
	db, err := s.pool()
	if err != nil {
		return Lapsed{}, err
	}
	out := Lapsed{}
	var lapsed []int64
	err = database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		lapsed = nil
		groups, err := ratedWorseGroups(ctx, tx, where)
		if err != nil {
			return err
		}
		var ids []int64
		for _, group := range groups {
			claim := Claim{Outcome: Outcome(group.Outcome), Justification: group.Justification}
			if !turnsOnSeverity(claim) {
				continue
			}
			now := finding.Rating{
				Published: group.Published, Assessed: group.Assessed, ScoreCenti: group.ScoreCenti,
			}.Score()
			if !ratedWorse(group.Baseline, now) {
				continue
			}
			var rows []int64
			q := tx.NewSelect().Model((*Decision)(nil)).
				ColumnExpr("de.id").
				Where("de.claim_id = ?", group.ClaimID).
				Where("de.product_id = ?", group.ProductID).
				Where("de.vulnerability_id = ?", group.VulnerabilityID).
				Where("de.state IN (?, ?)", Proposed, Approved).
				Where("de.live_key IS NOT NULL")
			if group.Baseline == nil {
				q = q.Where("de.severity_centi IS NULL")
			} else {
				q = q.Where("de.severity_centi = ?", *group.Baseline)
			}
			if err := q.Where(coversSomething).Scan(ctx, &rows); err != nil {
				return fmt.Errorf("read what a severity rise outgrew: %w", err)
			}
			ids = append(ids, rows...)
		}
		moment := s.now().Truncate(time.Microsecond)
		for start := 0; start < len(ids); start += database.InBulk.Most {
			end := min(start+database.InBulk.Most, len(ids))
			chunk := ids[start:end]
			// A row another sweep, a withdrawal or an approval moved in
			// between is not this sweep's to report. Run again, the read no
			// longer finds it, and nobody is told twice.
			changed, err := markLapsed(ctx, tx, chunk, moment)
			if err != nil {
				return fmt.Errorf("mark what a severity rise outgrew: %w", err)
			}
			if changed != int64(len(chunk)) {
				return database.ErrGoAgain
			}
		}
		lapsed = ids
		return nil
	})
	if err != nil {
		return Lapsed{}, err
	}
	if len(lapsed) == 0 {
		return out, nil
	}
	// Committed, so what lapsed is reported even when reading who to tell
	// fails part way.
	out.Rows = int64(len(lapsed))
	told, err := s.proposersOfAll(ctx, lapsed, database.InBulk.Most)
	for i := range told {
		told[i].RatedWorse = true
	}
	out.Told = told
	return out, err
}

// coversSomething keeps the decisions an open finding in their product still
// matches, at the versions they were made against, for a query over decision
// AS "de".
//
// A decision covering nothing is not a judgment anybody is relying on. Lapsed
// for a rating, its proposer would be told the finding is open again when none
// is, and re-affirming it would find nothing to re-make.
var coversSomething = `EXISTS (SELECT 1 FROM "finding" AS "fc"` +
	` JOIN "component" AS "c" ON c.id = fc.component_id` +
	` LEFT JOIN "component" AS "uc" ON uc.id = fc.consumer_id` +
	` JOIN "target" AS "tgc" ON tgc.id = fc.target_id` +
	` JOIN "stream" AS "stc" ON stc.id = tgc.stream_id` +
	` WHERE stc.product_id = de.product_id AND fc.closed_at IS NULL` +
	` AND ` + finding.SameIssue("fc.vulnerability_id", "de.vulnerability_id") +
	` AND fc.place_identity = de.place_identity` +
	` AND COALESCE(de.component_upstream_version, '') = ` + finding.ComponentUpstreamExpr +
	` AND COALESCE(de.consumer_upstream_version, '') = ` + finding.ConsumerUpstreamExpr + `)`

// ratedWorseGroup is the standing rows of one claim about one issue in one
// product that share a baseline, with the rating in force there now.
type ratedWorseGroup struct {
	ClaimID         int64   `bun:"claim_id"`
	ProductID       int64   `bun:"product_id"`
	VulnerabilityID int64   `bun:"vulnerability_id"`
	Outcome         string  `bun:"outcome"`
	Justification   *string `bun:"justification"`
	Baseline        *int    `bun:"baseline"`
	Published       string  `bun:"published"`
	Assessed        string  `bun:"assessed"`
	ScoreCenti      int     `bun:"score_centi"`
}

// ratedWorseGroups reads the candidates, one row per claim, issue, product
// and baseline rather than per place: a claim over a kernel issue is a row
// per place, and the rating it is compared with is the same for all of them.
func ratedWorseGroups(ctx context.Context, tx bun.IDB, where RatedWorseWhere) ([]ratedWorseGroup, error) {
	q := tx.NewSelect().
		TableExpr(finding.Decisions).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		// Rated as the issue the decision is read as.
		Join(`JOIN "vulnerability" AS "v" ON v.id = dv.issue_id`).
		Join(rating.For(rating.OnDecision)).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`de.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`cl.outcome AS "outcome"`).
		ColumnExpr(`cl.justification AS "justification"`).
		ColumnExpr(`de.severity_centi AS "baseline"`).
		ColumnExpr(`COALESCE(v.severity, '') AS "published"`).
		ColumnExpr(`COALESCE(ir.severity, '') AS "assessed"`).
		ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
		Where("de.state IN (?, ?)", Proposed, Approved).
		Where("de.live_key IS NOT NULL").
		Where(coversSomething).
		GroupExpr("de.claim_id, de.product_id, de.vulnerability_id, cl.outcome, " +
			"cl.justification, de.severity_centi, v.severity, ir.severity, v.score_centi")
	if where.ProductID > 0 {
		q = q.Where("de.product_id = ?", where.ProductID)
	}
	if len(where.Vulnerabilities) > 0 {
		q = q.Where(finding.FiledUnderAny("de.vulnerability_id"), bun.List(where.Vulnerabilities))
	}
	if where.OpenIn > 0 {
		q = q.Where(`dv.issue_id IN (SELECT "fo".vulnerability_id FROM "finding" AS "fo"`+
			` WHERE "fo".target_id = ? AND "fo".closed_at IS NULL)`, where.OpenIn)
	}
	var groups []ratedWorseGroup
	if err := q.Scan(ctx, &groups); err != nil {
		return nil, fmt.Errorf("read the standing claims a rating may have outgrown: %w", err)
	}
	return groups, nil
}
