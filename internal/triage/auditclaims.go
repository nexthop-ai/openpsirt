// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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

// SeveralStates is the word for a claim whose matching rows are not all in one
// state.
const SeveralStates = "mixed"

// JudgedClaim is one claim as the record lists it: the argument once, with how
// much of it the question asked matched.
//
// Every count is of the rows the filters matched and the reader may see. A
// claim is listed because some of its rows answer the question, and counting
// the rest into it would show rows nobody asked for, or rows the reader may not
// read.
type JudgedClaim struct {
	Claim Claim
	// Reasoning is the words the claim currently rests on.
	Reasoning string
	// ProposedByName and Approvals are the separation-of-duties record, as on
	// a single judgment.
	ProposedByName string
	Approvals      []Agreed
	// Issue, Component, Version, Consumer, Product and ProductName name what
	// the earliest matching row was about. The counts below say how
	// representative that is.
	Issue, Component, Version, Consumer string
	Product, ProductName                string
	// Decisions is the matching rows; Issues, Places and Products are the
	// distinct issues, places and products among them. Components is the
	// distinct component names at those places, counted through the findings
	// the reader may read.
	Decisions, Issues, Places, Products, Components int
	// States is the matching rows by state.
	States map[State]int
	// Standing is how many of the matching rows apply now.
	Standing int
}

// State is the claim's matching rows in one word: their state where they share
// one, and SeveralStates where they do not.
func (c JudgedClaim) State() string {
	word := ""
	for _, state := range States() {
		if c.States[state] == 0 {
			continue
		}
		if word != "" {
			return SeveralStates
		}
		word = string(state)
	}
	return word
}

// BySomebodyElse reports whether somebody other than the proposer has a
// standing agreement on the claim.
func (c JudgedClaim) BySomebodyElse() bool { return bySomebodyElse(c.Approvals, c.ProposedByName) }

// AuditClaims returns the record a claim at a time, newest first: every claim
// with a row the filters match and the reader may see, ordered by the newest
// such row.
//
// Grouped when read. A judgment covering forty places is one argument by one
// person, and a list of it forty times over is a list nobody reads. The rows
// stay in the per-decision read, which the file is written from.
func (s *Store) AuditClaims(ctx context.Context, subject access.Subject, f Filter,
	from, to time.Time, limit, offset int) ([]JudgedClaim, int, error) {

	limit = database.AList.Of(limit)
	narrow := auditedBy(subject, f, from, to)
	matching := func() *bun.SelectQuery {
		return narrow(s.db.NewSelect().Model((*Decision)(nil)))
	}

	grouped := func() *bun.SelectQuery {
		return matching().
			ColumnExpr(`de.claim_id AS "claim_id"`).
			ColumnExpr(`MAX(de.id) AS "newest"`).
			GroupExpr("de.claim_id")
	}
	total, err := s.db.NewSelect().TableExpr(`(?) AS "page"`, grouped()).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count the claims in the record: %w", err)
	}
	var page []struct {
		ClaimID int64 `bun:"claim_id"`
		Newest  int64 `bun:"newest"`
	}
	if err := grouped().OrderExpr(`"newest" DESC`).
		Limit(limit).Offset(offset).Scan(ctx, &page); err != nil {
		return nil, 0, fmt.Errorf("read the claims in the record: %w", err)
	}
	if len(page) == 0 {
		return nil, total, nil
	}
	ids := make([]int64, 0, len(page))
	for _, row := range page {
		ids = append(ids, row.ClaimID)
	}

	var sizes []struct {
		ClaimID   int64 `bun:"claim_id"`
		Decisions int   `bun:"decisions"`
		Issues    int   `bun:"issues"`
		Places    int   `bun:"places"`
		Products  int   `bun:"products"`
		Earliest  int64 `bun:"earliest"`
	}
	if err := matching().
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		ColumnExpr(`COUNT(DISTINCT de.vulnerability_id) AS "issues"`).
		ColumnExpr(`COUNT(DISTINCT de.place_identity) AS "places"`).
		ColumnExpr(`COUNT(DISTINCT de.product_id) AS "products"`).
		ColumnExpr(`MIN(de.id) AS "earliest"`).
		Where("de.claim_id IN (?)", bun.List(ids)).
		GroupExpr("de.claim_id").Scan(ctx, &sizes); err != nil {
		return nil, 0, fmt.Errorf("count what each claim covers: %w", err)
	}

	var byState []struct {
		ClaimID   int64 `bun:"claim_id"`
		State     State `bun:"state"`
		Decisions int   `bun:"decisions"`
	}
	if err := matching().
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.state AS "state"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		Where("de.claim_id IN (?)", bun.List(ids)).
		GroupExpr("de.claim_id").GroupExpr("de.state").Scan(ctx, &byState); err != nil {
		return nil, 0, fmt.Errorf("count each claim's states: %w", err)
	}

	// What applies now, the condition Judged.Standing reads off one row.
	standing, held := finding.InForce()
	var inForce []struct {
		ClaimID   int64 `bun:"claim_id"`
		Decisions int   `bun:"decisions"`
	}
	if err := matching().
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		Where("de.claim_id IN (?)", bun.List(ids)).
		Where("de.live_key IS NOT NULL").Where(standing, held...).
		GroupExpr("de.claim_id").Scan(ctx, &inForce); err != nil {
		return nil, 0, fmt.Errorf("count what each claim still covers: %w", err)
	}

	// Component names through the findings at the matching places, narrowed to
	// the findings the reader may read: a name read off a finding they may not
	// is the disclosure, even as a count.
	components := matching().
		Join(finding.DecisionIssue).
		Join(`JOIN "finding" AS "f" ON f.vulnerability_id = dv.issue_id`+
			` AND f.place_identity = de.place_identity`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id AND st.product_id = de.product_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`COUNT(DISTINCT c.name_folded) AS "components"`).
		Where("de.claim_id IN (?)", bun.List(ids)).
		GroupExpr("de.claim_id")
	components = readableFindings(components, subject, "f", "st.product_id")
	var named []struct {
		ClaimID    int64 `bun:"claim_id"`
		Components int   `bun:"components"`
	}
	if err := components.Scan(ctx, &named); err != nil {
		return nil, 0, fmt.Errorf("count the components each claim covers: %w", err)
	}

	var claims []Claim
	if err := s.db.NewSelect().Model(&claims).
		Where("cl.id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("read the claims in the record: %w", err)
	}
	proposers := make([]int64, 0, len(claims))
	for _, claim := range claims {
		proposers = append(proposers, claim.ProposedBy)
	}
	agreed, people, err := s.agreedAndNamed(ctx, ids, proposers)
	if err != nil {
		return nil, 0, err
	}
	reasoning, err := s.reasoningPerClaim(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	representatives := make([]Decision, 0, len(sizes))
	for _, size := range sizes {
		representatives = append(representatives, Decision{ID: size.Earliest})
	}
	about, err := s.aboutEach(ctx, representatives)
	if err != nil {
		return nil, 0, err
	}

	gathered := make(map[int64]*JudgedClaim, len(ids))
	for _, claim := range claims {
		gathered[claim.ID] = &JudgedClaim{
			Claim: claim, Reasoning: reasoning[claim.ID],
			ProposedByName: people[claim.ProposedBy],
			Approvals:      agreed[claim.ID],
			States:         map[State]int{},
		}
	}
	for _, size := range sizes {
		entry, held := gathered[size.ClaimID]
		if !held {
			continue
		}
		entry.Decisions, entry.Issues, entry.Places = size.Decisions, size.Issues, size.Places
		entry.Products = size.Products
		if what, known := about[size.Earliest]; known {
			entry.Issue, entry.Component, entry.Version = what.Issue, what.Component, what.Version
			entry.Consumer, entry.Product, entry.ProductName = what.Consumer, what.Product, what.ProductName
		}
	}
	for _, row := range byState {
		if entry, held := gathered[row.ClaimID]; held {
			entry.States[row.State] += row.Decisions
		}
	}
	for _, row := range inForce {
		if entry, held := gathered[row.ClaimID]; held {
			entry.Standing = row.Decisions
		}
	}
	for _, row := range named {
		if entry, held := gathered[row.ClaimID]; held {
			entry.Components = row.Components
		}
	}

	out := make([]JudgedClaim, 0, len(ids))
	for _, id := range ids {
		if entry, held := gathered[id]; held {
			out = append(out, *entry)
		}
	}
	return out, total, nil
}
