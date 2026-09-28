// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Whole is one claim and everything about it: what it says, what it covers
// now, and how far it has got.
//
// Assembled at claim scope rather than from a representative row. A claim is
// one argument, and every question anybody asks about it — what was decided,
// who agreed, how far it reaches, what became of it — is a question about the
// action rather than about any one of the rows it wrote.
type Whole struct {
	Claim Claim
	// Decision is a representative row — the earliest, which is the same on
	// every engine and every run. It is where the place and the finding to
	// link to are read from, and it carries nothing anybody acts on.
	Decision  Decision
	Reasoning string
	// Happened is what became of the claim, read from its rows the way the
	// proposer's own list reads it, so the two cannot disagree.
	Happened WhatHappened
	// When is the moment it became that, and who did it where a person did.
	When *time.Time
	By   int64
	// PreviouslyApproved says this was agreed to before and came back —
	// revised under the approval, or the code moved. False while it is
	// standing on an agreement, where an approval on record says only that
	// the current one exists.
	PreviouslyApproved bool
	// Rows, Issues and Places are what the claim wrote: rows, distinct issues,
	// distinct places. Places is what the bulk cap is measured against.
	Rows, Issues, Places int
	// Reach is what it covers now, in the units somebody acts in.
	Reach Reach
	// Builds names every build the claim's rows currently cover.
	Builds []string
	// Ended is what the rows that stopped applying reached at the moment they
	// stopped, one part per way of stopping: withdrawn, then lapsed. Empty
	// while every row is live.
	Ended []EndedPart
	// Outliers is what in a bulk set does not look like the rest. Only for a
	// claim over many issues; nil otherwise.
	Outliers *Outliers
	// Undisclosed says at least one row of the claim is about a finding
	// nobody has announced, which is what decides who may be named in the
	// discussion of it.
	//
	// Any row is enough, and it is not read off the representative row: that
	// one is chosen for naming the claim, and a claim is one action over many
	// places whose rows need not agree about visibility — so the most careful
	// row in the set answers for the whole of it, as it does everywhere else
	// this question is asked.
	Undisclosed bool
}

// Reach is what a claim covers now, counted the way the findings list counts.
//
// Not what it wrote. A claim reaches by matching, so a build appearing
// afterwards is covered with nobody acting — which is why this is worked out
// when it is asked for and the number an approver consented to is stored with
// the approval.
type Reach struct {
	// Folds is how many things there are to decide about, Packages how many
	// binaries those fold together, and Consumers how many things pull them
	// in. Findings is the row count underneath, which is what the register
	// and the VEX documents expand to.
	Folds, Packages, Consumers, Findings int
}

// EndedPart is the rows of a claim that stopped applying one way, and what
// they reached when they stopped.
//
// Worked out from the rows and the findings' own opening and closing, so it
// needs nothing stored beside them. Matched by place and not by version: a
// lapse is the version moving at a place, so matched on the versions it was
// written against, a lapsed row reaches nothing at the moment it lapsed.
type EndedPart struct {
	// State is how they stopped.
	State State
	// At is the latest moment a row of this part stopped.
	At time.Time
	// Rows and Places are what stopped: rows, and the distinct places they
	// sat at.
	Rows, Places int
	// Builds names every build holding an open finding at one of those places
	// at the moment its row stopped, narrowed to what the reader may see.
	Builds []string
}

// Whole reads one claim for somebody who may read every row of it.
//
// Refused whole or answered whole, for the reason ReadClaim gives: shown half,
// a reader would be told about words whose other half is about a finding they
// may not see.
func (s *Store) Whole(ctx context.Context, subject access.Subject, claimID int64) (*Whole, error) {
	claim := new(Claim)
	if err := s.db.NewSelect().Model(claim).Where("id = ?", claimID).Scan(ctx); err != nil {
		return nil, ErrNotTheirs
	}
	var rows []Decision
	if err := s.db.NewSelect().Model(&rows).Relation("Claim").
		Where("de.claim_id = ?", claimID).Order("de.id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what that claim covers: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrNotTheirs
	}
	// The case grant is asked beside the product-wide question, because a
	// collaborator reaches the decisions of the case they were brought into
	// and every list that offers them a claim links here. Offered and then
	// refused reads as a fault rather than as a rule.
	for _, row := range rows {
		if !readableOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return nil, ErrNotTheirs
		}
	}

	whole := &Whole{Claim: *claim, Decision: rows[0], Rows: len(rows)}
	issues := map[int64]bool{}
	places := map[string]bool{}
	for _, row := range rows {
		issues[row.VulnerabilityID] = true
		places[row.PlaceIdentity] = true
		if row.Visibility == access.Private {
			whole.Undisclosed = true
		}
	}
	whole.Issues, whole.Places = len(issues), len(places)

	reasoning, err := s.currentReasoning(ctx, []Decision{rows[0]})
	if err != nil {
		return nil, err
	}
	whole.Reasoning = reasoning[rows[0].ID]

	var agreements []Approval
	if err := s.db.NewSelect().Model(&agreements).
		Where("claim_id = ?", claimID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was agreed to: %w", err)
	}
	whole.Happened, whole.When, whole.By = became(rows,
		map[int64][]Approval{claimID: agreements})

	before, err := s.everApproved(ctx, []int64{claimID})
	if err != nil {
		return nil, err
	}
	// An approval on record and the claim not standing on one. Asked of a
	// claim that is currently approved, "was this ever approved" answers yes
	// about the agreement being read, which is not the question.
	whole.PreviouslyApproved = before[claimID] && whole.Happened != AgreedTo

	builds, err := s.buildsCovered(ctx, subject, []int64{claimID})
	if err != nil {
		return nil, err
	}
	whole.Builds = builds[claimID]
	if whole.Builds == nil {
		whole.Builds = []string{}
	}

	if whole.Reach, err = s.reachOf(ctx, subject, claimID); err != nil {
		return nil, err
	}
	if whole.Ended, err = s.endedParts(ctx, subject, claimID, rows); err != nil {
		return nil, err
	}

	many, err := s.overMany(ctx, *claim)
	if err != nil {
		return nil, err
	}
	if many {
		outliers, err := s.outliersFor(ctx, subject, []Claim{*claim})
		if err != nil {
			return nil, err
		}
		whole.Outliers = outliers[claimID]
	}
	return whole, nil
}

// reachOf counts what a claim covers now, in the units somebody acts in.
//
// The same match a finding makes when it asks whether a decision applies to
// it, so what is counted here is exactly what the judgment suppresses.
// Narrowed to the findings the reader may see: a claim somebody may read can
// match findings they may not, and a count is the leak even where no row is
// shown.
func (s *Store) reachOf(ctx context.Context, subject access.Subject, claimID int64) (Reach, error) {
	var counted struct {
		Folds     int `bun:"folds"`
		Packages  int `bun:"packages"`
		Consumers int `bun:"consumers"`
		Direct    int `bun:"direct"`
		Findings  int `bun:"findings"`
	}
	query := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		// The decision on the outside of the join, for the reason Describe
		// gives: SQLite otherwise starts from every open finding.
		Join(`CROSS JOIN "finding" AS "f"`).
		Where("f.vulnerability_id = de.vulnerability_id AND f.place_identity = de.place_identity").
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("COUNT(DISTINCT "+finding.FoldedOn+`) AS "folds"`).
		ColumnExpr(`COUNT(DISTINCT f.component_id) AS "packages"`).
		ColumnExpr(`COUNT(DISTINCT f.consumer_id) AS "consumers"`).
		// A component nothing pulls in has no consumer to count distinctly,
		// so the build itself is the one thing pulling it in.
		ColumnExpr(`COALESCE(SUM(CASE WHEN f.consumer_id IS NULL THEN 1 ELSE 0 END), 0) AS "direct"`).
		ColumnExpr(`COUNT(*) AS "findings"`).
		Where("de.claim_id = ?", claimID).
		// Live rows only: a row withdrawn or lapsed covers nothing, however
		// well its versions still match.
		Where("de.live_key IS NOT NULL").
		Where("f.closed_at IS NULL").
		Where("st.product_id = de.product_id").
		Where(finding.KeyMatches)
	if err := readableFindings(query, subject, "f", "st.product_id").
		Scan(ctx, &counted); err != nil {
		return Reach{}, fmt.Errorf("count what that claim covers: %w", err)
	}
	reach := Reach{
		Folds: counted.Folds, Packages: counted.Packages,
		Consumers: counted.Consumers, Findings: counted.Findings,
	}
	if counted.Direct > 0 {
		reach.Consumers++
	}
	return reach, nil
}

// endedParts reports what a claim's withdrawn and lapsed rows reached when
// each stopped.
//
// A finding counts where it was open at its own row's moment: opened at or
// before it and not closed by then. Each row is asked at its own moment,
// because the rows of one part can stop at different times.
func (s *Store) endedParts(ctx context.Context, subject access.Subject, claimID int64,
	rows []Decision) ([]EndedPart, error) {

	parts := map[State]*EndedPart{}
	places := map[State]map[string]bool{}
	for _, row := range rows {
		if row.State != Withdrawn && row.State != LapsedState {
			continue
		}
		part := parts[row.State]
		if part == nil {
			part = &EndedPart{State: row.State, Builds: []string{}}
			parts[row.State], places[row.State] = part, map[string]bool{}
		}
		part.Rows++
		places[row.State][row.PlaceIdentity] = true
		if row.EndedAt != nil && row.EndedAt.After(part.At) {
			part.At = *row.EndedAt
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}

	var reached []struct {
		State   State  `bun:"state"`
		Stream  string `bun:"stream"`
		Variant string `bun:"variant"`
	}
	query := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		// The decision on the outside of the join, for the reason Describe
		// gives: SQLite otherwise starts from every finding.
		Join(`CROSS JOIN "finding" AS "f"`).
		Where("f.vulnerability_id = de.vulnerability_id AND f.place_identity = de.place_identity").
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`de.state AS "state"`).
		ColumnExpr(`MIN(st.display_name) AS "stream"`).
		ColumnExpr(`MIN(va.display_name) AS "variant"`).
		Where("de.claim_id = ?", claimID).
		Where("de.state IN (?, ?)", Withdrawn, LapsedState).
		Where("de.ended_at IS NOT NULL").
		Where("st.product_id = de.product_id").
		Where("f.opened_at <= de.ended_at").
		Where("(f.closed_at IS NULL OR f.closed_at > de.ended_at)")
	if err := readableFindings(query, subject, "f", "st.product_id").
		GroupExpr("de.state, st.name, va.name").
		OrderExpr("de.state, st.name, va.name").
		Scan(ctx, &reached); err != nil {
		return nil, fmt.Errorf("read what that claim reached when it stopped: %w", err)
	}
	for _, one := range reached {
		if part := parts[one.State]; part != nil {
			part.Builds = append(part.Builds, one.Stream+" · "+one.Variant)
		}
	}

	out := make([]EndedPart, 0, len(parts))
	for _, state := range []State{Withdrawn, LapsedState} {
		if part := parts[state]; part != nil {
			part.Places = len(places[state])
			out = append(out, *part)
		}
	}
	return out, nil
}
