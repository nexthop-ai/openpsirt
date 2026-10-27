// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// Whole is one decision and everything about it: what it says, what it covers
// now, and how far it has got.
//
// Assembled at decision scope rather than from a representative row. A decision is
// one argument, and every question anybody asks about it — what was decided,
// who agreed, how far it reaches, what became of it — is a question about the
// action rather than about any one of the rows it wrote.
type Whole struct {
	Decision Decision
	// DecisionOccurrence is a representative row — the earliest, which is the same on
	// every engine and every run. It is where the occurrence and the finding to
	// link to are read from, and it carries nothing anybody acts on.
	DecisionOccurrence DecisionOccurrence
	Reasoning          string
	// Happened is what became of the decision, read from its rows the way the
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
	// Rows, Issues and Occurrences are what the decision wrote: rows, distinct issues,
	// distinct occurrences. Occurrences is what the bulk cap is measured against.
	Rows, Issues, Occurrences int
	// Reach is what it covers now, in the units somebody acts in.
	Reach Reach
	// Builds names every build the decision's rows currently cover.
	Builds []string
	// Ended is what the rows that stopped applying reached at the moment they
	// stopped, one part per way of stopping: withdrawn, then lapsed. Empty
	// while every row is live.
	Ended []EndedPart
	// Outliers is what in a bulk set does not look like the rest. Only for a
	// decision over many issues; nil otherwise.
	Outliers *Outliers
	// Undisclosed says at least one row of the decision is about a finding
	// nobody has announced, which is what decides who may be named in the
	// discussion of it.
	//
	// Any row is enough, and it is not read off the representative row: that
	// one is chosen for naming the decision, and a decision is one action over many
	// occurrences whose rows need not agree about visibility — so the most careful
	// row in the set answers for the whole of it, as it does everywhere else
	// this question is asked.
	Undisclosed bool
	// Internal says at least one row of the decision is about internal
	// material, a lead, which is what decides who may agree to it: at
	// internal visibility a second person holds the approver capability.
	Internal bool
}

// Reach is what a decision covers now, counted the way the findings list counts.
//
// Not what it wrote. A decision reaches by matching, so a build appearing
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

// EndedPart is the rows of a decision that stopped applying one way, and what
// they reached when they stopped.
//
// Worked out from the rows and the findings' own opening and closing, so it
// needs nothing stored beside them. Matched by occurrence and not by version: a
// lapse is the version moving at an occurrence, so matched on the versions it was
// written against, a lapsed row reaches nothing at the moment it lapsed.
type EndedPart struct {
	// State is how they stopped.
	State State
	// At is the latest moment a row of this part stopped.
	At time.Time
	// Rows and Occurrences are what stopped: rows, and the distinct occurrences they
	// sat at.
	Rows, Occurrences int
	// Builds names every build holding an open finding at one of those occurrences
	// at the moment its row stopped, narrowed to what the reader may see.
	Builds []string
}

// Whole reads one decision for somebody who may read every row of it.
//
// Refused whole or answered whole, for the reason ReadDecision gives: shown half,
// a reader would be told about words whose other half is about a finding they
// may not see.
func (s *Store) Whole(ctx context.Context, subject access.Subject, decisionID int64) (*Whole, error) {
	decision := new(Decision)
	if err := s.db.NewSelect().Model(decision).Where(`"id" = ?`, decisionID).Scan(ctx); err != nil {
		return nil, database.FromRead(err, ErrNotTheirs, fmt.Sprintf("read decision %d", decisionID))
	}
	var rows []DecisionOccurrence
	if err := s.db.NewSelect().Model(&rows).Relation("Decision").
		Where(`"de"."decision_id" = ?`, decisionID).Order("de.id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what that decision covers: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrNotTheirs
	}
	// The case grant is asked beside the product-wide question, because a
	// collaborator reaches the decisions of the case they were brought into
	// and every list that offers them a decision links here. Offered and then
	// refused reads as a fault rather than as a rule.
	var refused []int64
	for _, row := range rows {
		if !readableOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			refused = append(refused, row.ID)
		}
	}
	if len(refused) > 0 {
		// A lead included in its flaw's case is read by the flaw's readers.
		included, err := s.readsIncluded(ctx, subject, refused)
		if err != nil {
			return nil, err
		}
		for _, id := range refused {
			if !included[id] {
				return nil, ErrNotTheirs
			}
		}
	}

	whole := &Whole{Decision: *decision, DecisionOccurrence: rows[0], Rows: len(rows)}
	issues := map[int64]bool{}
	occurrences := map[string]bool{}
	for _, row := range rows {
		issues[row.VulnerabilityID] = true
		occurrences[row.OccurrenceIdentity] = true
		if row.Visibility != access.Public {
			whole.Undisclosed = true
		}
		if row.Visibility == access.Internal {
			whole.Internal = true
		}
	}
	whole.Issues, whole.Occurrences = len(issues), len(occurrences)

	reasoning, err := s.currentReasoning(ctx, []DecisionOccurrence{rows[0]})
	if err != nil {
		return nil, err
	}
	whole.Reasoning = reasoning[rows[0].ID]

	var agreements []Approval
	if err := s.db.NewSelect().Model(&agreements).
		Where(`"decision_id" = ?`, decisionID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was agreed to: %w", err)
	}
	whole.Happened, whole.When, whole.By = became(rows,
		map[int64][]Approval{decisionID: agreements})

	before, err := s.everApproved(ctx, []int64{decisionID})
	if err != nil {
		return nil, err
	}
	// An approval on record and the decision not standing on one. Asked of a
	// decision that is currently approved, "was this ever approved" answers yes
	// about the agreement being read, which is not the question.
	whole.PreviouslyApproved = before[decisionID] && whole.Happened != AgreedTo

	builds, err := s.buildsCovered(ctx, subject, []int64{decisionID})
	if err != nil {
		return nil, err
	}
	whole.Builds = builds[decisionID]
	if whole.Builds == nil {
		whole.Builds = []string{}
	}

	if whole.Reach, err = s.reachOf(ctx, subject, decisionID); err != nil {
		return nil, err
	}
	if whole.Ended, err = s.endedParts(ctx, subject, decisionID, rows); err != nil {
		return nil, err
	}

	many, err := s.overMany(ctx, *decision)
	if err != nil {
		return nil, err
	}
	if many {
		outliers, err := s.outliersFor(ctx, subject, []Decision{*decision})
		if err != nil {
			return nil, err
		}
		whole.Outliers = outliers[decisionID]
	}
	return whole, nil
}

// reachOf counts what a decision covers now, in the units somebody acts in.
//
// The same match a finding makes when it asks whether a decision applies to
// it, so what is counted here is exactly what the decision suppresses.
// Narrowed to the findings the reader may see: a decision somebody may read can
// match findings they may not, and a count is the leak even where no row is
// shown.
func (s *Store) reachOf(ctx context.Context, subject access.Subject, decisionID int64) (Reach, error) {
	var counted struct {
		Folds     int `bun:"folds"`
		Packages  int `bun:"packages"`
		Consumers int `bun:"consumers"`
		Direct    int `bun:"direct"`
		Findings  int `bun:"findings"`
	}
	query := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		// The decision occurrence on the outside of the join, for the reason Describe
		// gives: SQLite otherwise starts from every open finding.
		Join(finding.DecisionIssue).
		Join(`CROSS JOIN "finding" AS "f"`).
		Where(finding.DecisionAtOccurrence("f")).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		ColumnExpr("COUNT(DISTINCT "+finding.FoldedOn+`) AS "folds"`).
		ColumnExpr(`COUNT(DISTINCT "f"."component_id") AS "packages"`).
		ColumnExpr(`COUNT(DISTINCT "f"."consumer_id") AS "consumers"`).
		// A component nothing pulls in has no consumer to count distinctly,
		// so the build itself is the one thing pulling it in.
		ColumnExpr(`COALESCE(SUM(CASE WHEN "f"."consumer_id" IS NULL THEN 1 ELSE 0 END), 0) AS "direct"`).
		ColumnExpr(`COUNT(*) AS "findings"`).
		Where(`"de"."decision_id" = ?`, decisionID).
		// Live rows only: a row withdrawn or lapsed covers nothing, however
		// well its versions still match.
		Where(`"de"."live_key" IS NOT NULL`).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Where(`"st"."product_id" = "de"."product_id"`).
		Where(finding.KeyMatches)
	if err := readableFindings(query, subject, "f", `"st"."product_id"`).
		Scan(ctx, &counted); err != nil {
		return Reach{}, fmt.Errorf("count what that decision covers: %w", err)
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

// endedParts reports what a decision's withdrawn and lapsed rows reached when
// each stopped.
//
// A finding counts where it was open at its own row's moment: opened at or
// before it and not closed by then. Each row is asked at its own moment,
// because the rows of one part can stop at different times.
func (s *Store) endedParts(ctx context.Context, subject access.Subject, decisionID int64,
	rows []DecisionOccurrence) ([]EndedPart, error) {

	parts := map[State]*EndedPart{}
	occurrences := map[State]map[string]bool{}
	for _, row := range rows {
		if row.State != Withdrawn && row.State != LapsedState {
			continue
		}
		part := parts[row.State]
		if part == nil {
			part = &EndedPart{State: row.State, Builds: []string{}}
			parts[row.State], occurrences[row.State] = part, map[string]bool{}
		}
		part.Rows++
		occurrences[row.State][row.OccurrenceIdentity] = true
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
		TableExpr(`"decision_occurrence" AS "de"`).
		// The decision occurrence on the outside of the join, for the reason Describe
		// gives: SQLite otherwise starts from every finding.
		Join(`CROSS JOIN "finding" AS "f"`).
		Where(finding.DecisionFiledAt("de", "f")).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		ColumnExpr(`"de"."state" AS "state"`).
		ColumnExpr(`MIN("st"."display_name") AS "stream"`).
		ColumnExpr(`MIN("va"."display_name") AS "variant"`).
		Where(`"de"."decision_id" = ?`, decisionID).
		Where(`"de"."state" IN (?, ?)`, Withdrawn, LapsedState).
		Where(`"de"."ended_at" IS NOT NULL`).
		Where(`"st"."product_id" = "de"."product_id"`).
		Where(`"f"."opened_at" <= "de"."ended_at"`).
		Where(`("f"."closed_at" IS NULL OR "f"."closed_at" > "de"."ended_at")`).
		Apply(ofKinds(kind.Decisions, "f"))
	if err := readableFindings(query, subject, "f", `"st"."product_id"`).
		GroupExpr(`"de"."state", "st"."name", "va"."name"`).
		OrderExpr(`"de"."state", "st"."name", "va"."name"`).
		Scan(ctx, &reached); err != nil {
		return nil, fmt.Errorf("read what that decision reached when it stopped: %w", err)
	}
	for _, one := range reached {
		if part := parts[one.State]; part != nil {
			part.Builds = append(part.Builds, one.Stream+" · "+one.Variant)
		}
	}

	out := make([]EndedPart, 0, len(parts))
	for _, state := range []State{Withdrawn, LapsedState} {
		if part := parts[state]; part != nil {
			part.Occurrences = len(occurrences[state])
			out = append(out, *part)
		}
	}
	return out, nil
}
