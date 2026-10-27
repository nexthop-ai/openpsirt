// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/filed"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// The case against agreeing.
//
// An approver is shown the decision and the reasoning and nothing that argues
// against them, which is the rubber stamp the queue's whole shape was
// written against — so this is a weakness in a control rather than a card
// layout. The material already exists: the finding's own detail carries the
// decisions made elsewhere and what else sits at the occurrence. What was missing
// is putting it where the decision is made rather than a page away from it.
//
// Two counts and no argument. It does not say a decision is wrong — nothing
// here can know that — it says what a careful reader would go and look up, so
// that not looking is a choice rather than an omission.

// Counter is what argues against a decision, in numbers.
type Counter struct {
	// Elsewhere is what has already been agreed about this same issue at other
	// occurrences, by outcome. A dismissal here where six occurrences called it affected
	// is the case worth a second look.
	Elsewhere map[string]int
	// Undecided is how many other issues sit undecided at the same occurrence. A
	// decision in a run of forty is a different thing from a decision on its own:
	// it is usually right and it is also how a run gets waved through.
	Undecided int
}

// Said reports whether there is anything to say at all.
func (c Counter) Said() bool { return len(c.Elsewhere) > 0 || c.Undecided > 0 }

// counters reads both, for a whole page of decisions at once.
//
// One statement each rather than one per card: a page of fifty decisions read a
// row at a time is a hundred round trips before the queue draws, which is the
// shape that makes a card carry less than it should.
func (s *Store) counters(ctx context.Context, subject access.Subject,
	representatives []DecisionOccurrence) (map[int64]Counter, error) {

	out := map[int64]Counter{}
	if len(representatives) == 0 {
		return out, nil
	}
	issues := make([]int64, 0, len(representatives))
	occurrences := make([]string, 0, len(representatives))
	products := make([]int64, 0, len(representatives))
	for _, row := range representatives {
		issues = append(issues, row.VulnerabilityID)
		occurrences = append(occurrences, row.OccurrenceIdentity)
		products = append(products, row.ProductID)
	}

	// agreed is what has been agreed about the same issue somewhere else.
	// Approved only: a proposal is one person's opinion, and counting
	// proposals here would let two people in a queue agree with each other
	// by being counted at each other.
	//
	// The decision's own occurrence is not excluded, and that is deliberate. An
	// occurrence identity is a pair of names with no product in it, so
	// excluding by occurrence alone would drop a decision in *another* product
	// that happens to ship the same pair — which is exactly the
	// counter-evidence worth having. Nothing of the decision's own can be
	// counted here anyway: it is in the queue, so it is proposed, and one
	// live decision per occurrence means the occurrence it sits at holds no approved
	// one.
	var agreed []struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Outcome         string `bun:"outcome"`
		Occurrences     int    `bun:"places"`
	}
	// Counted by the issue each row is read as, so what was agreed under
	// a name that merged into this issue counts as agreed about it.
	issueOf, err := finding.IssuesOf(ctx, s.db, issues)
	if err != nil {
		return nil, err
	}
	elsewhere := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		Join(finding.DecisionOccurrenceIssue).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		ColumnExpr(`"dv"."issue_id" AS "vulnerability_id"`).
		ColumnExpr(`"cl"."outcome" AS "outcome"`).
		ColumnExpr(`COUNT(DISTINCT "de"."occurrence_identity") AS "places"`).
		Where(finding.FiledUnderAny(filed.DecisionOccurrenceIssue), bun.List(issues)).
		Where(`"de"."state" = ?`, Approved).
		Where(`"de"."live_key" IS NOT NULL`).
		GroupExpr(`"dv"."issue_id", "cl"."outcome"`)
	if err := readableBy(elsewhere, subject, "de").Scan(ctx, &agreed); err != nil {
		return nil, fmt.Errorf("read what was decided about this elsewhere: %w", err)
	}
	byIssue := map[int64]map[string]int{}
	for _, row := range agreed {
		if byIssue[row.VulnerabilityID] == nil {
			byIssue[row.VulnerabilityID] = map[string]int{}
		}
		byIssue[row.VulnerabilityID][row.Outcome] += row.Occurrences
	}

	// open is how much else at the same occurrence nobody has answered, by the
	// same test every screen uses for "undecided": no live decision covering
	// it at the versions the code holds now.
	var open []struct {
		ProductID  int64  `bun:"product_id"`
		Occurrence string `bun:"occurrence_identity"`
		Issues     int    `bun:"issues"`
	}
	undecided := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."occurrence_identity" AS "occurrence_identity"`).
		ColumnExpr(`COUNT(DISTINCT "f"."vulnerability_id") AS "issues"`).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Where(`"f"."occurrence_identity" IN (?)`, bun.List(occurrences)).
		Where(`"st"."product_id" IN (?)`, bun.List(products)).
		// The issue before the decision occurrence, and CROSS JOIN ... WHERE is what fixes
		// that order on SQLite: the row is then reached through its index
		// on product, issue and occurrence. Joined the other way, SQLite reads every
		// row in the product once per finding at the occurrence — 1.0 s for a
		// kernel occurrence carrying 6,000 issues in a product holding 3,060
		// rows, against 0.016 s this way.
		Where(`NOT EXISTS (SELECT 1 FROM "vulnerability" AS "dv"
			CROSS JOIN "decision_occurrence" AS "de"
			JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"
			WHERE "de"."vulnerability_id" = "dv"."id"
			  AND ` + finding.DecisionOccurrenceAt(`"st"."product_id"`) + `
			  AND "de"."live_key" IS NOT NULL
			  AND ` + finding.KeyMatches + `)`).
		GroupExpr(`"st"."product_id", "f"."occurrence_identity"`)
	if err := readableFindings(undecided, subject, "f", `"st"."product_id"`).
		Scan(ctx, &open); err != nil {
		return nil, fmt.Errorf("read what else is undecided there: %w", err)
	}
	byOccurrence := map[string]int{}
	for _, row := range open {
		byOccurrence[fmt.Sprintf("%d %s", row.ProductID, row.Occurrence)] = row.Issues
	}

	for _, row := range representatives {
		out[row.ID] = Counter{
			Elsewhere: byIssue[issueOf[row.VulnerabilityID]],
			Undecided: byOccurrence[fmt.Sprintf("%d %s", row.ProductID, row.OccurrenceIdentity)],
		}
	}
	return out, nil
}
