// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// RuleState is where a standing rule stands, worked out when it is read.
type RuleState string

const (
	// RuleProposed is a rule nobody has approved. It covers nothing.
	RuleProposed RuleState = "proposed"
	// RuleInForce is an approved rule covering no more than its approver
	// was shown, by the factor the deployment allows.
	RuleInForce RuleState = "in-force"
	// RuleOutgrown is an approved rule naming an analyzer rule and covering
	// more than that. It still covers what it names, and asks to be
	// approved again.
	RuleOutgrown RuleState = "outgrown"
	// RuleRetired is a rule taken out of use. It covers nothing.
	RuleRetired RuleState = "retired"
)

// RuleStates are every state a standing rule is in, in the order a rule
// meets them.
func RuleStates() []RuleState {
	return []RuleState{RuleProposed, RuleInForce, RuleOutgrown, RuleRetired}
}

// ErrNoSuchRule is a standing rule this product does not hold, or one
// retired already.
var ErrNoSuchRule = refusal.New("no standing rule of this product is in use under that identifier")

// ErrRuleNamesNothing refuses a standing rule naming neither an analyzer rule
// nor a path, which would dismiss every lead the product has.
var ErrRuleNamesNothing = refusal.New("a standing rule names an analyzer rule, a path, or both")

// ErrOwnRule refuses somebody approving a standing rule they proposed.
var ErrOwnRule = refusal.New("a standing rule is approved by somebody other than the person who proposed it")

// ErrRuleInForce refuses approving a rule already approved and not outgrown.
var ErrRuleInForce = refusal.New("that standing rule is approved, and covers no more than it did then")

// leadRule is a standing rule dismissing the leads it names.
type leadRule struct {
	bun.BaseModel `bun:"table:lead_rule,alias:lr"`

	ID               int64      `bun:"id,pk,autoincrement"`
	ProductID        int64      `bun:"product_id,notnull"`
	Rule             *string    `bun:"rule"`
	RuleFolded       *string    `bun:"rule_folded"`
	Prefix           *string    `bun:"prefix"`
	Under            *string    `bun:"under"`
	UnderLength      *int       `bun:"under_length"`
	Reason           string     `bun:"reason,notnull"`
	Reasoning        string     `bun:"reasoning,notnull"`
	ProposedBy       int64      `bun:"proposed_by,notnull"`
	ProposedAt       time.Time  `bun:"proposed_at,notnull"`
	ApprovedBy       *int64     `bun:"approved_by"`
	ApprovedAt       *time.Time `bun:"approved_at"`
	ApprovedCovering *int       `bun:"approved_covering"`
	RetiredBy        *int64     `bun:"retired_by"`
	RetiredAt        *time.Time `bun:"retired_at"`
}

// covers is whether the standing rule under "lr" names the finding under "f",
// whose result is under "ar": the analyzer rule it is filed under, and a path
// at or under the rule's prefix. A part the rule leaves out names every lead.
const covers = `("lr"."rule_folded" IS NULL OR EXISTS (SELECT 1 FROM "vulnerability" AS "rv"
		WHERE "rv"."id" = "f"."vulnerability_id" AND "rv"."identifier_folded" = "lr"."rule_folded"))
	AND ("lr"."prefix" IS NULL OR "lr"."prefix" = "ar"."path"
		OR SUBSTR("ar"."path", 1, "lr"."under_length") = "lr"."under")`

// ruled is whether an approved standing rule in use in the product bound
// covers the finding under "f", whose result is under "ar".
var ruled = `EXISTS (SELECT 1 FROM "lead_rule" AS "lr"
	WHERE "lr"."product_id" = ? AND "lr"."approved_at" IS NOT NULL AND "lr"."retired_at" IS NULL
	  AND ` + covers + `)`

// StandingRule is a standing rule as it is read: what it names, who proposed
// and approved it, and how many leads it covers now.
type StandingRule struct {
	ID         int64
	Rule       string
	Prefix     string
	Reason     triage.LeadReason
	Reasoning  string
	ProposedBy int64
	ProposedAt time.Time
	ApprovedBy *int64
	ApprovedAt *time.Time
	// ApprovedCovering is the leads it covered when it was approved.
	ApprovedCovering *int
	RetiredAt        *time.Time
	// Covering is the open leads it names now that the reader may read,
	// whether or not it is approved.
	Covering int
	State    RuleState
}

// Proposal is a standing rule somebody puts forward.
type Proposal struct {
	Rule      string
	Prefix    string
	Reason    triage.LeadReason
	Reasoning string
}

// ProposeRule records a standing rule in a product. It covers nothing until
// somebody else approves it. The subject has to triage internal findings in
// the product.
func ProposeRule(ctx context.Context, db bun.IDB, subject access.Subject, productID int64,
	in Proposal, now time.Time) (*StandingRule, error) {

	if !subject.Triages(access.Internal, productID) {
		return nil, access.Denied(fmt.Sprintf("propose a standing rule in product %d", productID))
	}
	row := leadRule{ProductID: productID, Reason: string(in.Reason),
		Reasoning: strings.TrimSpace(in.Reasoning), ProposedBy: subject.ID,
		ProposedAt: now.UTC().Truncate(time.Microsecond)}
	if row.Reasoning == "" {
		return nil, refusal.New("a standing rule says why, in its reasoning")
	}
	if err := markdown.Check(row.Reasoning); err != nil {
		return nil, err
	}
	if rule := strings.TrimSpace(in.Rule); rule != "" {
		if utf8.RuneCountInString(rule) > database.NameWidth {
			return nil, refusal.Errorf("an analyzer rule is at most %d characters", database.NameWidth)
		}
		folded := finding.FoldIdentifier(rule)
		row.Rule, row.RuleFolded = &rule, &folded
	}
	if in.Prefix != "" {
		clean, ok := sourcelink.CleanPath(in.Prefix)
		switch {
		case !ok:
			return nil, refusal.Errorf("path %q climbs out of the checkout or holds an empty segment", in.Prefix)
		case clean != "":
			under, length := clean+"/", utf8.RuneCountInString(clean)+1
			row.Prefix, row.Under, row.UnderLength = &clean, &under, &length
		}
	}
	if row.Rule == nil && row.Prefix == nil {
		return nil, ErrRuleNamesNothing
	}
	var out *StandingRule
	err := database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		if err := wholeRuleDismissable(ctx, tx, row); err != nil {
			return err
		}
		if _, err := tx.NewInsert().Model(&row).Exec(ctx); err != nil {
			return fmt.Errorf("record the standing rule: %w", err)
		}
		counted, err := coverage(ctx, tx, subject, productID, []int64{row.ID})
		if err != nil {
			return err
		}
		out = ruleOf(row, counted[row.ID], 0)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ApproveRule approves a standing rule, recording how many leads it covers as
// what the approver was shown. A rule in force is refused; an outgrown one is
// approved again at its new size. The subject has to hold the approver right
// and read internal findings in the product, and cannot be the rule's author.
func ApproveRule(ctx context.Context, db bun.IDB, subject access.Subject, productID, ruleID int64,
	now time.Time) (*StandingRule, error) {

	if !subject.Holds(access.Approver, productID) || !subject.Reads(access.Internal, productID) {
		return nil, access.Denied(fmt.Sprintf("approve a standing rule in product %d", productID))
	}
	var out *StandingRule
	err := database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		row, err := ruleIn(ctx, tx, productID, ruleID)
		if err != nil {
			return err
		}
		if row.ProposedBy == subject.ID {
			return ErrOwnRule
		}
		if err := wholeRuleDismissable(ctx, tx, *row); err != nil {
			return err
		}
		factor, err := growth(ctx, tx)
		if err != nil {
			return err
		}
		counted, err := coverage(ctx, tx, subject, productID, []int64{row.ID})
		if err != nil {
			return err
		}
		covering := counted[row.ID]
		if ruleState(*row, covering, factor) == RuleInForce {
			return ErrRuleInForce
		}
		at := now.UTC().Truncate(time.Microsecond)
		row.ApprovedBy, row.ApprovedAt, row.ApprovedCovering = &subject.ID, &at, &covering
		if _, err := tx.NewUpdate().Model(row).
			Column("approved_by", "approved_at", "approved_covering").
			WherePK().Exec(ctx); err != nil {
			return fmt.Errorf("approve the standing rule: %w", err)
		}
		out = ruleOf(*row, covering, factor)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RetireRule takes a standing rule out of use. The leads it covered are open
// again where nothing else answers them. The subject has to triage internal
// findings in the product.
func RetireRule(ctx context.Context, db bun.IDB, subject access.Subject, productID, ruleID int64,
	now time.Time) (*StandingRule, error) {

	if !subject.Triages(access.Internal, productID) {
		return nil, access.Denied(fmt.Sprintf("retire a standing rule in product %d", productID))
	}
	var out *StandingRule
	err := database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		row, err := ruleIn(ctx, tx, productID, ruleID)
		if err != nil {
			return err
		}
		at := now.UTC().Truncate(time.Microsecond)
		row.RetiredBy, row.RetiredAt = &subject.ID, &at
		if _, err := tx.NewUpdate().Model(row).Column("retired_by", "retired_at").
			WherePK().Exec(ctx); err != nil {
			return fmt.Errorf("retire the standing rule: %w", err)
		}
		out = ruleOf(*row, 0, 0)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// StandingRules is the standing rules of a product, retired ones included,
// in the order they were proposed, each with the leads it covers that the
// subject may read. The subject has to read internal findings in the
// product.
func StandingRules(ctx context.Context, db bun.IDB, subject access.Subject, productID int64) ([]StandingRule, error) {
	if !subject.Reads(access.Internal, productID) {
		return nil, access.Denied(fmt.Sprintf("read the standing rules of product %d", productID))
	}
	var rows []leadRule
	if err := db.NewSelect().Model(&rows).
		Where(`"lr"."product_id" = ?`, productID).
		OrderExpr(`"lr"."id" ASC`).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the standing rules of product %d: %w", productID, err)
	}
	if len(rows) == 0 {
		return []StandingRule{}, nil
	}
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	counted, err := coverage(ctx, db, subject, productID, ids)
	if err != nil {
		return nil, err
	}
	factor, err := growth(ctx, db)
	if err != nil {
		return nil, err
	}
	out := make([]StandingRule, 0, len(rows))
	for _, r := range rows {
		out = append(out, *ruleOf(r, counted[r.ID], factor))
	}
	return out, nil
}

// wholeRuleDismissable refuses a standing rule naming an analyzer rule and no
// path where the rule finds memory safety or injection, or where nothing has
// recorded the rule, so its weaknesses are not known. A flaw of those kinds
// is judged one lead at a time; a path narrows the rule to code somebody can
// vouch for.
func wholeRuleDismissable(ctx context.Context, tx bun.IDB, row leadRule) error {
	if row.RuleFolded == nil || row.Prefix != nil {
		return nil
	}
	var held []int
	if err := tx.NewSelect().TableExpr(`"vulnerability" AS "vu"`).
		Join(`LEFT JOIN "rule_rating" AS "rr" ON "rr"."vulnerability_id" = "vu"."id"`).
		ColumnExpr(`COALESCE("rr"."weakness_tier", 0)`).
		Where(`"vu"."identifier_folded" = ?`, *row.RuleFolded).
		Where(`"vu"."kind" = ?`, kind.Rule).
		Scan(ctx, &held); err != nil {
		return fmt.Errorf("read what the rule %q finds: %w", *row.Rule, err)
	}
	switch {
	case len(held) == 0:
		return refusal.Errorf("no analyzer has reported %q here, so what it finds is not known: name a path with it", *row.Rule)
	case weakness.Tier(slices.Max(held)) >= weakness.TierInjection:
		return refusal.Errorf("%q finds memory safety or injection flaws, which are judged one lead at a time: name a path with it", *row.Rule)
	}
	return nil
}

// ruleIn is a standing rule of the product in use, for an update.
func ruleIn(ctx context.Context, tx bun.IDB, productID, ruleID int64) (*leadRule, error) {
	var row leadRule
	err := tx.NewSelect().Model(&row).
		Where(`"lr"."id" = ?`, ruleID).
		Where(`"lr"."product_id" = ?`, productID).
		Where(`"lr"."retired_at" IS NULL`).
		Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNoSuchRule
	case err != nil:
		return nil, fmt.Errorf("read standing rule %d: %w", ruleID, err)
	}
	return &row, nil
}

// coverage is the open leads each of the rules names in the product that the
// subject may read, counted by place, whether or not the rule is approved.
func coverage(ctx context.Context, db bun.IDB, subject access.Subject, productID int64,
	ids []int64) (map[int64]int, error) {

	visible, err := access.Readable(subject, productID)
	if err != nil {
		return nil, err
	}
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	var counted []struct {
		ID    int64 `bun:"id"`
		Leads int   `bun:"leads"`
	}
	if err := db.NewSelect().TableExpr(`"lead_rule" AS "lr"`).
		Join(`JOIN "stream" AS "s" ON "s"."product_id" = "lr"."product_id"`).
		Join(`JOIN "target" AS "t" ON "t"."stream_id" = "s"."id"`).
		Join(`JOIN "finding" AS "f" ON "f"."target_id" = "t"."id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		ColumnExpr(`"lr"."id", COUNT(DISTINCT "f"."place_identity") AS "leads"`).
		Where(`"lr"."product_id" = ?`, productID).
		Where(`"lr"."id" IN (?)`, bun.List(ids)).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(kinds, kindArgs...).
		Where(covers).
		GroupExpr(`"lr"."id"`).
		Scan(ctx, &counted); err != nil {
		return nil, fmt.Errorf("count the leads the standing rules of product %d cover: %w", productID, err)
	}
	out := make(map[int64]int, len(counted))
	for _, c := range counted {
		out[c.ID] = c.Leads
	}
	return out, nil
}

// growth is how many times what its approver was shown an approved rule may
// cover before it is outgrown.
func growth(ctx context.Context, db bun.IDB) (int, error) {
	n, err := setting.NewStore(db).Count(ctx, setting.LeadRuleGrowth, setting.DefaultLeadRuleGrowth)
	if err != nil {
		return 0, fmt.Errorf("read how far a standing rule may grow: %w", err)
	}
	return n, nil
}

// ruleState is where a rule stands covering this many leads. A rule naming a
// path alone is never outgrown: code under a dismissed path grows as a
// matter of course, and what the approver agreed to is the path. An approval
// shown none is measured as though shown one, so that a rule approved over a
// rule with no leads yet is not outgrown by its first.
func ruleState(r leadRule, covering, factor int) RuleState {
	switch {
	case r.RetiredAt != nil:
		return RuleRetired
	case r.ApprovedAt == nil:
		return RuleProposed
	case r.Rule != nil && covering > max(*r.ApprovedCovering, 1)*factor:
		return RuleOutgrown
	}
	return RuleInForce
}

func ruleOf(r leadRule, covering, factor int) *StandingRule {
	out := &StandingRule{
		ID: r.ID, Reason: triage.LeadReason(r.Reason), Reasoning: r.Reasoning,
		ProposedBy: r.ProposedBy, ProposedAt: r.ProposedAt,
		ApprovedBy: r.ApprovedBy, ApprovedAt: r.ApprovedAt, ApprovedCovering: r.ApprovedCovering,
		RetiredAt: r.RetiredAt, Covering: covering, State: ruleState(r, covering, factor),
	}
	if r.Rule != nil {
		out.Rule = *r.Rule
	}
	if r.Prefix != nil {
		out.Prefix = *r.Prefix
	}
	return out
}
