// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Rule is an analyzer's rule as an issue: the name it is filed under, what
// the analyzer says it checks, the weaknesses its tags name, and where the
// analyzer documents it.
type Rule struct {
	Name        string
	Description string
	Tags        []string
	// Documentation is the address of the analyzer's page for the rule,
	// already checked against the hosts analyzers document rules on.
	Documentation string `json:",omitempty"`
	// SeverityTenths and Precision are the tool's own rating of the rule's
	// results, as RuleRating reads them. Unrated, the rating already recorded
	// stands.
	SeverityTenths *int   `json:",omitempty"`
	Precision      string `json:",omitempty"`
}

// Precisions are the words an analyzer rates a rule's precision in, most
// precise first.
func Precisions() []string { return []string{"very-high", "high", "medium", "low"} }

// RuleRating is a tool's security severity, a number from 0 to 10, in tenths,
// and its precision as one of Precisions. Either is nil or empty where the
// tool gave nothing this reads.
func RuleRating(severity, precision string) (*int, string) {
	var tenths *int
	if f, err := strconv.ParseFloat(strings.TrimSpace(severity), 64); err == nil && f >= 0 && f <= 10 {
		n := int(math.Round(f * 10))
		tenths = &n
	}
	precision = strings.ToLower(strings.TrimSpace(precision))
	if !slices.Contains(Precisions(), precision) {
		precision = ""
	}
	return tenths, precision
}

// ruleRating is a tool's rating of a rule's results.
type ruleRating struct {
	bun.BaseModel `bun:"table:rule_rating,alias:rr"`

	ID              int64   `bun:"id,pk,autoincrement"`
	VulnerabilityID int64   `bun:"vulnerability_id,notnull"`
	SeverityTenths  *int    `bun:"severity_tenths"`
	Precision       *string `bun:"precision"`
}

// cweTag is a rule tag naming a weakness, in the convention CodeQL writes and
// the upload client writes for cppcheck.
var cweTag = regexp.MustCompile(`(?i)^external/cwe/cwe-(\d+)$`)

// weaknessesOf is the weaknesses a rule's tags name.
func weaknessesOf(tags []string) []string {
	var out []string
	for _, tag := range tags {
		if m := cweTag.FindStringSubmatch(strings.TrimSpace(tag)); m != nil {
			out = append(out, "CWE-"+m[1])
		}
	}
	return out
}

// Rule is the issue an analyzer's rule is filed as, recorded where it is not
// yet. A rule is resolved among rules alone: no name a scan or a person
// reports reaches one, and a rule never reaches a vulnerability.
//
// A name some other kind of issue already holds is refused. Names are unique
// across every kind, and no published identifier holds the slash a rule's
// name carries, so only a scanner reporting such a name collides.
func (v *Vulnerabilities) Rule(ctx context.Context, rule Rule) (int64, error) {
	folded := FoldIdentifier(rule.Name)
	var held []Vulnerability
	if err := v.db.NewSelect().Model(&held).
		Where(`"vu"."identifier_folded" = ?`, folded).
		Scan(ctx); err != nil {
		return 0, fmt.Errorf("look up the rule %q: %w", rule.Name, err)
	}
	var id int64
	for _, row := range held {
		if row.Kind != kind.Rule {
			return 0, refusal.Errorf("the rule %q has a name an issue of another kind already holds", rule.Name)
		}
		id = row.IssueID
	}
	if id == 0 {
		row := &Vulnerability{
			Identifier: strings.TrimSpace(rule.Name), IdentifierFolded: folded, Kind: kind.Rule,
			Description: rule.Description, FirstSeenAt: v.now().Truncate(time.Microsecond),
		}
		if _, err := v.db.NewInsert().Model(row).Value("issue_id", "?", 0).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				return 0, fmt.Errorf("record the rule %q: %w", rule.Name, database.ErrGoAgain)
			}
			return 0, fmt.Errorf("record the rule %q: %w", rule.Name, err)
		}
		id = row.ID
		if _, err := v.db.NewUpdate().Model((*Vulnerability)(nil)).
			Set(`"issue_id" = ?`, id).
			Where(`"id" = ?`, id).Exec(ctx); err != nil {
			return 0, fmt.Errorf("record the rule %q: %w", rule.Name, err)
		}
	} else if rule.Description != "" {
		// A description arriving later fills one that was empty and replaces
		// nothing.
		if _, err := v.db.NewUpdate().Model((*Vulnerability)(nil)).
			Set(`"description" = ?`, rule.Description).
			Where(`"id" = ?`, id).
			Where(`("description" IS NULL OR "description" = '')`).Exec(ctx); err != nil {
			return 0, fmt.Errorf("describe the rule %q: %w", rule.Name, err)
		}
	}
	if err := v.classify(ctx, id, weaknessesOf(rule.Tags), ""); err != nil {
		return 0, fmt.Errorf("record what kind of flaw the rule %q finds: %w", rule.Name, err)
	}
	if err := v.reference(ctx, id, []Reference{{URL: rule.Documentation, Kind: Documentation}}); err != nil {
		return 0, fmt.Errorf("record where the rule %q is documented: %w", rule.Name, err)
	}
	if err := v.rateRule(ctx, id, rule); err != nil {
		return 0, fmt.Errorf("record how the tool rates the rule %q: %w", rule.Name, err)
	}
	return id, nil
}

// rateRule records the rating a rule arrived with in place of the one held. A
// rule arriving unrated leaves the one held: a run of the tool that omits it
// says nothing about the rule.
func (v *Vulnerabilities) rateRule(ctx context.Context, id int64, rule Rule) error {
	if rule.SeverityTenths == nil && rule.Precision == "" {
		return nil
	}
	row := ruleRating{VulnerabilityID: id, SeverityTenths: rule.SeverityTenths}
	if rule.Precision != "" {
		row.Precision = &rule.Precision
	}
	if _, err := v.db.NewDelete().Model((*ruleRating)(nil)).
		Where(`"vulnerability_id" = ?`, id).Exec(ctx); err != nil {
		return err
	}
	if _, err := v.db.NewInsert().Model(&row).Exec(ctx); err != nil {
		if database.IsDuplicate(err) {
			return database.ErrGoAgain
		}
		return err
	}
	return nil
}
