// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

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
	return id, nil
}
