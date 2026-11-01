// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// decidedSets is what a VEX read of one build knows about the open findings of
// the issues a decision exists for in the product: each finding with the
// decision occurrences covering it, the components and consumers they sit in,
// and the issues' identifiers.
//
// Read as sets, each statement reading one table by constants or joining
// another by its primary key, and matched here. Asked of each finding inside
// one statement, an engine on the statistics a bulk load leaves picks a plan
// that reads the build's graph or the product's decisions once per finding:
// past 30 s a read on MySQL and MariaDB, and 23.7 s on SQLite for a long-lived
// product.
type decidedSets struct {
	findings    []decidedFinding
	components  map[int64]decidedComponent
	identifiers map[int64]string
}

// decidedFinding is an open finding of the build, and what the decision
// occurrences whose keys match it say.
type decidedFinding struct {
	ID              int64  `bun:"id"`
	VulnerabilityID int64  `bun:"vulnerability_id"`
	ComponentID     int64  `bun:"component_id"`
	ConsumerID      int64  `bun:"consumer_id"`
	Occurrence      string `bun:"occurrence_identity"`
	decisionTally
}

// decidedComponent is a component or consumer of a decided finding: its name,
// the package identifier the build stated for it or its own, and the version a
// decision is keyed on.
type decidedComponent struct {
	ID      int64  `bun:"id"`
	Name    string `bun:"name"`
	Purl    string `bun:"purl"`
	Version string `bun:"version"`
}

// decidedOccurrence is a decision occurrence of the product at an issue the
// build holds, with the versions it was keyed on.
type decidedOccurrence struct {
	ID              int64  `bun:"id"`
	VulnerabilityID int64  `bun:"vulnerability_id"`
	Occurrence      string `bun:"occurrence_identity"`
	Component       string `bun:"component_version"`
	Consumer        string `bun:"consumer_version"`
	AnyVersion      int    `bun:"any_version"`
	// Outcome is the decision's outcome where the read counts it, and null
	// where the decision matches the occurrence without answering it.
	Outcome sql.NullString `bun:"outcome"`
}

// decisionTally is what the decision occurrences matching a group of findings
// add up to, as WhollyCovered counts them in a statement: each finding counts once
// with no match and once per match otherwise, a match counts as decided where
// the read counts its outcome, and the earliest match is the least of all of
// them, counted or not.
type decisionTally struct {
	joined   int
	decided  int
	least    string
	greatest string
	first    int64
}

// add folds another tally into this one.
func (t *decisionTally) add(o decisionTally) {
	if o.decided > 0 {
		if t.decided == 0 || o.least < t.least {
			t.least = o.least
		}
		if t.decided == 0 || o.greatest > t.greatest {
			t.greatest = o.greatest
		}
	}
	if o.first != 0 && (t.first == 0 || o.first < t.first) {
		t.first = o.first
	}
	t.joined += o.joined
	t.decided += o.decided
}

// agreed is whether every match counts and all say the same outcome.
func (t decisionTally) agreed() bool {
	return t.decided == t.joined && t.least == t.greatest
}

// decidedRead is which decision occurrences a read counts: the state they
// stand in, and the outcomes, as conditions over `de` and `cl`.
type decidedRead struct {
	state     string
	stateArgs []any
	outcomes  string
}

// The two sides of VersionsMatch: the version a decision occurrence `de` was
// keyed on and the one a component `c` holds now, read as columns and compared
// here.
var (
	keyedComponent, heldComponent = matchSides(componentMatches)
	keyedConsumer, _              = matchSides(consumerMatches)
)

// matchSides splits one half of VersionsMatch at its equality.
func matchSides(match string) (string, string) {
	keyed, held, ok := strings.Cut(match, " = ")
	if !ok || strings.Contains(held, " = ") {
		panic("finding: " + match + " is no longer one equality")
	}
	return keyed, held
}

// readDecided reads the open findings of one build of the issues given, at
// the visibilities given, with the decision occurrences of the product the
// read counts, matched to each as KeyMatches matches them.
func readDecided(ctx context.Context, db bun.IDB, productID, buildID int64, visible []access.Visibility,
	issues []int64, read decidedRead) (*decidedSets, error) {

	sets := &decidedSets{}
	kinds, kindArgs := kind.VEX.Where(`"f"."kind"`)
	byIssue, issueArgs := database.InAnyOf(`"f"."vulnerability_id"`, issues)
	if err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."id", "f"."vulnerability_id", "f"."component_id"`).
		ColumnExpr(`COALESCE("f"."consumer_id", 0) AS "consumer_id"`).
		ColumnExpr(`"f"."occurrence_identity"`).
		Where(`"f"."build_id" = ?`, buildID).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(kinds, kindArgs...).
		Where(byIssue, issueArgs...).
		Scan(ctx, &sets.findings); err != nil {
		return nil, fmt.Errorf("read the open findings of the issues decided: %w", err)
	}
	if len(sets.findings) == 0 {
		return sets, nil
	}

	// The issues each decision occurrence is filed under, read as the issue it
	// joined where it merged.
	var filed []struct {
		ID      int64 `bun:"id"`
		IssueID int64 `bun:"issue_id"`
	}
	byIssue, issueArgs = database.InAnyOf(`"dv"."issue_id"`, issues)
	if err := db.NewSelect().
		TableExpr(`"vulnerability" AS "dv"`).
		ColumnExpr(`"dv"."id", "dv"."issue_id"`).
		Where(byIssue, issueArgs...).
		Scan(ctx, &filed); err != nil {
		return nil, fmt.Errorf("read what the issues decided are filed under: %w", err)
	}
	issueOf := make(map[int64]int64, len(filed))
	names := make([]int64, 0, len(filed))
	for _, row := range filed {
		issueOf[row.ID] = row.IssueID
		names = append(names, row.ID)
	}

	var decisions []decidedOccurrence
	byName, nameArgs := database.InAnyOf(`"de"."vulnerability_id"`, names)
	if err := db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		ColumnExpr(`"de"."id", "de"."vulnerability_id", "de"."occurrence_identity"`).
		ColumnExpr(keyedComponent+` AS "component_version"`).
		ColumnExpr(keyedConsumer+` AS "consumer_version"`).
		ColumnExpr(`CASE WHEN "cl"."outcome" IN (`+anyVersionList+`) THEN 1 ELSE 0 END AS "any_version"`).
		ColumnExpr(`CASE WHEN `+read.outcomes+` THEN "cl"."outcome" END AS "outcome"`).
		Where(`"de"."product_id" = ?`, productID).
		Where(read.state, read.stateArgs...).
		Where(`"de"."live_key" IS NOT NULL`).
		Where(`"de"."visibility" IN (?)`, bun.List(visible)).
		Where(byName, nameArgs...).
		Scan(ctx, &decisions); err != nil {
		return nil, fmt.Errorf("read the decisions of the issues decided: %w", err)
	}

	held := make([]int64, 0, 2*len(sets.findings))
	for _, f := range sets.findings {
		held = append(held, f.ComponentID)
		if f.ConsumerID != 0 {
			held = append(held, f.ConsumerID)
		}
	}
	held = distinctIDs(held)
	var components []decidedComponent
	byComponent, componentArgs := database.InAnyOf(`"c"."id"`, held)
	if err := db.NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`"c"."id", "c"."name", COALESCE("c"."purl", '') AS "purl"`).
		ColumnExpr(heldComponent+` AS "version"`).
		Where(byComponent, componentArgs...).
		Scan(ctx, &components); err != nil {
		return nil, fmt.Errorf("read the components the issues decided are in: %w", err)
	}
	stated, err := StatedPurls(ctx, db, buildID, held)
	if err != nil {
		return nil, err
	}
	sets.components = make(map[int64]decidedComponent, len(components))
	for _, c := range components {
		if purl := stated[c.ID]; purl.Valid {
			c.Purl = purl.String
		}
		sets.components[c.ID] = c
	}

	var identified []struct {
		ID         int64  `bun:"id"`
		Identifier string `bun:"identifier"`
	}
	byID, idArgs := database.InAnyOf(`"v"."id"`, issues)
	if err := db.NewSelect().
		TableExpr(`"vulnerability" AS "v"`).
		ColumnExpr(`"v"."id", "v"."identifier"`).
		Where(byID, idArgs...).
		Scan(ctx, &identified); err != nil {
		return nil, fmt.Errorf("read the identifiers of the issues decided: %w", err)
	}
	sets.identifiers = make(map[int64]string, len(identified))
	for _, row := range identified {
		sets.identifiers[row.ID] = row.Identifier
	}

	type at struct {
		issue      int64
		occurrence string
	}
	byOccurrence := map[at][]decidedOccurrence{}
	for _, d := range decisions {
		key := at{issueOf[d.VulnerabilityID], d.Occurrence}
		byOccurrence[key] = append(byOccurrence[key], d)
	}
	for i := range sets.findings {
		f := &sets.findings[i]
		component := sets.components[f.ComponentID].Version
		consumer := ""
		if f.ConsumerID != 0 {
			consumer = sets.components[f.ConsumerID].Version
		}
		matched := 0
		for _, d := range byOccurrence[at{f.VulnerabilityID, f.Occurrence}] {
			if d.AnyVersion == 0 && (d.Component != component || d.Consumer != consumer) {
				continue
			}
			matched++
			f.add(decisionTally{first: d.ID})
			if d.Outcome.Valid {
				f.add(decisionTally{decided: 1, least: d.Outcome.String, greatest: d.Outcome.String})
			}
		}
		f.joined = max(1, matched)
	}
	return sets, nil
}

// groups is the findings regrouped into what one statement about the build is
// about, with what each group's decisions add up to.
func (s *decidedSets) groups() map[Grouped]*decisionTally {
	out := map[Grouped]*decisionTally{}
	for _, f := range s.findings {
		c := s.components[f.ComponentID]
		g := Grouped{VulnerabilityID: f.VulnerabilityID, Identifier: s.identifiers[f.VulnerabilityID],
			Component: c.Name, Purl: c.Purl}
		t := out[g]
		if t == nil {
			t = &decisionTally{}
			out[g] = t
		}
		t.add(f.decisionTally)
	}
	return out
}

// firstGroups is rows in the order of the groups they are about, up to one
// past most, so that reaching the ceiling is distinguishable from landing on
// it.
func firstGroups[T any](rows []T, key func(T) Grouped, most int) []T {
	slices.SortFunc(rows, func(a, b T) int {
		x, y := key(a), key(b)
		return strings.Compare(x.Identifier+"\x00"+x.Component+"\x00"+x.Purl,
			y.Identifier+"\x00"+y.Component+"\x00"+y.Purl)
	})
	if len(rows) > most+1 {
		rows = rows[:most+1]
	}
	return rows
}

// distinctIDs is a list's members once each, in order.
func distinctIDs(ids []int64) []int64 {
	slices.Sort(ids)
	return slices.Compact(ids)
}
