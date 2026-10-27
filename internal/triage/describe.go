// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Described is what a decision occurrence is about, as the findings list would show it:
// the build to link to, the issue, the component and where it sits.
//
// Read from the open findings the row matches rather than from
// anything the decision itself states, because a decision names an occurrence and
// versions and nothing else — the build, the component and what the issue is
// are the finding's to say.
type Described struct {
	BuildID int64
	// Product, Branch or tag and Variant are the names a path addresses the build
	// by, and the three Name fields the ones it is shown under.
	Product, ProductName         string
	BranchOrTag, BranchOrTagName string
	Variant, VariantName         string
	Component                    string
	Version                      string
	Purl                         string
	FixState                     string
	FixedIn                      string
	// Issue is the vulnerability, with what the report says about it.
	Issue finding.Vulnerability
	// Owner and Parent are the two ends of the way down, as the findings list
	// gives them; Unplaced says the inventory placed the component nowhere.
	Owner, Parent string
	// Occurrences is how many occurrences the issue sits at in that component in that
	// build, and Decided how many of those this row's decision covers.
	Occurrences, Decided int
}

// describedRow is one open finding a decision occurrence matches.
type describedRow struct {
	DecisionOccurrenceID int64  `bun:"decision_occurrence_id"`
	DecisionID           int64  `bun:"decision_id"`
	Exact                int    `bun:"exact"`
	BuildID              int64  `bun:"build_id"`
	ProductID            int64  `bun:"product_id"`
	Product              string `bun:"product"`
	ProductName          string `bun:"product_name"`
	BranchOrTag          string `bun:"branch_or_tag"`
	BranchOrTagName      string `bun:"branch_or_tag_name"`
	Variant              string `bun:"variant"`
	VariantName          string `bun:"variant_name"`
	ComponentID          int64  `bun:"component_id"`
	Component            string `bun:"component"`
	Version              string `bun:"version"`
	Purl                 string `bun:"purl"`
	ConsumerID           *int64 `bun:"consumer_id"`
	Consumer             string `bun:"consumer"`
	FixState             string `bun:"fix_state"`
	FixedIn              string `bun:"fixed_in"`
	Issue                int64  `bun:"vulnerability_id"`
}

// Describe reads what each of these decision occurrences is about, in a handful of
// statements for the whole set rather than one per row.
//
// A decision occurrence matches open findings by occurrence and, while it is live, by
// the versions it was written against. A lapsed row's versions no longer
// match anything, so the match falls back to the occurrence alone: the card can
// still say which component and build the decision was about, which is what
// somebody re-making it needs. Where a row matches several builds, the first
// by name is the one described.
//
// Narrowed to what the subject may read, like every count that is served
// back: a decision somebody may read can sit beside findings they may not.
func (s *Store) Describe(ctx context.Context, subject access.Subject, occurrences []DecisionOccurrence) (map[int64]Described, error) {
	out := map[int64]Described{}
	if len(occurrences) == 0 {
		return out, nil
	}
	ids := make([]int64, 0, len(occurrences))
	decisions := make([]int64, 0, len(occurrences))
	for _, occurrence := range occurrences {
		ids = append(ids, occurrence.ID)
		decisions = append(decisions, occurrence.DecisionID)
	}
	var rows []describedRow
	err := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		// The decision occurrence is on the outside of this join by construction, and
		// the spelling is the instruction. CROSS JOIN ... WHERE is an inner
		// join on every engine; on SQLite it also fixes the order, statistics
		// or not — and left
		// to itself the planner started from finding, taking "open" as an
		// equality that matches ten rows when it matches every open row in
		// the deployment, and probed the decision occurrences once per row: 0.46 s to
		// describe a page of thirty-two, against 0.1 ms the other way round.
		Join(finding.DecisionOccurrenceIssue).
		Join(`CROSS JOIN "finding" AS "f"`).
		Where(finding.DecisionOccurrenceOf("f")).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		Join(`JOIN "product" AS "pr" ON "pr"."id" = "st"."product_id"`).
		ColumnExpr(`"de"."id" AS "decision_occurrence_id"`).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr("CASE WHEN "+finding.VersionsMatch+` THEN 1 ELSE 0 END AS "exact"`).
		ColumnExpr(`"f"."build_id" AS "build_id"`).
		ColumnExpr(`"de"."product_id" AS "product_id"`).
		Apply(catalog.BuildNames("pr", "st", "va")).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		ColumnExpr(`"c"."name" AS "component"`).
		ColumnExpr(`"c"."version" AS "version"`).
		ColumnExpr(`"c"."purl" AS "purl"`).
		ColumnExpr(`"f"."consumer_id" AS "consumer_id"`).
		ColumnExpr(`COALESCE("uc"."name", '') AS "consumer"`).
		ColumnExpr(`"f"."fix_state" AS "fix_state"`).
		ColumnExpr(`"f"."fixed_in" AS "fixed_in"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		Where(`"de"."id" IN (?)`, bun.List(ids)).
		Where(`"st"."product_id" = "de"."product_id"`).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Apply(readableFindingsBy(subject, "f", `"st"."product_id"`)).
		OrderExpr(`"de"."id", exact DESC, "st"."name", "va"."name", "c"."name"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what these decision occurrences are about: %w", err)
	}
	if len(rows) == 0 {
		return out, nil
	}

	// The first row per decision occurrence is the one described: an exact match
	// first, then the first build by name.
	chosen := map[int64]describedRow{}
	for _, row := range rows {
		if _, seen := chosen[row.DecisionOccurrenceID]; !seen {
			chosen[row.DecisionOccurrenceID] = row
		}
	}

	// The issues, once each.
	issueIDs := map[int64]bool{}
	for _, row := range chosen {
		issueIDs[row.Issue] = true
	}
	wanted := make([]int64, 0, len(issueIDs))
	for id := range issueIDs {
		wanted = append(wanted, id)
	}
	var issues []finding.Vulnerability
	if err := s.db.NewSelect().Model(&issues).
		Where(`"id" IN (?)`, bun.List(wanted)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these issues are: %w", err)
	}
	// A flaw recorded where this reader may not read it wrote its summary
	// onto the issue row every product shares.
	withheld, err := finding.RecordedOutOfReach(ctx, s.db, subject, wanted)
	if err != nil {
		return nil, err
	}
	byIssue := make(map[int64]finding.Vulnerability, len(issues))
	for _, issue := range issues {
		if withheld[issue.ID] {
			issue.WithholdRecorded()
		}
		byIssue[issue.ID] = issue
	}
	// Each row's own product's rating of its issue. A rating belongs to a
	// product, and these rows span them — a queue of decisions is not one
	// product's — so the word a card shows is the one the product the
	// decision was made in holds.
	withinProducts := make([]int64, 0, len(chosen))
	for _, row := range chosen {
		withinProducts = append(withinProducts, row.ProductID)
	}
	rated, err := finding.RatingsIn(ctx, s.db, withinProducts, wanted)
	if err != nil {
		return nil, err
	}

	// The occurrences the issue sits at in that component in that build, and
	// how many of those the row's decision covers. One grouped statement
	// each over the builds and components in hand; the triples that were not
	// asked about fall out in Go.
	buildIDs, components := distinctOf(chosen)
	var counts []struct {
		BuildID     int64 `bun:"build_id"`
		Issue       int64 `bun:"vulnerability_id"`
		ComponentID int64 `bun:"component_id"`
		Occurrences int   `bun:"places"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"f"."build_id" AS "build_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		Where(`"f"."build_id" IN (?)`, bun.List(buildIDs)).
		Where(`"f"."vulnerability_id" IN (?)`, bun.List(wanted)).
		Where(`"f"."component_id" IN (?)`, bun.List(components)).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Apply(readableFindingsBy(subject, "f", `"st"."product_id"`)).
		GroupExpr(`"f"."build_id", "f"."vulnerability_id", "f"."component_id"`).
		Scan(ctx, &counts); err != nil {
		return nil, fmt.Errorf("count where these sit: %w", err)
	}
	type triple struct {
		build, issue, component int64
	}
	occurrencesAt := map[triple]int{}
	for _, count := range counts {
		occurrencesAt[triple{count.BuildID, count.Issue, count.ComponentID}] = count.Occurrences
	}

	// Covered is what the decision's live rows actually match — the occurrence and
	// both versions, as a finding asks it — rather than every occurrence the
	// decision ever named. The occurrence-only fallback above is for naming what a
	// lapsed decision was about; counted that way, a decision whose rows had
	// lapsed, or which was keyed at another build's version, reported occurrences
	// it does not cover.
	var covered []struct {
		DecisionID  int64 `bun:"decision_id"`
		BuildID     int64 `bun:"build_id"`
		Issue       int64 `bun:"vulnerability_id"`
		ComponentID int64 `bun:"component_id"`
		Decided     int   `bun:"decided"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		// The decision occurrence on the outside, as above.
		Join(finding.DecisionOccurrenceIssue).
		Join(`CROSS JOIN "finding" AS "f"`).
		Where(finding.DecisionOccurrenceOf("f")).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`"f"."build_id" AS "build_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		ColumnExpr(`COUNT(DISTINCT "f"."occurrence_identity") AS "decided"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(decisions)).
		Where(`"de"."live_key" IS NOT NULL`).
		Where(`"st"."product_id" = "de"."product_id"`).
		Where(finding.KeyMatches).
		Where(`"f"."build_id" IN (?)`, bun.List(buildIDs)).
		Where(`"f"."component_id" IN (?)`, bun.List(components)).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Apply(readableFindingsBy(subject, "f", `"st"."product_id"`)).
		GroupExpr(`"de"."decision_id", "f"."build_id", "f"."vulnerability_id", "f"."component_id"`).
		Scan(ctx, &covered); err != nil {
		return nil, fmt.Errorf("count what these decisions cover: %w", err)
	}
	type claimed struct {
		decision, build, issue, component int64
	}
	decided := map[claimed]int{}
	for _, count := range covered {
		decided[claimed{count.DecisionID, count.BuildID, count.Issue, count.ComponentID}] = count.Decided
	}

	// The two ends of the way down, one walk per build rather than per row.
	byBuild := map[int64][]int64{}
	for _, row := range chosen {
		if row.ConsumerID != nil {
			byBuild[row.BuildID] = append(byBuild[row.BuildID], *row.ConsumerID)
		} else {
			byBuild[row.BuildID] = append(byBuild[row.BuildID], row.ComponentID)
		}
	}
	// The graph store reads through the pool. Describing is a read on the
	// way out of a handler, never part of a transaction.
	pool, err := s.pool()
	if err != nil {
		return nil, fmt.Errorf("describing decision occurrences reads the graph through the pool: %w", err)
	}
	chains := map[int64]map[int64][]graph.Step{}
	for build, components := range byBuild {
		down, err := graph.NewStore(pool).Chains(ctx, subject, build, components)
		if err != nil {
			return nil, err
		}
		chains[build] = down
	}

	for id, row := range chosen {
		one := Described{
			BuildID: row.BuildID,
			Product: row.Product, ProductName: row.ProductName,
			BranchOrTag: row.BranchOrTag, BranchOrTagName: row.BranchOrTagName,
			Variant: row.Variant, VariantName: row.VariantName,
			Component: row.Component, Version: row.Version, Purl: row.Purl,
			FixState: row.FixState, FixedIn: row.FixedIn,
			Issue: byIssue[row.Issue].RatedIn(
				rated[finding.RatedKey{ProductID: row.ProductID, VulnerabilityID: row.Issue}]),
			Occurrences: occurrencesAt[triple{row.BuildID, row.Issue, row.ComponentID}],
			Decided:     decided[claimed{row.DecisionID, row.BuildID, row.Issue, row.ComponentID}],
		}
		at := row.ComponentID
		if row.ConsumerID != nil {
			at = *row.ConsumerID
		}
		one.Owner, one.Parent, _ = finding.Ends(chains[row.BuildID][at])
		// A route up that could not be walked is not the same as nothing
		// pulling this in. The finding records its consumer either way, so
		// the card names it rather than showing an approver a blank where the
		// path they are meant to judge the decision by should be.
		if one.Owner == "" && one.Parent == "" && row.Consumer != "" {
			one.Parent = row.Consumer
		}
		out[id] = one
	}
	return out, nil
}

// distinctOf lists the builds and components a set of described rows names,
// in a stable order.
func distinctOf(rows map[int64]describedRow) (buildIDs, components []int64) {
	seenBuild := map[int64]bool{}
	seenComponent := map[int64]bool{}
	for _, row := range rows {
		if !seenBuild[row.BuildID] {
			seenBuild[row.BuildID] = true
			buildIDs = append(buildIDs, row.BuildID)
		}
		if !seenComponent[row.ComponentID] {
			seenComponent[row.ComponentID] = true
			components = append(components, row.ComponentID)
		}
	}
	sort.Slice(buildIDs, func(i, j int) bool { return buildIDs[i] < buildIDs[j] })
	sort.Slice(components, func(i, j int) bool { return components[i] < components[j] })
	return buildIDs, components
}
