// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Described is what a decision is about, as the findings list would show it:
// the build to link to, the issue, the component and where it sits.
//
// Read from the open findings the decision's row matches rather than from
// anything the decision itself states, because a decision names a place and
// versions and nothing else — the build, the component and what the issue is
// are the finding's to say.
type Described struct {
	TargetID int64
	// Product, Stream and Variant are the names a path addresses the build
	// by, and the three Name fields the ones it is shown under.
	Product, ProductName string
	Stream, StreamName   string
	Variant, VariantName string
	Component            string
	Version              string
	FixState             string
	FixedIn              string
	// Issue is the vulnerability, with what the report says about it.
	Issue finding.Vulnerability
	// Owner and Parent are the two ends of the way down, as the findings list
	// gives them; Unplaced says the inventory placed the component nowhere.
	Owner, Parent string
	// Places is how many places the issue sits at in that component in that
	// build, and Decided how many of those this decision's claim covers.
	Places, Decided int
}

// describedRow is one open finding a decision's row matches.
type describedRow struct {
	DecisionID  int64  `bun:"decision_id"`
	ClaimID     int64  `bun:"claim_id"`
	Exact       int    `bun:"exact"`
	TargetID    int64  `bun:"target_id"`
	ProductID   int64  `bun:"product_id"`
	Product     string `bun:"product"`
	ProductName string `bun:"product_name"`
	Stream      string `bun:"stream"`
	StreamName  string `bun:"stream_name"`
	Variant     string `bun:"variant"`
	VariantName string `bun:"variant_name"`
	ComponentID int64  `bun:"component_id"`
	Component   string `bun:"component"`
	Version     string `bun:"version"`
	ConsumerID  *int64 `bun:"consumer_id"`
	Consumer    string `bun:"consumer"`
	FixState    string `bun:"fix_state"`
	FixedIn     string `bun:"fixed_in"`
	Issue       int64  `bun:"vulnerability_id"`
}

// Describe reads what each of these decisions is about, in a handful of
// statements for the whole set rather than one per decision.
//
// A decision's row matches open findings by place and, while it is live, by
// the versions it was written against. A lapsed decision's versions no longer
// match anything, so the match falls back to the place alone: the card can
// still say which component and build the judgment was about, which is what
// somebody re-making it needs. Where a row matches several builds, the first
// by name is the one described.
//
// Narrowed to what the subject may read, like every count that is served
// back: a decision somebody may read can sit beside findings they may not.
func (s *Store) Describe(ctx context.Context, subject access.Subject, decisions []Decision) (map[int64]Described, error) {
	out := map[int64]Described{}
	if len(decisions) == 0 {
		return out, nil
	}
	ids := make([]int64, 0, len(decisions))
	claims := make([]int64, 0, len(decisions))
	for _, decision := range decisions {
		ids = append(ids, decision.ID)
		claims = append(claims, decision.ClaimID)
	}
	readable := readableVisibilities(subject, ids, s, ctx)

	var rows []describedRow
	err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		// The decision is on the outside of this join by construction, and
		// the spelling is the instruction. CROSS JOIN ... WHERE is an inner
		// join on every engine; on SQLite, which plans without statistics
		// unless somebody has run ANALYZE, it also fixes the order — and left
		// to itself the planner started from finding, taking "open" as an
		// equality that matches ten rows when it matches every open row in
		// the deployment, and probed the decisions once per row: 0.46 s to
		// describe a page of thirty-two, against 0.1 ms the other way round.
		Join(`CROSS JOIN "finding" AS "f"`).
		Where("f.vulnerability_id = de.vulnerability_id AND f.place_identity = de.place_identity").
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		Join(`JOIN "product" AS "pr" ON pr.id = st.product_id`).
		ColumnExpr(`de.id AS "decision_id"`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr("CASE WHEN COALESCE(de.component_upstream_version, '') = "+finding.ComponentUpstreamExpr+
			" AND COALESCE(de.consumer_upstream_version, '') = "+finding.ConsumerUpstreamExpr+
			` THEN 1 ELSE 0 END AS "exact"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`pr.name AS "product"`).
		ColumnExpr(`COALESCE(NULLIF(pr.display_name, ''), pr.name) AS "product_name"`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`st.display_name AS "stream_name"`).
		ColumnExpr(`va.name AS "variant"`).
		ColumnExpr(`va.display_name AS "variant_name"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`c.name AS "component"`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(`f.consumer_id AS "consumer_id"`).
		ColumnExpr(`COALESCE(uc.name, '') AS "consumer"`).
		ColumnExpr(`f.fix_state AS "fix_state"`).
		ColumnExpr(`f.fixed_in AS "fixed_in"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		Where("de.id IN (?)", bun.List(ids)).
		Where("st.product_id = de.product_id").
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(readable)).
		OrderExpr("de.id, exact DESC, st.name, va.name, c.name").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what these decisions are about: %w", err)
	}
	if len(rows) == 0 {
		return out, nil
	}

	// The first row per decision is the one described: an exact match
	// first, then the first build by name.
	chosen := map[int64]describedRow{}
	for _, row := range rows {
		if _, seen := chosen[row.DecisionID]; !seen {
			chosen[row.DecisionID] = row
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
		Where("id IN (?)", bun.List(wanted)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these issues are: %w", err)
	}
	byIssue := make(map[int64]finding.Vulnerability, len(issues))
	for _, issue := range issues {
		byIssue[issue.ID] = issue
	}
	// Each decision's own product's rating of its issue. A rating belongs to a
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

	// The places the issue sits at in that component in that build, and
	// how many of those the decision's claim covers. One grouped statement
	// each over the builds and components in hand; the triples that were not
	// asked about fall out in Go.
	targets, components := distinctOf(chosen)
	var counts []struct {
		TargetID    int64 `bun:"target_id"`
		Issue       int64 `bun:"vulnerability_id"`
		ComponentID int64 `bun:"component_id"`
		Places      int   `bun:"places"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.vulnerability_id IN (?)", bun.List(wanted)).
		Where("f.component_id IN (?)", bun.List(components)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(readable)).
		GroupExpr("f.target_id, f.vulnerability_id, f.component_id").
		Scan(ctx, &counts); err != nil {
		return nil, fmt.Errorf("count where these sit: %w", err)
	}
	type triple struct {
		target, issue, component int64
	}
	places := map[triple]int{}
	for _, count := range counts {
		places[triple{count.TargetID, count.Issue, count.ComponentID}] = count.Places
	}

	// Covered is what the claim's live rows actually match — the place and
	// both versions, as a finding asks it — rather than every place the
	// claim ever named. The place-only fallback above is for naming what a
	// lapsed judgment was about; counted that way, a claim whose rows had
	// lapsed, or which was keyed at another build's version, reported places
	// it does not cover.
	var covered []struct {
		ClaimID     int64 `bun:"claim_id"`
		TargetID    int64 `bun:"target_id"`
		Issue       int64 `bun:"vulnerability_id"`
		ComponentID int64 `bun:"component_id"`
		Decided     int   `bun:"decided"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		// The decision on the outside, as above.
		Join(`CROSS JOIN "finding" AS "f"`).
		Where("f.vulnerability_id = de.vulnerability_id AND f.place_identity = de.place_identity").
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`COUNT(DISTINCT f.place_identity) AS "decided"`).
		Where("de.claim_id IN (?)", bun.List(claims)).
		Where("de.live_key IS NOT NULL").
		Where("st.product_id = de.product_id").
		Where(finding.KeyMatches).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.component_id IN (?)", bun.List(components)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(readable)).
		GroupExpr("de.claim_id, f.target_id, f.vulnerability_id, f.component_id").
		Scan(ctx, &covered); err != nil {
		return nil, fmt.Errorf("count what these claims cover: %w", err)
	}
	type claimed struct {
		claim, target, issue, component int64
	}
	decided := map[claimed]int{}
	for _, count := range covered {
		decided[claimed{count.ClaimID, count.TargetID, count.Issue, count.ComponentID}] = count.Decided
	}

	// The two ends of the way down, one walk per build rather than per row.
	byTarget := map[int64][]int64{}
	for _, row := range chosen {
		if row.ConsumerID != nil {
			byTarget[row.TargetID] = append(byTarget[row.TargetID], *row.ConsumerID)
		} else {
			byTarget[row.TargetID] = append(byTarget[row.TargetID], row.ComponentID)
		}
	}
	// The graph store reads through the pool. Describing is a read on the
	// way out of a handler, never part of a transaction.
	pool, err := s.pool()
	if err != nil {
		return nil, fmt.Errorf("describing decisions reads the graph through the pool: %w", err)
	}
	chains := map[int64]map[int64][]graph.Step{}
	for target, components := range byTarget {
		down, err := graph.NewStore(pool).Chains(ctx, subject, target, components)
		if err != nil {
			return nil, err
		}
		chains[target] = down
	}

	for id, row := range chosen {
		one := Described{
			TargetID: row.TargetID,
			Product:  row.Product, ProductName: row.ProductName,
			Stream: row.Stream, StreamName: row.StreamName,
			Variant: row.Variant, VariantName: row.VariantName,
			Component: row.Component, Version: row.Version,
			FixState: row.FixState, FixedIn: row.FixedIn,
			Issue: byIssue[row.Issue].RatedIn(
				rated[finding.RatedKey{ProductID: row.ProductID, VulnerabilityID: row.Issue}]),
			Places:  places[triple{row.TargetID, row.Issue, row.ComponentID}],
			Decided: decided[claimed{row.ClaimID, row.TargetID, row.Issue, row.ComponentID}],
		}
		at := row.ComponentID
		if row.ConsumerID != nil {
			at = *row.ConsumerID
		}
		one.Owner, one.Parent, _ = finding.Ends(chains[row.TargetID][at])
		// A route up that could not be walked is not the same as nothing
		// pulling this in. The finding records its consumer either way, so
		// the card names it rather than showing an approver a blank where the
		// path they are meant to judge the claim by should be.
		if one.Owner == "" && one.Parent == "" && row.Consumer != "" {
			one.Parent = row.Consumer
		}
		out[id] = one
	}
	return out, nil
}

// distinctOf lists the builds and components a set of described rows names,
// in a stable order.
func distinctOf(rows map[int64]describedRow) (targets, components []int64) {
	seenTarget := map[int64]bool{}
	seenComponent := map[int64]bool{}
	for _, row := range rows {
		if !seenTarget[row.TargetID] {
			seenTarget[row.TargetID] = true
			targets = append(targets, row.TargetID)
		}
		if !seenComponent[row.ComponentID] {
			seenComponent[row.ComponentID] = true
			components = append(components, row.ComponentID)
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	sort.Slice(components, func(i, j int) bool { return components[i] < components[j] })
	return targets, components
}
