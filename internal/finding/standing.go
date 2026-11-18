// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// A product's standing, per build.
//
// "How is SONiC doing" in one place: what is open per build, how much of it
// is overdue, how much has been decided, when each build was last scanned.

// BuildStanding is one build of a product and how far its work has got.
//
// Named for the build because "Standing" is already what a decision is when it
// still applies, and one word for two things is how two readers come to mean
// different ones.
type BuildStanding struct {
	BuildID     int64
	BranchOrTag string
	Variant     string
	// Open is issues at components, the unit every count here uses.
	Open int
	// Overdue is how many of those are past a deadline, and Exploited how many
	// somebody is known to be exploiting. Those two are what decides whether a
	// build needs an afternoon or a week.
	Overdue   int
	Exploited int
	// Undecided is how many nobody has decided anything about, and Agreed how
	// many are answered at every occurrence by a standing decision — the same
	// two words the findings list's state filter uses, by the same definition,
	// so this page and that list cannot disagree about what "agreed" means.
	Undecided int
	Agreed    int
}

// HowItStands reads each build of a product with how far its work has got, and
// the product's own totals.
//
// The product's totals are not the sum of its builds. The findings list
// answers for a whole product as one row per issue and component across every
// build it holds, so a library carrying one issue in two builds is
// one thing to decide about and two build rows. Adding the build rows up would
// put a number on this page that the list it links to contradicts — which is
// the failure this page exists to avoid, arrived at from the other side. So
// the totals are counted again, over the product, by the same grouping the
// list uses.
//
// Derived rather than stored for the reason every count here is: a stored
// total is right at the end of a scan and drifts from the list beside it
// thereafter.
func (s *Store) HowItStands(ctx context.Context, subject access.Subject,
	productID int64) ([]BuildStanding, BuildStanding, error) {

	var whole BuildStanding
	visible, err := access.Readable(subject, productID)
	if err != nil {
		return nil, whole, err
	}
	// The store's clock, like everything else here, so a frozen clock
	// reaches it and so one answer is worked out from one moment.
	now := s.now().UTC()

	// The things somebody decides about: one row per build, issue and
	// component, with the occurrences counted and the standing decisions
	// counted against them. The state words below compare an approved count
	// against the number of occurrences, so the decisions arrive as one row per
	// decided occurrence (decisionsAtOccurrences) rather than joined in, where
	// an occurrence with two decisions would count twice.
	//
	// The one count no list carries: anything that still says something about
	// the occurrence. A withdrawn decision does not — it covers the occurrence
	// so that "lapsed" can be said, and counted as a decision it would take the
	// finding out of the undecided figure while putting it in no other. Spelled
	// through the same helper as the rest, so the version match is one
	// expression.
	anyDecision := decisionState{"any_claim", ` AND "de"."state" <> ?`, []any{StateWithdrawn}}
	// One row per build, issue and component. The build rows count these
	// directly, and the product's totals fold them again by issue and
	// component, in one pass here. Every column folds exactly: the occurrences
	// and the decided occurrences are sums, the deadline a minimum and the
	// exploitation flag a maximum.
	//
	// Counted in chunks of builds (chunked), and the decided occurrences
	// counted apart and added after. Joined to every open occurrence and
	// grouped over the product at once, 3.6 million occurrences in 15 builds
	// spilled 147 MB to disk on PostgreSQL, 2.56 s against 1.07 s; the decided
	// occurrences are
	// the few a decision reaches, read from the decision side. Only builds
	// holding an open finding are read.
	kinds, kindArgs := kind.Statistics.Where(`"f"."kind"`)
	var inProduct []int64
	if err := s.db.NewSelect().
		TableExpr(`"build" AS "b"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
		ColumnExpr(`"b"."id"`).
		Where(`"st"."product_id" = ?`, productID).
		OrderExpr(`"b"."id"`).
		Scan(ctx, &inProduct); err != nil {
		return nil, whole, fmt.Errorf("read this product's builds: %w", err)
	}
	chunks, err := s.chunks(ctx, inProduct, `"f"."closed_at" IS NULL`)
	if err != nil {
		return nil, whole, err
	}
	type group struct {
		BuildID         int64      `bun:"build_id"`
		VulnerabilityID int64      `bun:"vulnerability_id"`
		ComponentID     int64      `bun:"component_id"`
		Occurrences     int        `bun:"places"`
		DueAt           *time.Time `bun:"due_at"`
		Exploited       int        `bun:"exploited"`
		AnyDecision     int        `bun:"any_claim"`
		Approved        int        `bun:"approved_here"`
	}
	var groups []group
	if counted := perChunk(chunks, func(builds []int64) *bun.SelectQuery {
		return s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			ColumnExpr(`"f"."build_id" AS "build_id"`).
			ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
			ColumnExpr(`"f"."component_id" AS "component_id"`).
			ColumnExpr(`COUNT(*) AS "places"`).
			ColumnExpr(`MIN("f"."due_at") AS "due_at"`).
			// The flag rather than the urgency's top bands, which answer
			// "some exploitation". This total is the feed's word about the
			// world, and a product recorded as attacked here is a different
			// fact that would be counted under the wrong name.
			ColumnExpr(exploitedAcross+` AS "exploited"`).
			Where(`"f"."build_id" IN (?)`, bun.List(builds)).
			Where(`"f"."closed_at" IS NULL`).
			Where(`"f"."visibility" IN (?)`, bun.List(visible)).
			Where(kinds, kindArgs...).
			GroupExpr(`"f"."build_id", "f"."vulnerability_id", "f"."component_id"`)
	}); counted != nil {
		if err := counted.Scan(ctx, &groups); err != nil {
			return nil, whole, fmt.Errorf("read how this product's builds stand: %w", err)
		}
	}
	var decided []group
	q := s.db.NewSelect()
	if err := q.
		TableExpr(`(?) AS "dd"`, decisionsAtOccurrences(q, productID, anyDecision, decisionApproved)).
		Join(`JOIN "finding" AS "f" ON "f"."id" = "dd"."finding_id"`).
		ColumnExpr(`"f"."build_id" AS "build_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		ColumnExpr(occurrencesDecided(anyDecision)).
		ColumnExpr(occurrencesDecided(decisionApproved)).
		Where(inThisProductAs(`"f"."build_id"`), productID).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(kinds, kindArgs...).
		GroupExpr(`"f"."build_id", "f"."vulnerability_id", "f"."component_id"`).
		Scan(ctx, &decided); err != nil {
		return nil, whole, fmt.Errorf("read what is decided in this product's builds: %w", err)
	}
	type place struct{ build, issue, component int64 }
	at := make(map[place]int, len(groups))
	for i, g := range groups {
		at[place{g.BuildID, g.VulnerabilityID, g.ComponentID}] = i
	}
	for _, d := range decided {
		if i, held := at[place{d.BuildID, d.VulnerabilityID, d.ComponentID}]; held {
			groups[i].AnyDecision += d.AnyDecision
			groups[i].Approved += d.Approved
		}
	}

	// One thing somebody decides about, and how it stands, counted into a
	// build row or the product's totals by the same four rules, so the two
	// cannot come to mean different things.
	type thing struct {
		occurrences, anyDecision, approved int
		dueAt                              *time.Time
		exploited                          bool
	}
	count := func(into *BuildStanding, one thing) {
		into.Open++
		if one.dueAt != nil && one.dueAt.Before(now) {
			into.Overdue++
		}
		if one.exploited {
			into.Exploited++
		}
		if one.anyDecision == 0 {
			into.Undecided++
		}
		if one.approved == one.occurrences {
			into.Agreed++
		}
	}
	type key struct{ issue, component int64 }
	builds := map[int64]*BuildStanding{}
	across := map[key]*thing{}
	order := make([]key, 0, len(groups))
	for _, group := range groups {
		one := thing{occurrences: group.Occurrences, anyDecision: group.AnyDecision, approved: group.Approved,
			dueAt: group.DueAt, exploited: group.Exploited > 0}
		build, held := builds[group.BuildID]
		if !held {
			build = &BuildStanding{BuildID: group.BuildID}
			builds[group.BuildID] = build
		}
		count(build, one)
		k := key{group.VulnerabilityID, group.ComponentID}
		sum, seen := across[k]
		if !seen {
			copied := one
			across[k] = &copied
			order = append(order, k)
			continue
		}
		sum.occurrences += one.occurrences
		sum.anyDecision += one.anyDecision
		sum.approved += one.approved
		sum.exploited = sum.exploited || one.exploited
		if one.dueAt != nil && (sum.dueAt == nil || one.dueAt.Before(*sum.dueAt)) {
			sum.dueAt = one.dueAt
		}
	}
	for _, k := range order {
		count(&whole, *across[k])
	}

	// Each build's branch or tag and variant, for the builds holding something.
	ids := make([]int64, 0, len(builds))
	for id := range builds {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) == 0 {
		return []BuildStanding{}, whole, nil
	}
	var named []struct {
		BuildID     int64  `bun:"build_id"`
		BranchOrTag string `bun:"branch_or_tag"`
		Variant     string `bun:"variant"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"build" AS "b"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "b"."variant_id"`).
		ColumnExpr(`"b"."id" AS "build_id"`).
		ColumnExpr(`"st"."name" AS "branch_or_tag"`).
		ColumnExpr(`"va"."name" AS "variant"`).
		Where(`"b"."id" IN (?)`, bun.List(ids)).
		Scan(ctx, &named); err != nil {
		return nil, whole, fmt.Errorf("read the builds of this product: %w", err)
	}
	for _, build := range named {
		builds[build.BuildID].BranchOrTag, builds[build.BuildID].Variant = build.BranchOrTag, build.Variant
	}

	out := make([]BuildStanding, 0, len(ids))
	for _, id := range ids {
		out = append(out, *builds[id])
	}
	return out, whole, nil
}
