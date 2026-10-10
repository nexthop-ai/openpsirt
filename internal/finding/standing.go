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
)

// A product's standing, per build.
//
// There was no page for one product. "How is SONiC doing" was five
// requests and a spreadsheet: what is open per build, how much of it is
// overdue, how much has been decided, when each build was last scanned. Every
// piece existed and none of them sat together, so the question was answered by
// somebody who already knew where to look.

// BuildStanding is one build of a product and how far its work has got.
//
// Named for the build because "Standing" is already what a decision is when it
// still applies, and one word for two things is how two readers come to mean
// different ones.
type BuildStanding struct {
	TargetID int64
	Stream   string
	Variant  string
	// Open is issues at components, the unit every count here uses.
	Open int
	// Overdue is how many of those are past a deadline, and Exploited how many
	// somebody is known to be exploiting. Those two are what decides whether a
	// build needs an afternoon or a week.
	Overdue   int
	Exploited int
	// Undecided is how many nobody has claimed anything about, and Agreed how
	// many are answered at every place by a standing decision — the same two
	// words the findings list's state filter uses, by the same definition, so
	// this page and that list cannot disagree about what "agreed" means.
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
	// component, with the places counted and the standing decisions counted
	// against them. The state words below compare an approved count against
	// the number of places, so the decisions arrive as one row per decided
	// place (decisionsAtPlaces) rather than joined in, where a place with two
	// decisions would count twice.
	//
	// The one count no list carries: anything that still says something about
	// the place. A withdrawn claim does not — it covers the place so that
	// "lapsed" can be said, and counted as a claim it would take the finding
	// out of the undecided figure while putting it in no other. Spelled
	// through the same helper as the rest, so the version match is one
	// expression.
	anyClaim := decisionState{"any_claim", " AND de.state <> ?", []any{"withdrawn"}}
	// One row per build, issue and component. The build rows count these
	// directly, and the product's totals fold them again by issue and
	// component, in one pass here. The table of decided places is most of the
	// cost of the reading, 0.7 s with 133,000 decisions on PostgreSQL, and a
	// second statement builds it a second time. Every column folds exactly — the
	// places and the decided places are sums, the deadline a minimum and the
	// exploitation flag a maximum.
	q := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`MIN(f.due_at) AS "due_at"`).
		// The flag rather than the urgency's top bands, which answer
		// "some exploitation". This total is the feed's word about the
		// world, and a product recorded as attacked here is a different
		// fact that would be counted under the wrong name.
		ColumnExpr(exploitedAcross + ` AS "exploited"`).
		ColumnExpr(placesDecided(anyClaim)).
		ColumnExpr(placesDecided(claimApproved))
	var groups []struct {
		TargetID        int64      `bun:"target_id"`
		VulnerabilityID int64      `bun:"vulnerability_id"`
		ComponentID     int64      `bun:"component_id"`
		Places          int        `bun:"places"`
		DueAt           *time.Time `bun:"due_at"`
		Exploited       int        `bun:"exploited"`
		AnyClaim        int        `bun:"any_claim"`
		Approved        int        `bun:"approved_here"`
	}
	err = q.Join(`LEFT JOIN (?) AS "dd" ON dd.finding_id = f.id`,
		decisionsAtPlaces(q, productID, anyClaim, claimApproved)).
		Where(inThisProductAs("f.target_id"), productID).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.target_id, f.vulnerability_id, f.component_id").
		Scan(ctx, &groups)
	if err != nil {
		return nil, whole, fmt.Errorf("read how this product's builds stand: %w", err)
	}

	// One thing somebody decides about, and how it stands, counted into a
	// build row or the product's totals by the same four rules, so the two
	// cannot come to mean different things.
	type thing struct {
		places, anyClaim, approved int
		dueAt                      *time.Time
		exploited                  bool
	}
	count := func(into *BuildStanding, one thing) {
		into.Open++
		if one.dueAt != nil && one.dueAt.Before(now) {
			into.Overdue++
		}
		if one.exploited {
			into.Exploited++
		}
		if one.anyClaim == 0 {
			into.Undecided++
		}
		if one.approved == one.places {
			into.Agreed++
		}
	}
	type key struct{ issue, component int64 }
	builds := map[int64]*BuildStanding{}
	across := map[key]*thing{}
	order := make([]key, 0, len(groups))
	for _, group := range groups {
		one := thing{places: group.Places, anyClaim: group.AnyClaim, approved: group.Approved,
			dueAt: group.DueAt, exploited: group.Exploited > 0}
		build, held := builds[group.TargetID]
		if !held {
			build = &BuildStanding{TargetID: group.TargetID}
			builds[group.TargetID] = build
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
		sum.places += one.places
		sum.anyClaim += one.anyClaim
		sum.approved += one.approved
		sum.exploited = sum.exploited || one.exploited
		if one.dueAt != nil && (sum.dueAt == nil || one.dueAt.Before(*sum.dueAt)) {
			sum.dueAt = one.dueAt
		}
	}
	for _, k := range order {
		count(&whole, *across[k])
	}

	// Each build's stream and variant, for the builds holding something.
	ids := make([]int64, 0, len(builds))
	for id := range builds {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) == 0 {
		return []BuildStanding{}, whole, nil
	}
	var named []struct {
		TargetID int64  `bun:"target_id"`
		Stream   string `bun:"stream"`
		Variant  string `bun:"variant"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`tg.id AS "target_id"`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`va.name AS "variant"`).
		Where("tg.id IN (?)", bun.List(ids)).
		Scan(ctx, &named); err != nil {
		return nil, whole, fmt.Errorf("read the builds of this product: %w", err)
	}
	for _, build := range named {
		builds[build.TargetID].Stream, builds[build.TargetID].Variant = build.Stream, build.Variant
	}

	out := make([]BuildStanding, 0, len(ids))
	for _, id := range ids {
		out = append(out, *builds[id])
	}
	return out, whole, nil
}
