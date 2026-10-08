// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// PlaceCovered is an issue in a component as one product of the build pulls
// it in, where the component's places disagree and every place beneath that
// product agrees.
//
// A VEX document states it naming the consumer as the product and the
// component beneath it: "zlib inside curl 8.5.0: not affected". A reader
// applies such a statement beneath the product it names, so it is made only
// where everything beneath that product was decided the same way.
type PlaceCovered struct {
	VulnerabilityID int64
	Identifier      string
	Component       string
	Purl            string
	// Consumer and ConsumerPurl are the product the statement names: the
	// component pulling this one in, by the package identifier the build
	// stated for it.
	Consumer     string
	ConsumerPurl string
	Covering
}

// coveredPlace is one open place of an issue, and whether approved, live
// decisions agreeing on one outcome cover it.
type coveredPlace struct {
	vulnerabilityID int64
	identifier      string
	componentID     int64
	component       string
	purl            string
	consumerID      int64
	consumer        string
	consumerPurl    string
	covered         bool
	Covering
}

// statedGroup is what one statement about a component is about: an issue, and a
// component by its name and the package identifier the build stated.
type statedGroup struct {
	vulnerabilityID int64
	component       string
	purl            string
}

// CoveredAtPlaces reads what a VEX document of one build states place by
// place: the places a decision covers, in components some of whose places are
// open and undecided or decided another way.
//
// A place is stated only where all of these hold:
//
//   - its consumer's package identifier names a version, because a statement
//     naming a product at no version is about every release of it. A place
//     the build holds directly has no consumer, and so no product but the
//     build, which a statement about the whole build names
//   - every open place of the component beneath the consumer, at any depth, is
//     covered with the same outcome
//
// Where several places beneath one consumer were decided in separate sittings,
// the earliest decision speaks, as it does for a whole component.
func CoveredAtPlaces(ctx context.Context, db bun.IDB, productID, targetID int64,
	visible []access.Visibility, most int) ([]PlaceCovered, error) {

	decided, err := decidedPlaces(ctx, db, productID, targetID, visible)
	if err != nil || len(decided) == 0 {
		return nil, err
	}
	every, err := everyPlaceOf(ctx, db, targetID, visible, decided)
	if err != nil {
		return nil, err
	}
	places, err := placeEdges(ctx, db, targetID, 0)
	if err != nil {
		return nil, err
	}
	children := map[int64][]int64{}
	for child, above := range places {
		for _, consumer := range above {
			children[consumer] = append(children[consumer], child)
		}
	}
	beneath := map[int64]map[int64]bool{}
	under := func(consumer int64) map[int64]bool {
		if held, ok := beneath[consumer]; ok {
			return held
		}
		seen := map[int64]bool{consumer: true}
		queue := append([]int64(nil), children[consumer]...)
		for len(queue) > 0 {
			at := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			if seen[at] {
				continue
			}
			seen[at] = true
			queue = append(queue, children[at]...)
		}
		beneath[consumer] = seen
		return seen
	}

	var out []PlaceCovered
	stated := map[[2]any]bool{}
	for g, all := range every {
		wholly := true
		for _, one := range all {
			if !one.covered || one.Outcome != all[0].Outcome {
				wholly = false
				break
			}
		}
		if wholly {
			// One statement about the whole component says it.
			continue
		}
		for _, one := range all {
			if !one.covered ||
				graph.PartsOfPurl(one.consumerPurl).Version == "" ||
				stated[[2]any{g, one.consumerID}] {
				continue
			}
			inside := under(one.consumerID)
			earliest, agreed := one.DecidedBy, true
			for _, other := range all {
				if !inside[other.consumerID] {
					continue
				}
				if !other.covered || other.Outcome != one.Outcome {
					agreed = false
					break
				}
				earliest = min(earliest, other.DecidedBy)
			}
			if !agreed {
				continue
			}
			stated[[2]any{g, one.consumerID}] = true
			out = append(out, PlaceCovered{
				VulnerabilityID: one.vulnerabilityID, Identifier: one.identifier,
				Component: one.component, Purl: one.purl,
				Consumer: one.consumer, ConsumerPurl: one.consumerPurl,
				Covering: Covering{Outcome: one.Outcome, DecidedBy: earliest},
			})
			if len(out) > most {
				return out, nil
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Identifier != b.Identifier {
			return a.Identifier < b.Identifier
		}
		if a.Purl != b.Purl {
			return a.Purl < b.Purl
		}
		return a.ConsumerPurl < b.ConsumerPurl
	})
	return out, nil
}

// statedPlaceColumns are what a place is read with: the issue, the component and
// the consumer, each by the package identifier the build stated for it.
//
// The build's open node for a component holds the identifier this build
// stated; the component row is shared by every product shipping the package.
// A build holds one open node per component, so the joins add no row.
func statedPlaceColumns(q *bun.SelectQuery) *bun.SelectQuery {
	return q.
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "graph_node" AS "gn" ON gn.target_id = f.target_id
			AND gn.component_id = f.component_id AND gn.closed_scan_id IS NULL`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`LEFT JOIN "graph_node" AS "cn" ON cn.target_id = f.target_id
			AND cn.component_id = f.consumer_id AND cn.closed_scan_id IS NULL`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		ColumnExpr(`f.id AS "finding_id"`).
		ColumnExpr(`v.id AS "vulnerability_id"`).
		ColumnExpr(`v.identifier AS "identifier"`).
		ColumnExpr(`c.id AS "component_id"`).
		ColumnExpr(`c.name AS "component"`).
		ColumnExpr(`COALESCE(gn.purl, c.purl, '') AS "purl"`).
		ColumnExpr(`COALESCE(f.consumer_id, 0) AS "consumer_id"`).
		ColumnExpr(`COALESCE(uc.name, '') AS "consumer"`).
		ColumnExpr(`COALESCE(cn.purl, uc.purl, '') AS "consumer_purl"`)
}

// statedPlace is one place as statedPlaceColumns reads it.
type statedPlace struct {
	FindingID       int64  `bun:"finding_id"`
	VulnerabilityID int64  `bun:"vulnerability_id"`
	Identifier      string `bun:"identifier"`
	ComponentID     int64  `bun:"component_id"`
	Component       string `bun:"component"`
	Purl            string `bun:"purl"`
	ConsumerID      int64  `bun:"consumer_id"`
	Consumer        string `bun:"consumer"`
	ConsumerPurl    string `bun:"consumer_purl"`
}

func (r statedPlace) place() coveredPlace {
	return coveredPlace{
		vulnerabilityID: r.VulnerabilityID, identifier: r.Identifier,
		componentID: r.ComponentID, component: r.Component, purl: r.Purl,
		consumerID: r.ConsumerID, consumer: r.Consumer, consumerPurl: r.ConsumerPurl,
	}
}

// decidedPlaces is every open place of the build a decision covers for a VEX
// document, one row per place.
//
// Only places somebody decided are read here. A build holds hundreds of
// thousands of open places, and a statement place by place is only ever about
// a component somebody decided at least one place of.
func decidedPlaces(ctx context.Context, db bun.IDB, productID, targetID int64,
	visible []access.Visibility) (map[int64]coveredPlace, error) {

	var rows []struct {
		statedPlace
		Joined   int `bun:"joined"`
		Decided  int `bun:"decided"`
		Outcomes int `bun:"outcomes"`
		Covering
	}
	q := covered(statedPlaceColumns(db.NewSelect()), productID, visible, ForStatements).
		ColumnExpr(`COUNT(*) AS "joined"`).
		ColumnExpr(`COUNT(cl.id) AS "decided"`).
		ColumnExpr(`COUNT(DISTINCT cl.outcome) AS "outcomes"`).
		Where("f.target_id = ?", targetID).
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr(`f.id, v.id, v.identifier, c.id, c.name, gn.purl, c.purl, f.consumer_id,
			uc.name, cn.purl, uc.purl`).
		Having("COUNT(cl.id) > 0")
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the places decisions cover: %w", err)
	}
	out := make(map[int64]coveredPlace, len(rows))
	for _, row := range rows {
		one := row.place()
		one.covered = row.Decided == row.Joined && row.Outcomes == 1
		one.Covering = row.Covering
		out[row.FindingID] = one
	}
	return out, nil
}

// everyPlaceOf is every open place of the components the decided places are
// in, grouped by what one statement is about, with whether each is covered.
func everyPlaceOf(ctx context.Context, db bun.IDB, targetID int64,
	visible []access.Visibility, decided map[int64]coveredPlace) (map[statedGroup][]coveredPlace, error) {

	wanted := map[statedGroup]bool{}
	issues, components := map[int64]bool{}, map[int64]bool{}
	for _, one := range decided {
		wanted[statedGroup{one.vulnerabilityID, one.component, one.purl}] = true
		issues[one.vulnerabilityID] = true
		components[one.componentID] = true
	}
	var rows []statedPlace
	byIssue, issueArgs := database.InAnyOf("f.vulnerability_id", keysOf(issues))
	byComponent, componentArgs := database.InAnyOf("f.component_id", keysOf(components))
	if err := statedPlaceColumns(db.NewSelect()).
		Where("f.target_id = ?", targetID).
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("f.closed_at IS NULL").
		Where(byIssue, issueArgs...).
		Where(byComponent, componentArgs...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read every place of the components decided: %w", err)
	}
	out := map[statedGroup][]coveredPlace{}
	for _, row := range rows {
		g := statedGroup{row.VulnerabilityID, row.Component, row.Purl}
		if !wanted[g] {
			continue
		}
		one, ok := decided[row.FindingID]
		if !ok {
			one = row.place()
		}
		out[g] = append(out[g], one)
	}
	return out, nil
}

// keysOf is a set's members, in order.
func keysOf(set map[int64]bool) []int64 {
	out := make([]int64, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
