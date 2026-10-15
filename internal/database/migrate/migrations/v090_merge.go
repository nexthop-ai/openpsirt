// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"
)

// The rows v0.8.0 holds for container images, moved to an image identified by
// its name.
//
// v0.8.0 identified an image by its package identifier, version included, so
// every build stamping its images anew made a component per image per build,
// a node for each, and closed every edge and finding beneath the one before.
// v0.9.0 identifies an image by its name and keeps each build's version in the
// image version table. This merges what v0.8.0 made into that shape.
//
// Everything here is written for this migration and frozen with it: how an
// identity, a fold key and a decision's live key are worked out is copied
// rather than called, so a later change to the application does not change
// what a database v0.8.0 built is upgraded into.
//
// An image is recognized by its package identifier alone, of type oci or
// docker. v0.8.0 kept nothing saying the format called a component a
// container, so an image stated with no identifier is not recognized here; the
// next upload of each build stores it by name, once, as a version moving would.

// imageRowV090 is one component v0.8.0 stored for an image.
type imageRowV090 struct {
	ID              int64  `bun:"id"`
	Identity        string `bun:"identity"`
	Purl            string `bun:"purl"`
	Name            string `bun:"name"`
	Version         string `bun:"version"`
	UpstreamName    string `bun:"upstream_name"`
	UpstreamVersion string `bun:"upstream_version"`
	FoldKey         string `bun:"fold_key"`
	Supplier        string `bun:"supplier"`
	License         string `bun:"license"`
	CPE             string `bun:"cpe"`
}

// nodeRowV090 is one node of an image.
type nodeRowV090 struct {
	ID           int64  `bun:"id"`
	TargetID     int64  `bun:"target_id"`
	ComponentID  int64  `bun:"component_id"`
	IsRoot       bool   `bun:"is_root"`
	OpenedScanID int64  `bun:"opened_scan_id"`
	ClosedScanID *int64 `bun:"closed_scan_id"`
	Purl         string `bun:"purl"`
}

// imageVersionRowV090 is a row of the image version table as this migration
// writes it.
type imageVersionRowV090 struct {
	bun.BaseModel `bun:"table:image_version"`

	NodeID       int64   `bun:"node_id"`
	Version      string  `bun:"version"`
	Purl         *string `bun:"purl"`
	OpenedScanID int64   `bun:"opened_scan_id"`
	ClosedScanID *int64  `bun:"closed_scan_id"`
}

// mergeImagesV090 merges the components v0.8.0 made per version of one image
// into one component per name, and points everything that pointed at them at
// it.
//
// Every build's row is taken first: it is the lock a scan's apply and a run's
// apply take, so on a server another replica still running the release before
// waits for this rather than writing a graph part way through it.
//
// A name some build held at two versions at once is left as it is. Those are
// two images side by side, which v0.9.0 also keeps apart by version.
func mergeImagesV090(ctx context.Context, tx bun.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE "target" SET "last_scan_id" = "last_scan_id"`); err != nil {
		return fmt.Errorf("hold every build: %w", err)
	}
	var rows []imageRowV090
	if err := tx.NewSelect().TableExpr(`"component" AS "c"`).
		ColumnExpr(`"c"."id", "c"."identity", "c"."purl", "c"."name", "c"."version"`).
		ColumnExpr(`COALESCE("c"."upstream_name", '') AS "upstream_name"`).
		ColumnExpr(`COALESCE("c"."upstream_version", '') AS "upstream_version"`).
		ColumnExpr(`"c"."fold_key"`).
		ColumnExpr(`COALESCE("c"."supplier", '') AS "supplier"`).
		ColumnExpr(`COALESCE("c"."license", '') AS "license"`).
		ColumnExpr(`COALESCE("c"."cpe", '') AS "cpe"`).
		Where(`"c"."purl" IS NOT NULL`).
		OrderExpr(`"c"."id"`).
		Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read the components with an identifier: %w", err)
	}
	groups := map[string][]imageRowV090{}
	for _, row := range rows {
		if !imageTypesV090[purlTypeV090(row.Purl)] {
			continue
		}
		key := identityV090(withoutVersionV090(row.Purl))
		groups[key] = append(groups[key], row)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	m := &mergerV090{ctx: ctx, tx: tx, now: time.Now().UTC().Truncate(time.Microsecond),
		survivors: map[int64][]int64{}, merged: map[int64]int64{}}
	var all []int64
	for _, key := range keys {
		for _, row := range groups[key] {
			all = append(all, row.ID)
		}
	}
	if err := m.readPlaces(all); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.merge(key, groups[key]); err != nil {
			return err
		}
	}
	if err := m.joinEdges(); err != nil {
		return err
	}
	return m.moveFindings()
}

// readPlaces reads every place a finding against or beneath one of these
// components sits at.
func (m *mergerV090) readPlaces(ids []int64) error {
	for from := 0; from < len(ids); from += 500 {
		batch := ids[from:min(from+500, len(ids))]
		var some []placeV090
		if err := m.tx.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
			Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
			ColumnExpr(`"st"."product_id", "f"."place_identity", "f"."component_id", "f"."consumer_id"`).
			WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
				return q.Where(`"f"."component_id" IN (?)`, bun.List(batch)).
					WhereOr(`"f"."consumer_id" IN (?)`, bun.List(batch))
			}).
			Distinct().
			Scan(m.ctx, &some); err != nil {
			return fmt.Errorf("read the places beneath the images: %w", err)
		}
		m.places = append(m.places, some...)
	}
	return nil
}

// moveFindings points every finding against or beneath a merged component at
// the component it was merged into, and removes the merged ones: nothing
// points at them any more.
func (m *mergerV090) moveFindings() error {
	gone := make([]int64, 0, len(m.merged))
	for id := range m.merged {
		gone = append(gone, id)
	}
	slices.Sort(gone)
	for from := 0; from < len(gone); from += 250 {
		batch := gone[from:min(from+250, len(gone))]
		for _, column := range []string{"component_id", "consumer_id"} {
			becomes := "CASE " + `"` + column + `"` + strings.Repeat(" WHEN ? THEN ?", len(batch)) + " END"
			args := make([]any, 0, 2*len(batch))
			for _, id := range batch {
				args = append(args, id, m.merged[id])
			}
			if _, err := m.tx.NewUpdate().Table("finding").
				Set(`? = `+becomes, append([]any{bun.Ident(column)}, args...)...).
				Where(`? IN (?)`, bun.Ident(column), bun.List(batch)).
				Exec(m.ctx); err != nil {
				return fmt.Errorf("point the findings at the merged images: %w", err)
			}
		}
		if _, err := m.tx.NewDelete().Table("component").
			Where(`"id" IN (?)`, bun.List(batch)).
			Exec(m.ctx); err != nil {
			return fmt.Errorf("remove the components merged into one: %w", err)
		}
	}
	return nil
}

type mergerV090 struct {
	ctx context.Context
	tx  bun.Tx
	now time.Time
	// survivors is the nodes each build kept, whose edges are joined once
	// every image is merged: an edge can run between two of them.
	survivors map[int64][]int64
	// places is every place a finding against or beneath an image sits at,
	// read once for every image rather than once per image: the finding
	// table is the largest there is, and nothing indexes it by component
	// alone.
	places []placeV090
	// merged is the component each merged one is now, and the findings
	// pointing at it are moved together once every image is merged, for the
	// same reason.
	merged map[int64]int64
}

// placeV090 is one place a finding sits at, in its product.
type placeV090 struct {
	ProductID     int64  `bun:"product_id"`
	PlaceIdentity string `bun:"place_identity"`
	ComponentID   int64  `bun:"component_id"`
	ConsumerID    *int64 `bun:"consumer_id"`
}

// merge moves one image's components onto one.
func (m *mergerV090) merge(key string, group []imageRowV090) error {
	ids := make([]int64, 0, len(group))
	for _, row := range group {
		ids = append(ids, row.ID)
	}
	var nodes []nodeRowV090
	if err := m.tx.NewSelect().TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."id", "n"."target_id", "n"."component_id", "n"."is_root", "n"."opened_scan_id", "n"."closed_scan_id"`).
		ColumnExpr(`COALESCE("n"."purl", '') AS "purl"`).
		Where(`"n"."component_id" IN (?)`, bun.List(ids)).
		OrderExpr(`"n"."target_id", "n"."opened_scan_id", "n"."id"`).
		Scan(m.ctx, &nodes); err != nil {
		return fmt.Errorf("read the nodes of %s: %w", group[0].Name, err)
	}
	if sideBySideV090(nodes) {
		return nil
	}
	survivor := group[0]
	for _, row := range group {
		if row.Identity == key {
			survivor = row
		}
	}
	if len(group) == 1 && survivor.Identity == key && survivor.Version == "" &&
		strings.TrimSpace(survivor.Purl) == withoutVersionV090(survivor.Purl) && !anyStampedV090(nodes) {
		return nil
	}
	versionOf := map[int64]string{}
	for _, row := range group {
		versionOf[row.ID] = row.Version
	}

	stored := survivor
	stored.Identity, stored.Version = key, ""
	stored.Purl = withoutVersionV090(survivor.Purl)
	for _, row := range group {
		if stored.Supplier == "" {
			stored.Supplier = row.Supplier
		}
		if stored.License == "" {
			stored.License = row.License
		}
		if stored.CPE == "" {
			stored.CPE = row.CPE
		}
	}
	stored.FoldKey = foldKeyV090(stored)

	if err := m.rekeyDecisions(group, stored); err != nil {
		return err
	}
	if err := m.rekeyCommitments(group, stored); err != nil {
		return err
	}

	var others []int64
	for _, id := range ids {
		if id != survivor.ID {
			others = append(others, id)
		}
	}
	if _, err := m.tx.NewUpdate().Table("component").
		Set(`"identity" = ?`, key).
		Set(`"version" = ?`, "").
		Set(`"purl" = ?`, stored.Purl).
		Set(`"fold_key" = ?`, stored.FoldKey).
		Set(`"supplier" = ?`, nullableV090(stored.Supplier)).
		Set(`"license" = ?`, nullableV090(stored.License)).
		Set(`"cpe" = ?`, nullableV090(stored.CPE)).
		Where(`"id" = ?`, survivor.ID).
		Exec(m.ctx); err != nil {
		return fmt.Errorf("store %s by its name: %w", survivor.Name, err)
	}
	if err := m.moveNodes(nodes, survivor.ID, versionOf); err != nil {
		return err
	}
	if len(others) == 0 {
		return nil
	}
	for _, id := range others {
		m.merged[id] = survivor.ID
	}
	return m.moveTags(ids, survivor.ID)
}

// sideBySideV090 reports whether a build held two of these nodes at once.
func sideBySideV090(nodes []nodeRowV090) bool {
	for i := 1; i < len(nodes); i++ {
		before, at := nodes[i-1], nodes[i]
		if before.TargetID != at.TargetID {
			continue
		}
		if before.ClosedScanID == nil || at.OpenedScanID < *before.ClosedScanID {
			return true
		}
	}
	for _, n := range nodes {
		if n.IsRoot {
			// A root is stored by its name already, and is no image here.
			return true
		}
	}
	return false
}

// anyStampedV090 reports whether a node states a version in its identifier.
func anyStampedV090(nodes []nodeRowV090) bool {
	for _, n := range nodes {
		if n.Purl != "" && withoutVersionV090(n.Purl) != strings.TrimSpace(n.Purl) {
			return true
		}
	}
	return false
}

// moveNodes points an image's nodes at the merged component, joins the nodes
// of one build whose intervals meet into one, and records each node's version
// as a version the build stated.
//
// A node v0.8.0 closed at the scan that opened the next one is the same image
// rebuilt, so the two are one node across both intervals. A gap between them
// is the image leaving the build and coming back, which stays two nodes.
func (m *mergerV090) moveNodes(nodes []nodeRowV090, survivor int64, versionOf map[int64]string) error {
	var history []imageVersionRowV090
	for start := 0; start < len(nodes); {
		end := start + 1
		for end < len(nodes) && nodes[end].TargetID == nodes[start].TargetID &&
			nodes[end-1].ClosedScanID != nil && nodes[end].OpenedScanID == *nodes[end-1].ClosedScanID {
			end++
		}
		chain := nodes[start:end]
		kept, last := chain[0], chain[len(chain)-1]
		for _, n := range chain {
			version := strings.TrimSpace(versionOf[n.ComponentID])
			var purl *string
			if p := strings.TrimSpace(n.Purl); p != "" {
				purl = &p
			}
			history = append(history, imageVersionRowV090{
				NodeID: kept.ID, Version: version, Purl: purl,
				OpenedScanID: n.OpenedScanID, ClosedScanID: n.ClosedScanID,
			})
		}
		if _, err := m.tx.NewUpdate().Table("graph_node").
			Set(`"component_id" = ?`, survivor).
			Set(`"closed_scan_id" = ?`, last.ClosedScanID).
			Set(`"purl" = ?`, nullableV090(withoutVersionV090(last.Purl))).
			Where(`"id" = ?`, kept.ID).
			Exec(m.ctx); err != nil {
			return fmt.Errorf("point a node at its image: %w", err)
		}
		var joined []int64
		for _, n := range chain[1:] {
			joined = append(joined, n.ID)
		}
		if len(joined) > 0 {
			for _, column := range []string{"parent_id", "child_id"} {
				if _, err := m.tx.NewUpdate().Table("graph_edge").
					Set(`? = ?`, bun.Ident(column), kept.ID).
					Where(`? IN (?)`, bun.Ident(column), bun.List(joined)).
					Exec(m.ctx); err != nil {
					return fmt.Errorf("point an image's edges at its node: %w", err)
				}
			}
			if _, err := m.tx.NewDelete().Table("graph_node").
				Where(`"id" IN (?)`, bun.List(joined)).
				Exec(m.ctx); err != nil {
				return fmt.Errorf("remove the nodes joined into one: %w", err)
			}
		}
		m.survivors[kept.TargetID] = append(m.survivors[kept.TargetID], kept.ID)
		start = end
	}
	if len(history) == 0 {
		return nil
	}
	if _, err := m.tx.NewInsert().Model(&history).Exec(m.ctx); err != nil {
		return fmt.Errorf("record the versions each build stated: %w", err)
	}
	return nil
}

// joinEdges joins the edges of each build that meet end to end once their
// nodes are one: an edge closed at the scan the same edge opened again is one
// edge across both.
func (m *mergerV090) joinEdges() error {
	targets := make([]int64, 0, len(m.survivors))
	for target := range m.survivors {
		targets = append(targets, target)
	}
	slices.Sort(targets)
	for _, target := range targets {
		kept := m.survivors[target]
		var edges []struct {
			ID           int64  `bun:"id"`
			ParentID     int64  `bun:"parent_id"`
			ChildID      int64  `bun:"child_id"`
			Kind         string `bun:"kind"`
			OpenedScanID int64  `bun:"opened_scan_id"`
			ClosedScanID *int64 `bun:"closed_scan_id"`
		}
		if err := m.tx.NewSelect().TableExpr(`"graph_edge" AS "e"`).
			ColumnExpr(`"e"."id", "e"."parent_id", "e"."child_id", "e"."kind", "e"."opened_scan_id", "e"."closed_scan_id"`).
			Where(`"e"."target_id" = ?`, target).
			WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
				return q.Where(`"e"."parent_id" IN (?)`, bun.List(kept)).
					WhereOr(`"e"."child_id" IN (?)`, bun.List(kept))
			}).
			OrderExpr(`"e"."parent_id", "e"."child_id", "e"."kind", "e"."opened_scan_id", "e"."id"`).
			Scan(m.ctx, &edges); err != nil {
			return fmt.Errorf("read the edges of a build's images: %w", err)
		}
		var gone []int64
		for start := 0; start < len(edges); {
			end := start + 1
			for end < len(edges) && edges[end].ParentID == edges[start].ParentID &&
				edges[end].ChildID == edges[start].ChildID && edges[end].Kind == edges[start].Kind &&
				edges[end-1].ClosedScanID != nil && edges[end].OpenedScanID == *edges[end-1].ClosedScanID {
				gone = append(gone, edges[end].ID)
				end++
			}
			if end-start > 1 {
				if _, err := m.tx.NewUpdate().Table("graph_edge").
					Set(`"closed_scan_id" = ?`, edges[end-1].ClosedScanID).
					Where(`"id" = ?`, edges[start].ID).
					Exec(m.ctx); err != nil {
					return fmt.Errorf("join an image's edges: %w", err)
				}
			}
			start = end
		}
		for from := 0; from < len(gone); from += 500 {
			to := min(from+500, len(gone))
			if _, err := m.tx.NewDelete().Table("graph_edge").
				Where(`"id" IN (?)`, bun.List(gone[from:to])).
				Exec(m.ctx); err != nil {
				return fmt.Errorf("remove the edges joined into one: %w", err)
			}
		}
	}
	return nil
}

// moveTags points the tags on an image's findings at the merged component. A
// tag is one per product, issue, component and name, so where two of the
// merged components carried the same one, the first added is kept.
func (m *mergerV090) moveTags(ids []int64, survivor int64) error {
	var tags []struct {
		ID              int64  `bun:"id"`
		ProductID       int64  `bun:"product_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Tag             string `bun:"tag"`
	}
	if err := m.tx.NewSelect().TableExpr(`"finding_tag" AS "ft"`).
		ColumnExpr(`"ft"."id", "ft"."product_id", "ft"."vulnerability_id", "ft"."tag"`).
		Where(`"ft"."component_id" IN (?)`, bun.List(ids)).
		OrderExpr(`"ft"."added_at", "ft"."id"`).
		Scan(m.ctx, &tags); err != nil {
		return fmt.Errorf("read the tags on an image's findings: %w", err)
	}
	seen := map[string]bool{}
	var keep, drop []int64
	for _, tag := range tags {
		key := fmt.Sprintf("%d\x00%d\x00%s", tag.ProductID, tag.VulnerabilityID, tag.Tag)
		if seen[key] {
			drop = append(drop, tag.ID)
			continue
		}
		seen[key] = true
		keep = append(keep, tag.ID)
	}
	if len(drop) > 0 {
		if _, err := m.tx.NewDelete().Table("finding_tag").
			Where(`"id" IN (?)`, bun.List(drop)).Exec(m.ctx); err != nil {
			return fmt.Errorf("remove a tag the merged image carried twice: %w", err)
		}
	}
	if len(keep) > 0 {
		if _, err := m.tx.NewUpdate().Table("finding_tag").
			Set(`"component_id" = ?`, survivor).
			Where(`"id" IN (?)`, bun.List(keep)).Exec(m.ctx); err != nil {
			return fmt.Errorf("point the tags at the merged image: %w", err)
		}
	}
	return nil
}

// rekeyDecisions moves the live decisions keyed on an image's version to the
// version the merged image carries, which is none.
//
// A decision is keyed on the place and on the upstream versions of the
// component and of what pulls it in. A finding beneath an image has the image
// as what pulls it in, so every decision about one was keyed on that image's
// build stamp, and would stop matching the moment the image is stored without
// it. Only live decisions move: one already ended is history, and stays as it
// was recorded.
//
// Two live decisions that differed only in that stamp become one claim about
// one place. The approved one stays live over one only proposed, and the one
// proposed last over an earlier one; the other lapses, as a sweep lapses a
// decision the code moved out from under.
func (m *mergerV090) rekeyDecisions(group []imageRowV090, stored imageRowV090) error {
	old := map[int64]string{}
	for _, row := range group {
		old[row.ID] = upstreamOfV090(row)
	}
	becomes := upstreamOfV090(stored)

	type at struct {
		product int64
		place   string
	}
	component, consumer := map[at]map[string]bool{}, map[at]map[string]bool{}
	for _, p := range m.places {
		k := at{p.ProductID, p.PlaceIdentity}
		if _, ok := old[p.ComponentID]; ok {
			if component[k] == nil {
				component[k] = map[string]bool{}
			}
			component[k][old[p.ComponentID]] = true
		}
		if p.ConsumerID != nil {
			if v, ok := old[*p.ConsumerID]; ok {
				if consumer[k] == nil {
					consumer[k] = map[string]bool{}
				}
				consumer[k][v] = true
			}
		}
	}
	keys := map[at]bool{}
	for k := range component {
		keys[k] = true
	}
	for k := range consumer {
		keys[k] = true
	}
	if len(keys) == 0 {
		return nil
	}

	type decided struct {
		ID              int64     `bun:"id"`
		ProductID       int64     `bun:"product_id"`
		VulnerabilityID int64     `bun:"vulnerability_id"`
		PlaceIdentity   string    `bun:"place_identity"`
		Component       string    `bun:"component"`
		Consumer        string    `bun:"consumer"`
		LiveKey         *string   `bun:"live_key"`
		State           string    `bun:"state"`
		ProposedAt      time.Time `bun:"proposed_at"`
	}
	type moved struct {
		decided
		component, consumer, key string
	}
	// Read a product at a time, its places a batch at a time. No index on
	// the decisions leads with the place, so a read per place is a read of
	// the product's decisions per place.
	byProduct := map[int64][]string{}
	for k := range keys {
		byProduct[k.product] = append(byProduct[k.product], k.place)
	}
	var live []decided
	for product, places := range byProduct {
		slices.Sort(places)
		for from := 0; from < len(places); from += 500 {
			var rows []decided
			if err := m.tx.NewSelect().TableExpr(`"decision" AS "de"`).
				ColumnExpr(`"de"."id", "de"."product_id", "de"."vulnerability_id", "de"."place_identity", "de"."live_key", "de"."state"`).
				ColumnExpr(`"de"."proposed_at"`).
				ColumnExpr(`COALESCE("de"."component_upstream_version", '') AS "component"`).
				ColumnExpr(`COALESCE("de"."consumer_upstream_version", '') AS "consumer"`).
				Where(`"de"."product_id" = ?`, product).
				Where(`"de"."place_identity" IN (?)`, bun.List(places[from:min(from+500, len(places))])).
				Where(`"de"."live_key" IS NOT NULL`).
				Scan(m.ctx, &rows); err != nil {
				return fmt.Errorf("read the decisions beneath %s: %w", stored.Name, err)
			}
			live = append(live, rows...)
		}
	}
	var changes []moved
	for _, row := range live {
		k := at{row.ProductID, row.PlaceIdentity}
		c, u := strings.TrimSpace(row.Component), strings.TrimSpace(row.Consumer)
		nc, nu := c, u
		if component[k][c] {
			nc = becomes
		}
		if consumer[k][u] {
			nu = becomes
		}
		if nc == c && nu == u {
			continue
		}
		key := *row.LiveKey
		if key == liveKeyV090(row.ProductID, row.VulnerabilityID, row.PlaceIdentity, c, u) {
			key = liveKeyV090(row.ProductID, row.VulnerabilityID, row.PlaceIdentity, nc, nu)
		}
		changes = append(changes, moved{decided: row, component: nc, consumer: nu, key: key})
	}
	if len(changes) == 0 {
		return nil
	}

	// Who holds each key once this is done: the decisions moving to it and
	// any decision already holding it.
	moving := map[int64]bool{}
	wanted := map[string]bool{}
	for _, c := range changes {
		moving[c.ID] = true
		wanted[c.key] = true
	}
	keyList := make([]string, 0, len(wanted))
	for k := range wanted {
		keyList = append(keyList, k)
	}
	slices.Sort(keyList)
	var holding []decided
	for from := 0; from < len(keyList); from += 500 {
		var some []decided
		if err := m.tx.NewSelect().TableExpr(`"decision" AS "de"`).
			ColumnExpr(`"de"."id", "de"."live_key", "de"."state", "de"."proposed_at"`).
			Where(`"de"."live_key" IN (?)`, bun.List(keyList[from:min(from+500, len(keyList))])).
			Scan(m.ctx, &some); err != nil {
			return fmt.Errorf("read the decisions already keyed there: %w", err)
		}
		holding = append(holding, some...)
	}
	type claimant struct {
		id       int64
		approved bool
		proposed time.Time
	}
	// Approved over proposed, then the one proposed last, then the later
	// row: the order a settled decision is read in.
	outranks := func(a, b claimant) bool {
		if a.approved != b.approved {
			return a.approved
		}
		if !a.proposed.Equal(b.proposed) {
			return a.proposed.After(b.proposed)
		}
		return a.id > b.id
	}
	by := map[string][]claimant{}
	for _, h := range holding {
		if !moving[h.ID] {
			by[*h.LiveKey] = append(by[*h.LiveKey], claimant{h.ID, h.State == "approved", h.ProposedAt})
		}
	}
	for _, c := range changes {
		by[c.key] = append(by[c.key], claimant{c.ID, c.State == "approved", c.ProposedAt})
	}
	lapsing := map[int64]bool{}
	for _, held := range by {
		if len(held) < 2 {
			continue
		}
		best := held[0]
		for _, h := range held[1:] {
			if outranks(h, best) {
				best = h
			}
		}
		for _, h := range held {
			if h.id != best.id {
				lapsing[h.id] = true
			}
		}
	}
	if len(lapsing) > 0 {
		lapsed := make([]int64, 0, len(lapsing))
		for id := range lapsing {
			lapsed = append(lapsed, id)
		}
		if _, err := m.tx.NewUpdate().Table("decision").
			Set(`"state" = ?`, "lapsed").
			Set(`"ended_at" = ?`, m.now).
			Set(`"live_key" = NULL`).
			Where(`"id" IN (?)`, bun.List(lapsed)).
			Exec(m.ctx); err != nil {
			return fmt.Errorf("lapse a decision the merged image made a second claim: %w", err)
		}
	}
	for _, c := range changes {
		q := m.tx.NewUpdate().Table("decision").
			Set(`"component_upstream_version" = ?`, nullableV090(c.component)).
			Set(`"consumer_upstream_version" = ?`, nullableV090(c.consumer)).
			Where(`"id" = ?`, c.ID)
		if !lapsing[c.ID] {
			q = q.Set(`"live_key" = ?`, c.key)
		}
		if _, err := q.Exec(m.ctx); err != nil {
			return fmt.Errorf("key a decision on the merged image: %w", err)
		}
	}
	return nil
}

// rekeyCommitments moves the upgrade commitments made on an image's fold to
// the fold of the merged image. A build already committed on it keeps that
// commitment, and one build committed on two of the old folds keeps the first.
func (m *mergerV090) rekeyCommitments(group []imageRowV090, stored imageRowV090) error {
	var folds []string
	for _, row := range group {
		if row.FoldKey != stored.FoldKey {
			folds = append(folds, row.FoldKey)
		}
	}
	if len(folds) == 0 {
		return nil
	}
	var committed []struct {
		ID       int64 `bun:"id"`
		TargetID int64 `bun:"target_id"`
	}
	if err := m.tx.NewSelect().TableExpr(`"upgrade" AS "ug"`).
		ColumnExpr(`"ug"."id", "ug"."target_id"`).
		Where(`"ug"."fold_key" IN (?)`, bun.List(folds)).
		OrderExpr(`"ug"."id"`).
		Scan(m.ctx, &committed); err != nil {
		return fmt.Errorf("read the commitments on %s: %w", stored.Name, err)
	}
	for _, one := range committed {
		already, err := m.tx.NewSelect().TableExpr(`"upgrade" AS "ug"`).
			Where(`"ug"."target_id" = ?`, one.TargetID).
			Where(`"ug"."fold_key" = ?`, stored.FoldKey).
			Exists(m.ctx)
		if err != nil {
			return fmt.Errorf("read what a build commits on %s: %w", stored.Name, err)
		}
		if already {
			if _, err := m.tx.NewDelete().Table("upgrade").Where(`"id" = ?`, one.ID).Exec(m.ctx); err != nil {
				return fmt.Errorf("remove a commitment the merged image holds already: %w", err)
			}
			continue
		}
		if _, err := m.tx.NewUpdate().Table("upgrade").
			Set(`"fold_key" = ?`, stored.FoldKey).
			Where(`"id" = ?`, one.ID).Exec(m.ctx); err != nil {
			return fmt.Errorf("move a commitment to the merged image: %w", err)
		}
	}
	return nil
}

func nullableV090(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

// imageTypesV090 are the package identifier types that name a container
// image.
var imageTypesV090 = map[string]bool{"oci": true, "docker": true}

// purlTypeV090 is a package identifier's type, lowercased, or nothing where
// the identifier is not one.
func purlTypeV090(purl string) string {
	purl = strings.TrimSpace(purl)
	if cut := strings.IndexAny(purl, "?#"); cut >= 0 {
		purl = purl[:cut]
	}
	scheme, rest, found := strings.Cut(purl, ":")
	if !found || !strings.EqualFold(scheme, "pkg") {
		return ""
	}
	segments := strings.Split(strings.Trim(rest, "/"), "/")
	if len(segments) < 2 {
		return ""
	}
	return strings.ToLower(decodedV090(segments[0]))
}

// withoutVersionV090 cuts the version from a package identifier and keeps the
// rest as written.
func withoutVersionV090(purl string) string {
	purl = strings.TrimSpace(purl)
	end := len(purl)
	if cut := strings.IndexAny(purl, "?#"); cut >= 0 {
		end = cut
	}
	at := strings.LastIndex(purl[:end], "@")
	if at <= 0 || purl[at-1] == '/' {
		return purl
	}
	return purl[:at] + purl[end:]
}

// identityV090 is a component's identity from its package identifier:
// qualifiers and subpath dropped, escapes decoded, scheme and type lowercased,
// hashed under the mark that says it is an identifier.
func identityV090(purl string) string {
	purl = strings.TrimSpace(purl)
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	basis := decodedV090(purl)
	if scheme, rest, found := strings.Cut(purl, ":"); found {
		if kind, path, split := strings.Cut(rest, "/"); split {
			basis = strings.ToLower(scheme) + ":" + strings.ToLower(kind) + "/" + decodedV090(path)
		} else {
			basis = strings.ToLower(scheme) + ":" + decodedV090(rest)
		}
	}
	sum := sha256.Sum256([]byte("purl\x00" + basis))
	return hex.EncodeToString(sum[:])
}

func decodedV090(s string) string {
	unescaped, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return unescaped
}

// foldKeyV090 is the key the binaries of one source package share: the
// package type, the distribution release, the source package and the version
// it was built at, each folded, hashed together.
func foldKeyV090(row imageRowV090) string {
	kind := purlTypeV090(row.Purl)
	distro := ""
	osName, osVersion, stated := "", "", false
	if _, q, found := strings.Cut(strings.SplitN(row.Purl, "#", 2)[0], "?"); found {
		for _, pair := range strings.Split(q, "&") {
			key, value, ok := strings.Cut(pair, "=")
			switch {
			case !ok:
			case strings.EqualFold(key, "distro"):
				distro, stated = decodedV090(value), true
			case strings.EqualFold(key, "os_name"):
				osName = decodedV090(value)
			case strings.EqualFold(key, "os_version"):
				osVersion = decodedV090(value)
			}
		}
	}
	if !stated && osName != "" && osVersion != "" {
		distro = strings.ToLower(osName) + "-" + osVersion
	}
	name, version := row.UpstreamName, row.UpstreamVersion
	if strings.TrimSpace(name) == "" {
		name = row.Name
	}
	if strings.TrimSpace(version) == "" {
		version = row.Version
	}
	basis := strings.Join([]string{foldedV090(kind), foldedV090(distro), foldedV090(name), foldedV090(version)}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// foldedV090 is a name lowered and cut to the width of an indexed name
// column, in characters.
func foldedV090(name string) string {
	const width = 191
	folded := strings.ToLower(strings.TrimSpace(name))
	if utf8.RuneCountInString(folded) <= width {
		return folded
	}
	return string([]rune(folded)[:width])
}

// upstreamOfV090 is the version a decision is keyed on for a component: what
// it was built from where stated, and otherwise its own.
func upstreamOfV090(row imageRowV090) string {
	if v := strings.TrimSpace(row.UpstreamVersion); v != "" {
		return v
	}
	return strings.TrimSpace(row.Version)
}

// liveKeyV090 is the key a live decision about versions is held under.
func liveKeyV090(product, issue int64, place, component, consumer string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strconv.FormatInt(product, 10), strconv.FormatInt(issue, 10), place,
		strings.TrimSpace(component), strings.TrimSpace(consumer),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}
