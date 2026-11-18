// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// What a build holds and where, as applying a scan and recording a flaw read
// it.

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// inventory is what a build currently contains, as far as findings care.
//
// byName is keyed on each component's identifying name, so a package that
// carries its version in its name is found under one name at every version.
type inventory struct {
	byID       map[int64]graph.Component
	byIdentity map[string]graph.Component
	byName     map[string][]graph.Component
}

// nameOf is the identifying name of a consumer, or nothing where the consumer
// is the product.
func (i inventory) nameOf(consumerID int64) string {
	if consumerID == 0 {
		return ""
	}
	return i.byID[consumerID].IdentifyingName()
}

// why explains a finding that is no longer reported, and says what it moved to
// where moving is the explanation.
//
// The component being gone, its upstream version having moved, and a
// downstream revision having landed are three different things to whoever
// reads the report later. What is left over — the component still present and
// unchanged, and the scanner no longer reporting it — is the case that must
// never be quietly dropped.
//
// The version returned alongside is what the occurrence moved to. It is available
// only here, because the component that carried the issue is gone from the
// inventory the moment this run is over, so anything asking later has one
// version and not two — which is why a release note could say a component was
// upgraded and never say to what.
func (i inventory) why(gone graph.Component) (Closure, string) {
	if _, present := i.byID[gone.ID]; present {
		return Unexplained, ""
	}
	for _, now := range i.byName[gone.IdentifyingName()] {
		switch {
		case upstreamOf(now) != upstreamOf(gone):
			return Upgraded, upstreamOf(now)
		case now.Version != gone.Version:
			return Revised, now.Version
		}
	}
	// Something of that name is still here, unchanged in both the version that
	// ships and the version vulnerabilities are matched against. Nothing about
	// the component explains the finding going away, so it is not explained.
	if len(i.byName[gone.IdentifyingName()]) > 0 {
		return Unexplained, ""
	}
	return Removed, ""
}

// pulledBy is what a build holds, by the identifying name of what pulls each
// component in and then by the component's own identifying name. A component
// nothing leads to sits under the empty name, as OccurrenceIdentity has it.
// Each list is in component identifier order.
type pulledBy map[string]map[string][]graph.Component

// pulled indexes the inventory by what pulls each component in.
func (i inventory) pulled(at consumers) pulledBy {
	out := pulledBy{}
	for _, id := range slices.Sorted(maps.Keys(i.byID)) {
		c := i.byID[id]
		name := c.IdentifyingName()
		for _, consumerID := range at.of(id) {
			consumer := i.nameOf(consumerID)
			if out[consumer] == nil {
				out[consumer] = map[string][]graph.Component{}
			}
			out[consumer][name] = append(out[consumer][name], c)
		}
	}
	return out
}

// whyAt explains a finding no longer reported at its occurrence: the thing
// that pulled the component in is asked what it pulls now under the
// component's identifying name. A finding is a component at an occurrence, so
// a version the same component keeps under another consumer explains nothing
// here.
//
// A consumer of nothing is the product itself, and is answered across the
// build, as why answers: a producer adding the edge that names what pulls a
// component in moves it off the product without anything changing.
//
// Several components of the name under one consumer are read in identifier
// order: the same component is unexplained, then the first at another
// upstream version is an upgrade to it, then the first at another shipped
// version is a revision to it.
//
// The same component now directly under the product, its consumer still
// there, is unexplained: a producer that stops naming what pulls a component
// in moves it onto the product with nothing changed, the mirror of the
// product's own case. A component that was its own consumer is the exception,
// since an edge from a component to itself places no occurrence.
func (i inventory) whyAt(gone graph.Component, consumerID int64, consumer string, under pulledBy) (Closure, string) {
	if consumerID == 0 {
		return i.why(gone)
	}
	if len(i.byName[consumer]) == 0 {
		return i.left(gone)
	}
	now := under[consumer][gone.IdentifyingName()]
	for _, c := range now {
		if c.ID == gone.ID {
			return Unexplained, ""
		}
	}
	for _, c := range now {
		if upstreamOf(c) != upstreamOf(gone) {
			return Upgraded, upstreamOf(c)
		}
	}
	for _, c := range now {
		if c.Version != gone.Version {
			return Revised, c.Version
		}
	}
	if len(now) > 0 {
		return Unexplained, ""
	}
	if consumerID != gone.ID && slices.ContainsFunc(under[""][gone.IdentifyingName()],
		func(c graph.Component) bool { return c.ID == gone.ID }) {
		return Unexplained, ""
	}
	return i.left(gone)
}

// left explains a component nothing of its name is under its consumer any
// more. Gone from the build with another version of its name in it, it was
// upgraded or revised, since a release note saying it no longer ships would
// be false; otherwise it left the occurrence.
func (i inventory) left(gone graph.Component) (Closure, string) {
	if reason, movedTo := i.why(gone); reason == Upgraded || reason == Revised {
		return reason, movedTo
	}
	return Removed, ""
}

// upstreamOf is the version a vulnerability is actually matched against: what
// a fork was made from, where there is one, and otherwise what shipped.
func upstreamOf(c graph.Component) string {
	if c.UpstreamVersion != "" {
		return c.UpstreamVersion
	}
	return c.Version
}

// componentsByID reads the components a set of a build's findings was about,
// with what the build stated for each of them.
//
// Each component is asked for once. A kernel's findings name one component
// thousands of times.
func componentsByID(ctx context.Context, db bun.IDB, buildID int64,
	components []int64) (map[int64]graph.Component, error) {
	if len(components) == 0 {
		return nil, nil
	}
	seen := make(map[int64]bool, len(components))
	ids := make([]int64, 0, len(components))
	for _, id := range components {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	byID := map[int64]graph.Component{}
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var rows []graph.Component
		if err := db.NewSelect().Model(&rows).Where(`"id" IN (?)`, bun.List(batch)).Scan(ctx); err != nil {
			return err
		}
		for _, row := range rows {
			byID[row.ID] = row
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read what closing findings were about: %w", err)
	}
	if err := withStated(ctx, db, buildID, byID); err != nil {
		return nil, err
	}
	return byID, nil
}

// withStated replaces each component's identifiers and source package with
// what the build stated for it, which is what its scanner was given. The row
// holds whichever report first described the component, in any product, so a
// claim matched against the row and a finding matched against the build's
// statement disagree.
func withStated(ctx context.Context, db bun.IDB, buildID int64, byID map[int64]graph.Component) error {
	ids := make([]int64, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	stated, err := graph.NewStore(db).Stated(ctx, buildID, ids)
	if err != nil {
		return err
	}
	for id, said := range stated {
		c, ok := byID[id]
		if !ok {
			continue
		}
		c.Purl, c.CPE = said.Purl, said.CPE
		c.UpstreamName, c.UpstreamVersion = said.UpstreamName, said.UpstreamVersion
		byID[id] = c
	}
	return nil
}

// openComponents reads what a variant contains at a moment.
func openComponents(ctx context.Context, db bun.IDB, buildID int64, at graph.Moment) (inventory, error) {
	holding, args := at.Held("n")
	var rows []graph.Component
	err := db.NewSelect().Model(&rows).
		Join(`JOIN "graph_node" AS "n" ON "n"."component_id" = "c"."id"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(holding, args...).
		Scan(ctx)
	if err != nil {
		return inventory{}, fmt.Errorf("read what the variant contains: %w", err)
	}
	stated := make(map[int64]graph.Component, len(rows))
	for _, row := range rows {
		stated[row.ID] = row
	}
	if err := withStated(ctx, db, buildID, stated); err != nil {
		return inventory{}, err
	}
	for i := range rows {
		rows[i] = stated[rows[i].ID]
	}

	held := inventory{
		byID:       make(map[int64]graph.Component, len(rows)),
		byIdentity: make(map[string]graph.Component, len(rows)),
		byName:     map[string][]graph.Component{},
	}
	for _, row := range rows {
		held.byID[row.ID] = row
		held.byIdentity[row.Identity] = row
		name := row.IdentifyingName()
		held.byName[name] = append(held.byName[name], row)
	}
	// A report names a component by what the scanner was given, hashed as
	// identity is read now. A component stored before then holds an identity
	// that description no longer hashes to, and is matched by the
	// description too; a stored identity is never displaced by one.
	scanned, err := graph.NewStore(db).ScannedAs(ctx, buildID, at)
	if err != nil {
		return inventory{}, err
	}
	for _, id := range slices.Sorted(maps.Keys(scanned)) {
		described := scanned[id]
		row, present := held.byID[id]
		if !present {
			continue
		}
		if _, taken := held.byIdentity[described.Identity()]; !taken {
			held.byIdentity[described.Identity()] = row
		}
	}
	return held, nil
}

// consumers maps a component to everything that directly pulled it in.
type consumers map[int64][]int64

// of returns where a component sits. A component nothing leads to still has an
// occurrence — itself — because it ships whether or not the producer could say
// what pulled it in.
func (c consumers) of(componentID int64) []int64 {
	if at, held := c[componentID]; held {
		return at
	}
	return []int64{0}
}

// openOccurrences reads every occurrence in a variant at a moment.
func openOccurrences(ctx context.Context, db bun.IDB, buildID int64, at graph.Moment) (consumers, error) {
	return occurrenceEdges(ctx, db, buildID, 0, at)
}

// sits is one occurrence of a component occupies: what pulls it in, by
// identifier and by identifying name. A component sitting directly under the
// build is pulled in by nothing and its consumer has no name, for the reason
// OccurrenceIdentity gives.
type sits struct {
	consumerID int64
	consumer   string
}

// sittingsOf reads where one component sits, with the identifying name of each
// thing that pulls it in.
//
// For a finding somebody records by hand: a person names a component and the
// occurrences are derived from the build's own graph, exactly as a scan's are.
// A component can sit at more than one occurrence at once, which is why the
// answer is a list — and which is why a form asking "where does it sit" could
// not express it.
func sittingsOf(ctx context.Context, db bun.IDB, buildID, componentID int64) ([]sits, error) {
	at, err := occurrenceEdges(ctx, db, buildID, componentID, graph.Now)
	if err != nil {
		return nil, err
	}
	ids := at.of(componentID)
	names, err := componentNames(ctx, db, ids)
	if err != nil {
		return nil, err
	}
	occurrences := make([]sits, 0, len(ids))
	for _, id := range ids {
		occurrences = append(occurrences, sits{consumerID: id, consumer: names[id]})
	}
	return occurrences, nil
}

// componentNames is the identifying name of each component by identifier,
// leaving out the one that is no component at all.
func componentNames(ctx context.Context, db bun.IDB, ids []int64) (map[int64]string, error) {
	wanted := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id != 0 {
			wanted = append(wanted, id)
		}
	}
	names := map[int64]string{}
	if len(wanted) == 0 {
		return names, nil
	}
	var rows []graph.Component
	if err := db.NewSelect().Model(&rows).
		Column("id", "name", "version", "purl").
		Where(`"c"."id" IN (?)`, bun.List(wanted)).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what pulls it in: %w", err)
	}
	for _, row := range rows {
		names[row.ID] = row.IdentifyingName()
	}
	return names, nil
}

// occurrenceEdges reads where things sit in a variant, all of them or one of
// them.
//
// A component under the product itself is recorded as being under nothing: the
// product's name differs per variant, so keying on it would stop the same
// occurrence being recognized across them.
func occurrenceEdges(ctx context.Context, db bun.IDB, buildID, componentID int64,
	moment graph.Moment) (consumers, error) {
	held, args := moment.Held("e")
	var edges []struct {
		ChildComponentID  int64 `bun:"child_component_id"`
		ParentComponentID int64 `bun:"parent_component_id"`
		ParentIsRoot      bool  `bun:"parent_is_root"`
	}
	err := db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "child" ON "child"."id" = "e"."child_id"`).
		Join(`JOIN "graph_node" AS "parent" ON "parent"."id" = "e"."parent_id"`).
		ColumnExpr(`"child"."component_id" AS "child_component_id"`).
		ColumnExpr(`"parent"."component_id" AS "parent_component_id"`).
		ColumnExpr(`"parent"."is_root" AS "parent_is_root"`).
		Where(`"e"."build_id" = ?`, buildID).
		// An edge from a component to itself pulls in nothing, as the walks
		// read it, so it places no occurrence.
		Where(`"e"."parent_id" <> "e"."child_id"`).
		Where(held, args...).
		Apply(func(q *bun.SelectQuery) *bun.SelectQuery {
			if componentID == 0 {
				return q
			}
			return q.Where(`"child"."component_id" = ?`, componentID)
		}).
		Scan(ctx, &edges)
	if err != nil {
		return nil, fmt.Errorf("read where things sit: %w", err)
	}

	at := consumers{}
	seen := map[[2]int64]bool{}
	for _, e := range edges {
		consumer := e.ParentComponentID
		if e.ParentIsRoot {
			consumer = 0
		}
		pair := [2]int64{e.ChildComponentID, consumer}
		if seen[pair] {
			continue
		}
		seen[pair] = true
		at[e.ChildComponentID] = append(at[e.ChildComponentID], consumer)
	}
	return at, nil
}
