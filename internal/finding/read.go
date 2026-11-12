// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// Reading findings back, and the naming layer every other read here shares.
//
// The whole-target read, which product a build belongs to and what a subject
// may read of it, and the lookups that turn identifiers into names. The
// narrowing is in narrow.go, the page in groups.go, and what is open at one
// component in component.go.

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// productOf reads which product a build belongs to.
func productOf(ctx context.Context, db bun.IDB, buildID int64) (int64, error) {
	return catalog.NewStore(db).ProductOf(ctx, buildID)
}

// readableIn is the product a build belongs to and which visibilities this
// subject may read of its findings, refused where that is none.
//
// Every read of one build's findings starts here, so a subject who may read
// nothing in the product is refused by all of them alike rather than answered
// empty by some. Where the read is about one issue a collaborator may have
// been brought into, the caller asks access.ReadableOn instead.
func readableIn(ctx context.Context, db bun.IDB, subject access.Subject,
	buildID int64) (int64, []access.Visibility, error) {

	productID, err := productOf(ctx, db, buildID)
	if err != nil {
		return 0, nil, err
	}
	visible, err := access.Readable(subject, productID)
	if err != nil {
		return 0, nil, err
	}
	return productID, visible, nil
}

// issuesNamed reads what these issues are called and how bad they were
// published to be, as this subject may be told it.
//
// The published rating only. What a product says instead belongs to the
// product, so it is read alongside by whoever knows which product is being
// asked about and put on the copy the row shows (RatedIn). A description a
// flaw recorded out of the subject's reach wrote is left out.
func issuesNamed(ctx context.Context, db bun.IDB, subject access.Subject,
	ids []int64) (map[int64]Vulnerability, error) {
	held := map[int64]Vulnerability{}
	if len(ids) == 0 {
		return held, nil
	}
	var issues []Vulnerability
	if err := db.NewSelect().Model(&issues).
		// The description too, for the one line the row shows of it. One
		// lookup for the page either way, and the row is already being read
		// for the identifier beside it.
		Column("id", "identifier", "severity", "description").
		Where(`"id" IN (?)`, bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these issues are: %w", err)
	}
	withheld, err := RecordedOutOfReach(ctx, db, subject, ids)
	if err != nil {
		return nil, err
	}
	for _, issue := range issues {
		if withheld[issue.ID] {
			issue.WithholdRecorded()
		}
		held[issue.ID] = issue
	}
	return held, nil
}

// namedComponents is a page's components, each named as a build stated it.
type namedComponents struct {
	rows map[int64]graph.Component
	said statedBy
}

// at is the component as buildID stated it, and whether it was read.
func (n namedComponents) at(componentID, buildID int64) (graph.Component, bool) {
	c, held := n.rows[componentID]
	if !held {
		return c, false
	}
	return n.said.as(c, buildID), true
}

// inProduct is the component as the latest of the builds asked about stated
// it, and whether it was read, for a page over one product's builds.
func (n namedComponents) inProduct(componentID int64) (graph.Component, bool) {
	c, held := n.rows[componentID]
	if !held {
		return c, false
	}
	return n.said.asLatest(c), true
}

// componentsNamed reads what these components are, including the upstream they
// were cut from where one is known, with the name and version these builds
// stated for them.
func componentsNamed(ctx context.Context, db bun.IDB, ids, buildIDs []int64) (namedComponents, error) {
	rows, err := componentRows(ctx, db, ids)
	if err != nil {
		return namedComponents{}, err
	}
	said, err := statedNames(ctx, db, buildIDs, ids)
	if err != nil {
		return namedComponents{}, err
	}
	return namedComponents{rows: rows, said: said}, nil
}

// componentRows reads these components' rows.
func componentRows(ctx context.Context, db bun.IDB, ids []int64) (map[int64]graph.Component, error) {
	held := map[int64]graph.Component{}
	if len(ids) == 0 {
		return held, nil
	}
	var components []graph.Component
	if err := db.NewSelect().Model(&components).
		Column("id", "purl", "name", "version", "upstream_name", "upstream_version").
		Where(`"id" IN (?)`, bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these components are: %w", err)
	}
	for _, component := range components {
		held[component.ID] = component
	}
	return held, nil
}

// statedBy is the name and version builds stated for components, read off
// their open nodes. The component row holds what the first product to
// describe a package stated, so a row shown by its own name would show
// another product's words.
type statedBy struct {
	// pair is keyed by build, then component.
	pair map[[2]int64]graph.Component
	// latest is the node opened last among the builds asked about, for a page
	// whose rows span one product's builds and name none of them.
	latest map[int64]graph.Component
}

// statedNames reads what these builds stated these components are called and
// at which version: the open node's, else the build's latest node's, so a row
// closed since is named as its build last stated it, as graph.StatedName
// names it. A node holding neither predates the node holding them and is left
// out, so the row's stands.
func statedNames(ctx context.Context, db bun.IDB, buildIDs, componentIDs []int64) (statedBy, error) {
	said := statedBy{pair: map[[2]int64]graph.Component{}, latest: map[int64]graph.Component{}}
	if len(buildIDs) == 0 || len(componentIDs) == 0 {
		return said, nil
	}
	var rows []struct {
		ID          int64  `bun:"id"`
		BuildID     int64  `bun:"build_id"`
		ComponentID int64  `bun:"component_id"`
		Name        string `bun:"name"`
		Version     string `bun:"version"`
		Opened      int64  `bun:"opened_scan_id"`
		Closed      *int64 `bun:"closed_scan_id"`
	}
	if err := db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."id", "n"."build_id", "n"."component_id", "n"."name", "n"."version"`).
		ColumnExpr(`"n"."opened_scan_id", "n"."closed_scan_id"`).
		Where(`"n"."build_id" IN (?)`, bun.List(buildIDs)).
		Where(`"n"."component_id" IN (?)`, bun.List(componentIDs)).
		// Both values of the root flag, so the index led by the build, the
		// flag and the component answers it, as graph.BuildName's does.
		Where(`"n"."is_root" IN (FALSE, TRUE)`).
		Where(`"n"."name" IS NOT NULL`).
		Scan(ctx, &rows); err != nil {
		return said, fmt.Errorf("read what these builds call these components: %w", err)
	}
	// An open node outranks a closed one, then the later opened, then the
	// later written, which is the order graph.StatedName reads them in.
	type rank struct {
		open         bool
		opened, node int64
	}
	above := func(a, b rank) bool {
		if a.open != b.open {
			return a.open
		}
		if a.opened != b.opened {
			return a.opened > b.opened
		}
		return a.node > b.node
	}
	byPair := map[[2]int64]rank{}
	byComponent := map[int64]rank{}
	for _, row := range rows {
		named := graph.Component{Name: row.Name, Version: row.Version}
		at := rank{open: row.Closed == nil, opened: row.Opened, node: row.ID}
		pair := [2]int64{row.BuildID, row.ComponentID}
		if held, ok := byPair[pair]; !ok || above(at, held) {
			byPair[pair], said.pair[pair] = at, named
		}
		if held, ok := byComponent[row.ComponentID]; !ok || above(at, held) {
			byComponent[row.ComponentID], said.latest[row.ComponentID] = at, named
		}
	}
	return said, nil
}

// as is the component named as the build stated it, or as the row where the
// build holds no node stating it. Never another build's word: a page spans
// products, and another build's is another product's.
func (s statedBy) as(c graph.Component, buildID int64) graph.Component {
	if named, held := s.pair[[2]int64{buildID, c.ID}]; held {
		c.Name, c.Version = named.Name, named.Version
	}
	return c
}

// asLatest is the component named as the latest of the builds asked about
// stated it, or as the row. Only for builds of one product.
func (s statedBy) asLatest(c graph.Component) graph.Component {
	if named, held := s.latest[c.ID]; held {
		c.Name, c.Version = named.Name, named.Version
	}
	return c
}
