// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// Node is a component's presence in a variant.
//
// The graph is a graph, not a tree. A component reached by several parents is
// one node with several edges, not one node per route. Enumerating routes is a
// separate question, left until real data can say how much a real graph
// shares.
type Node struct {
	bun.BaseModel `bun:"table:graph_node,alias:n"`

	ID           int64  `bun:"id,pk,autoincrement"`
	BuildID      int64  `bun:"build_id,notnull"`
	ComponentID  int64  `bun:"component_id,notnull"`
	IsRoot       bool   `bun:"is_root,notnull"`
	OpenedScanID int64  `bun:"opened_scan_id,notnull"`
	ClosedScanID *int64 `bun:"closed_scan_id"`
	// Purl and CPE are the identifiers this build stated for the component,
	// as it stated them: the package identifier with its qualifiers, and the
	// platform enumeration. The component row is shared by every product
	// that ships the package, and what one build states about its
	// distribution or its enumeration is not what another does. A scanner is
	// given these.
	Purl string `bun:"purl,nullzero"`
	CPE  string `bun:"cpe,nullzero"`
	// UpstreamName and UpstreamVersion are the source package this build
	// stated the component was built from, and the version it was built at.
	// The component row holds what the first report of it stated, which can
	// be another product's.
	UpstreamName    string `bun:"upstream_name,nullzero"`
	UpstreamVersion string `bun:"upstream_version,nullzero"`
	// Repository is the version-control address this build stated the
	// component is built from, without credentials. An analyzer's result in
	// that repository is placed on the component.
	Repository string `bun:"repository,nullzero"`
	// Name and Version are what this build stated the component is called
	// and at which version. The component row holds what the first report
	// of it stated, and a package identifier names one component whatever
	// version field a report puts beside it, so the row's can be another
	// product's. A scanner is given these and every screen shows them. Null
	// on a node written before they were kept, which reads the row's; an
	// empty version is one the build stated none for.
	Name    string `bun:"name"`
	Version string `bun:"version"`
	// NameFolded is Name folded as the component's name is, which a name
	// somebody types is matched on.
	NameFolded string `bun:"name_folded"`
	// SourceFolded is the source package this build stated, else Name,
	// folded: what an assignment rule's source pattern is matched on.
	SourceFolded string `bun:"source_folded"`
}

// Edge is one component depending on another.
type Edge struct {
	bun.BaseModel `bun:"table:graph_edge,alias:e"`

	ID       int64 `bun:"id,pk,autoincrement"`
	BuildID  int64 `bun:"build_id,notnull"`
	ParentID int64 `bun:"parent_id,notnull"`
	ChildID  int64 `bun:"child_id,notnull"`
	// Kind is the scope the producer declared for this dependency, in the
	// producer's own word, and empty where it declared none. It is a fact
	// about the document received and nothing reads it to decide anything.
	Kind         string `bun:"kind,notnull"`
	OpenedScanID int64  `bun:"opened_scan_id,notnull"`
	ClosedScanID *int64 `bun:"closed_scan_id"`
}

// Snapshot is the graph a single scan describes.
type Snapshot struct {
	// Components are every component the scan mentions.
	Components []Described
	// Root is the component the scan is about — the product itself. It is
	// marked so it can be excluded from anything that walks upwards: its
	// version changes on every build and its name differs per variant, so
	// letting it into an identity or an expiry rule would invalidate
	// everything below it on every rebuild.
	Root Described
	// Dependencies say which component depends on which, by identity.
	Dependencies []Dependency
}

// Dependency is one edge, named by component identity rather than by row.
type Dependency struct {
	Parent, Child Described
	// Kind is what the producer said this dependency's scope is, in its own
	// word, and empty where it said nothing. Recorded, never acted on.
	Kind string
}

// Applied describes what a snapshot changed.
type Applied struct {
	NodesOpened int
	NodesClosed int
	EdgesOpened int
	EdgesClosed int
	// VersionsOpened and VersionsClosed count the versions stated for images
	// identified by name: a rebuilt image moves these and nothing else.
	VersionsOpened int
	VersionsClosed int
}

// Store writes graphs.
type Store struct {
	db         bun.IDB
	components *Components
	// code counts the open code findings on components, where the reader
	// asked for them beside the issues. Nil, none are counted.
	code CodeCounter
	// ours is the most components the tree seen upward assembles over. A
	// field, so a test sets a small one on its own store beside parallel
	// tests on the default.
	ours int
}

// CodeCounter reads the open code findings one build places on each of these
// components, by occurrence, narrowed to the reader; nil components is every
// component of the build. The graph cannot read them itself: their state is
// the analysis package's, which reads the graph.
type CodeCounter func(ctx context.Context, buildID int64, components []int64) (map[int64][]string, error)

// CountingCode is the store with every neighbor it answers carrying the open
// code findings on it and beneath it as well, by the same walk as its issues.
func (s *Store) CountingCode(counter CodeCounter) *Store {
	counting := *s
	counting.code = counter
	return &counting
}

// NewStore returns a graph store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, components: NewComponents(db), ours: ours}
}

// ApplyWithin records a scan's graph against a variant, inside a transaction
// the caller opened.
//
// Only differences are written. A nightly rebuild that changed nothing writes
// nothing at all — no rows, no history, no growth. That is what keeps the
// stored volume tracking real change rather than the calendar, and it is
// checked by a test rather than assumed.
//
// A half-applied graph is indistinguishable from components having been
// removed, which would close findings that are still present, so the whole
// graph is one transaction. Ingest stores a graph, what the build argued about its own patches and what
// the inventory was made of, and those three are one act: a graph applied
// beside claims that were not recorded reads as a build that withdrew every
// patch it carries, and reopens every finding they suppressed.
func ApplyWithin(ctx context.Context, tx bun.IDB, buildID, scanID int64,
	snap Snapshot) (Applied, error) {

	var applied Applied
	err := func() error {
		// Taken first, before anything is read. Two scans of one build can be
		// in flight at once — the queue hands different jobs to different
		// workers by design — and without this both would read the same open
		// rows, both compute the same difference, and both write it, leaving
		// two open rows where everything downstream assumes one. This is an
		// ordinary row update, so every engine takes the lock and the second
		// worker waits rather than racing.
		if _, err := tx.NewUpdate().Table("build").
			Set(`"last_scan_id" = ?`, scanID).
			Where(`"id" = ?`, buildID).Exec(ctx); err != nil {
			return fmt.Errorf("take the build: %w", err)
		}

		components := NewComponents(tx)

		// The product itself is stored without the version that moves every
		// build. Everything the document said about it — including every edge
		// hanging off it — has to resolve to that one row, or the version
		// arrives again through the edges and the churn it causes with it.
		// An image the document states once is stored the same way, by its
		// name, for the same reason.
		root := snap.Root.AsRoot()
		described := snap.Root.Identity()
		images := imagesByName(snap.Components)
		asStored := func(d Described) Described {
			if d.Identity() == described {
				return root
			}
			if image, ok := images[d.Identity()]; ok {
				return image
			}
			return d
		}

		all := []Described{root}
		for _, d := range snap.Components {
			all = append(all, asStored(d))
		}
		for _, dep := range snap.Dependencies {
			all = append(all, asStored(dep.Parent), asStored(dep.Child))
		}
		ids, err := components.Intern(ctx, all)
		if err != nil {
			return err
		}

		wanted := map[int64]stated{}
		wanted[ids[root.Identity()]] = stated{isRoot: true, name: strings.TrimSpace(root.Name)}
		for _, d := range snap.Components {
			stored := asStored(d)
			id := ids[stored.Identity()]
			if _, already := wanted[id]; !already {
				wanted[id] = stated{
					purl: StoredPurl(stored.Purl), cpe: strings.TrimSpace(stored.CPE),
					upstreamName:    strings.TrimSpace(stored.UpstreamName),
					upstreamVersion: strings.TrimSpace(stored.UpstreamVersion),
					repository:      statedRepository(stored.Repository),
					name:            strings.TrimSpace(stored.Name),
					version:         strings.TrimSpace(stored.Version),
				}
			}
		}

		nodeIDs, opened, closed, err := reconcileNodes(ctx, tx, buildID, scanID, wanted)
		if err != nil {
			return err
		}
		applied.NodesOpened, applied.NodesClosed = opened, closed

		// What the build stated for each image it holds by name, whole.
		statedImages := map[int64]statedImage{}
		for _, d := range snap.Components {
			image, ok := images[d.Identity()]
			if !ok || d.Identity() == described {
				continue
			}
			statedImages[nodeIDs[ids[image.Identity()]]] = statedImage{
				version: strings.TrimSpace(d.Version), purl: StoredPurl(d.Purl),
			}
		}
		applied.VersionsOpened, applied.VersionsClosed, err = reconcileImageVersions(ctx, tx,
			buildID, scanID, statedImages)
		if err != nil {
			return err
		}

		wantedEdges := map[edgeAt]bool{}
		for _, dep := range snap.Dependencies {
			parent, okP := nodeIDs[ids[asStored(dep.Parent).Identity()]]
			child, okC := nodeIDs[ids[asStored(dep.Child).Identity()]]
			if !okP || !okC {
				return refusal.Errorf("dependency names a component the snapshot does not list: %s -> %s",
					dep.Parent.Name, dep.Child.Name)
			}
			wantedEdges[edgeAt{Parent: parent, Child: child, Kind: dep.Kind}] = true
		}

		applied.EdgesOpened, applied.EdgesClosed, err = reconcileEdges(ctx, tx, buildID, scanID, wantedEdges)
		return err
	}()
	return applied, err
}

// CurrentComponents returns what a build contains now, as the scanner needs
// to be given it.
//
// The scanner is fed from here rather than from the file a build sent, because
// that file is not kept for a moving line: a nightly scan is superseded the
// next night. Re-scanning a year-old release against today's vulnerability
// data works from this, which is why what is not stored can never be scanned.
//
// The identifiers and the source package are the ones this build stated, from
// its node. What the build did not state is taken from what other builds of
// the same product stated for the component, earliest first, and nothing the
// build stated is replaced by it. Never from another product: a pipeline key
// scoped to one product would otherwise decide which advisories another
// product's scanner matches. The component row is not read for them at all,
// because it holds whichever report first described the component.
func (s *Store) CurrentComponents(ctx context.Context, buildID int64) ([]Described, error) {
	return s.ComponentsAt(ctx, buildID, Now)
}

// ComponentsAt is what a build contained at a moment, as CurrentComponents
// gives it to the scanner.
func (s *Store) ComponentsAt(ctx context.Context, buildID int64, at Moment) ([]Described, error) {
	_, described, err := s.componentsAt(ctx, buildID, at)
	return described, err
}

// ScannedAs is each component a build contained at a moment, by component,
// as ComponentsAt gives it to the scanner. A scanner's report names a
// component by what it was given, and a component stored before identity was
// read the way it is now holds an identity that description no longer hashes
// to.
func (s *Store) ScannedAs(ctx context.Context, buildID int64, at Moment) (map[int64]Described, error) {
	ids, described, err := s.componentsAt(ctx, buildID, at)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]Described, len(ids))
	for i, id := range ids {
		out[id] = described[i]
	}
	return out, nil
}

// componentsAt is ComponentsAt with the component each description is of,
// in the same order.
func (s *Store) componentsAt(ctx context.Context, buildID int64, at Moment) ([]int64, []Described, error) {
	held, args := at.Held("n")
	var rows []struct {
		ComponentID     int64  `bun:"component_id"`
		Name            string `bun:"name"`
		Version         string `bun:"version"`
		UpstreamName    string `bun:"upstream_name"`
		UpstreamVersion string `bun:"upstream_version"`
		Purl            string `bun:"purl"`
		CPE             string `bun:"cpe"`
	}
	err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`"c"."id" AS "component_id"`).
		ColumnExpr(NodeName("n", "c")+` AS "name"`).
		ColumnExpr(NodeVersion("n", "c")+` AS "version"`).
		ColumnExpr(`"n"."upstream_name" AS "upstream_name"`).
		ColumnExpr(`"n"."upstream_version" AS "upstream_version"`).
		ColumnExpr(`"n"."purl" AS "purl"`).
		ColumnExpr(`"n"."cpe" AS "cpe"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(held, args...).
		Where(`"n"."is_root" = ?`, false).
		Scan(ctx, &rows)
	if err != nil {
		return nil, nil, fmt.Errorf("read what a build contains: %w", err)
	}
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ComponentID)
	}
	others, err := s.statedInProduct(ctx, buildID, ids)
	if err != nil {
		return nil, nil, err
	}

	described := make([]Described, 0, len(rows))
	for _, row := range rows {
		stated := Described{
			Purl: row.Purl, CPE: row.CPE, Name: row.Name, Version: row.Version,
			UpstreamName: row.UpstreamName, UpstreamVersion: row.UpstreamVersion,
		}
		for _, other := range others[row.ComponentID] {
			stated.FillFrom(other)
		}
		described = append(described, stated)
	}
	return ids, described, nil
}

// statedRow is what one node states for its component.
type statedRow struct {
	ComponentID     int64  `bun:"component_id"`
	Purl            string `bun:"purl"`
	CPE             string `bun:"cpe"`
	UpstreamName    string `bun:"upstream_name"`
	UpstreamVersion string `bun:"upstream_version"`
}

// statedColumns reads a statedRow from the nodes as "n".
func statedColumns(q *bun.SelectQuery) *bun.SelectQuery {
	return q.TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."component_id" AS "component_id"`).
		ColumnExpr(`"n"."purl" AS "purl"`).
		ColumnExpr(`"n"."cpe" AS "cpe"`).
		ColumnExpr(`"n"."upstream_name" AS "upstream_name"`).
		ColumnExpr(`"n"."upstream_version" AS "upstream_version"`)
}

func (r statedRow) described() Described {
	return Described{Purl: r.Purl, CPE: r.CPE, UpstreamName: r.UpstreamName, UpstreamVersion: r.UpstreamVersion}
}

// Stated is what a build states for each of these components, as
// CurrentComponents gives it to the scanner: the identifiers and the source
// package from the build's latest node holding the component, open or closed,
// with what it left out filled from other builds of the same product. A
// component the build never held is absent from the answer.
//
// Claim matching and a closing finding's explanation read this, so a claim is
// matched against what the scanner was given and never against the component
// row, which holds whichever report first described the component.
func (s *Store) Stated(ctx context.Context, buildID int64, componentIDs []int64) (map[int64]Described, error) {
	out := make(map[int64]Described, len(componentIDs))
	if len(componentIDs) == 0 {
		return out, nil
	}
	err := database.IDsInBatches(ctx, componentIDs, func(ctx context.Context, batch []int64) error {
		var rows []statedRow
		err := statedColumns(s.db.NewSelect()).
			Where(`"n"."build_id" = ?`, buildID).
			Where(`"n"."component_id" IN (?)`, bun.List(batch)).
			OrderExpr(`"n"."opened_scan_id", "n"."id"`).
			Scan(ctx, &rows)
		if err != nil {
			return err
		}
		// Ordered earliest first, so the latest node is the one left.
		for _, row := range rows {
			out[row.ComponentID] = row.described()
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read what a build states for its components: %w", err)
	}
	held := make([]int64, 0, len(out))
	for id := range out {
		held = append(held, id)
	}
	others, err := s.statedInProduct(ctx, buildID, held)
	if err != nil {
		return nil, err
	}
	for id, stated := range out {
		for _, other := range others[id] {
			stated.FillFrom(other)
		}
		out[id] = stated
	}
	return out, nil
}

// statedInProduct is what the other builds of a build's product stated for
// each of these components, earliest statement first. Only nodes that state
// something are read.
func (s *Store) statedInProduct(ctx context.Context, buildID int64,
	componentIDs []int64) (map[int64][]Described, error) {

	out := make(map[int64][]Described, len(componentIDs))
	if len(componentIDs) == 0 {
		return out, nil
	}
	productID, err := catalog.NewStore(s.db).ProductOf(ctx, buildID)
	if err != nil {
		return nil, err
	}
	err = database.IDsInBatches(ctx, componentIDs, func(ctx context.Context, batch []int64) error {
		var rows []statedRow
		err := statedColumns(s.db.NewSelect()).
			// By build first, which the node index leads with: a product
			// has a handful of builds and the node table holds every
			// product's history.
			Where(`"n"."build_id" IN (SELECT "b"."id" FROM "build" AS "b"
				JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"
				WHERE "st"."product_id" = ? AND "b"."id" <> ?)`, productID, buildID).
			Where(`"n"."component_id" IN (?)`, bun.List(batch)).
			WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
				return q.Where(`"n"."purl" IS NOT NULL`).
					WhereOr(`"n"."cpe" IS NOT NULL`).
					WhereOr(`"n"."upstream_name" IS NOT NULL`)
			}).
			OrderExpr(`"n"."opened_scan_id", "n"."id"`).
			Scan(ctx, &rows)
		if err != nil {
			return err
		}
		for _, row := range rows {
			out[row.ComponentID] = append(out[row.ComponentID], row.described())
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read what the product's other builds state: %w", err)
	}
	return out, nil
}

// DeclaredScopes is what a producer said about each edge arriving at one
// component in one build, by the component that pulls it in.
//
// Keyed on the puller rather than on the edge row, because that is what an occurrence
// names: a finding sits at a component under a consumer, and the product itself
// is a consumer of nothing, which is the zero key here for the same reason a
// occurrence under the build carries no consumer.
//
// A word is present only where the producer stated one, and most inventories
// state none at all.
func (s *Store) DeclaredScopes(ctx context.Context, buildID int64,
	componentIDs []int64) (map[[2]int64]string, error) {

	if len(componentIDs) == 0 {
		return map[[2]int64]string{}, nil
	}
	var rows []struct {
		ChildComponentID  int64  `bun:"child_component_id"`
		ParentComponentID int64  `bun:"parent_component_id"`
		ParentIsRoot      bool   `bun:"parent_is_root"`
		Kind              string `bun:"kind"`
	}
	err := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "child" ON "child"."id" = "e"."child_id"`).
		Join(`JOIN "graph_node" AS "parent" ON "parent"."id" = "e"."parent_id"`).
		ColumnExpr(`"child"."component_id" AS "child_component_id"`).
		ColumnExpr(`"parent"."component_id" AS "parent_component_id"`).
		ColumnExpr(`"parent"."is_root" AS "parent_is_root"`).
		ColumnExpr(`"e"."kind" AS "kind"`).
		Where(`"e"."build_id" = ?`, buildID).
		Where(`"e"."closed_scan_id" IS NULL`).
		Where(`"e"."kind" <> ?`, "").
		Where(`"e"."parent_id" <> "e"."child_id"`).
		Where(`"child"."component_id" IN (?)`, bun.List(componentIDs)).
		// The earliest scan first, and within one scan the words in byte
		// order, so the word kept below is the same on every engine and every
		// read. One scan opens its edges in no particular order.
		OrderExpr(`"e"."opened_scan_id", "e"."kind", "e"."id"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what the producer called these dependencies: %w", err)
	}
	scopes := make(map[[2]int64]string, len(rows))
	for _, row := range rows {
		puller := row.ParentComponentID
		if row.ParentIsRoot {
			puller = 0
		}
		at := [2]int64{row.ChildComponentID, puller}
		// The first word for a pair, in the order above. A component reached
		// from one consumer by two edges is one occurrence, and two words for it is
		// the producer having said two things about the same dependency.
		if _, already := scopes[at]; !already {
			scopes[at] = row.Kind
		}
	}
	return scopes, nil
}

// statedRepository is a repository address as a node holds it: trimmed,
// without a credential or query, and bounded the way what a producer states
// about a component is. A credential in an inventory would otherwise reach
// every reader of the build.
func statedRepository(remote string) string {
	return bound.HeadRunes(sourcelink.WithoutCredential(remote), statedWidth)
}
