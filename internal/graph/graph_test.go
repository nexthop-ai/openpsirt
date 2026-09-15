package graph_test

import (
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// fixture is one migrated database with a variant to file scans against, and a
// way to mint scans in order.
type fixture struct {
	store *graph.Store
	scans *ingest.Store
	// db is the same database the store reads, for the tests that need a
	// second store over it.
	db       *database.DB
	targetID int64
	// scope is the same build as a selection, for the findings list, which
	// takes one rather than a build identifier.
	scope finding.Scope
	built time.Time
	seq   int
}

// scan records a new scan, each newer than the last, and returns its
// identifier.
func (f *fixture) scan(t *testing.T) int64 {
	t.Helper()
	f.seq++
	f.built = f.built.Add(time.Hour)
	rec, outcome, err := f.scans.Record(t.Context(), ingest.Arriving{
		TargetID: f.targetID, ContentHash: fmt.Sprintf("hash-%d", f.seq),
		BuiltAt: f.built, ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan %d: outcome %v, err %v", f.seq, outcome, err)
	}
	return rec.ID
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		fn(t, &fixture{
			store: graph.NewStore(w.DB.DB), scans: ingest.NewStore(w.DB.DB), db: w.DB,
			targetID: w.Target.ID,
			scope: finding.Scope{
				ProductID: &w.Product.ID, StreamID: &w.Branch.ID, VariantID: &w.Customer.ID,
			},
			built: time.Now().UTC().Add(-48 * time.Hour),
		})
	})
}

func at(name, version string) graph.Described {
	return graph.Described{
		Purl: "pkg:generic/" + name + "@" + version, Name: name, Version: version,
	}
}

// rebuilt is the product as the next night's build describes it. Its version
// carries a build stamp, which is what a real producer emits and what makes
// the unchanged-rebuild test worth anything.
func rebuilt(snap graph.Snapshot, version string) graph.Snapshot {
	snap.Root = at("sonic", version)
	for i, dep := range snap.Dependencies {
		if dep.Parent.Name == "sonic" {
			snap.Dependencies[i].Parent = snap.Root
		}
	}
	return snap
}

var (
	root    = at("sonic", "2.4.0")
	openssl = at("openssl", "3.0.11")
	curl    = at("curl", "8.4.0")
	zlib    = at("zlib", "1.3")
)

// tree is the graph used by most of these tests: the product depends on curl
// and openssl, and curl depends on openssl too. openssl sits at two places and
// is still one node — the graph is a graph.
func tree() graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{openssl, curl},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: curl},
			{Parent: root, Child: openssl},
			{Parent: curl, Child: openssl},
		},
	}
}

func TestFirstSnapshotIsStored(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), tree())
		if err != nil {
			t.Fatal(err)
		}
		if applied.NodesOpened != 3 || applied.EdgesOpened != 3 {
			t.Errorf("opened %+v, want 3 nodes and 3 edges", applied)
		}
		if applied.NodesClosed != 0 || applied.EdgesClosed != 0 {
			t.Errorf("closed something on a first snapshot: %+v", applied)
		}

		nodes, err := f.store.CurrentNodes(t.Context(), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 3 {
			t.Fatalf("%d nodes present, want 3", len(nodes))
		}
		roots := 0
		for _, n := range nodes {
			if n.IsRoot {
				roots++
			}
		}
		if roots != 1 {
			t.Errorf("%d roots, want exactly 1", roots)
		}
	})
}

func TestARebuildThatOnlyMovedItsOwnVersionWritesNothing(t *testing.T) {
	// The product's version changes on every build — a real one carries a
	// build stamp — so if that reached identity, the node standing for the
	// product would close and reopen nightly and take every edge hanging off
	// it along. On a real image that is thousands of rows for a build in which
	// nothing happened.
	each(t, func(t *testing.T, f *fixture) {
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), tree()); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.targetID, f.scan(t),
			rebuilt(tree(), "2.4.0-20260829.010101"))
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("a rebuild that changed only the product's own version wrote %+v", applied)
		}
	})
}

// The claim the whole interval design exists for. A nightly build that changed
// nothing must cost nothing: not a row, not a re-stamped timestamp. Without it,
// storage grows with the calendar rather than with change, and a product
// tracked for a year costs the same whether or not anything happened to it.
func TestAnUnchangedRebuildWritesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), tree()); err != nil {
			t.Fatal(err)
		}
		before := rowCounts(t, f)

		applied, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), tree())
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("an identical rebuild wrote %+v", applied)
		}
		if after := rowCounts(t, f); !maps.Equal(after, before) {
			t.Errorf("row counts moved from %v to %v on an identical rebuild", before, after)
		}
	})
}

func TestOnlyTheChangeIsWritten(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), tree()); err != nil {
			t.Fatal(err)
		}

		// zlib arrives under curl. Nothing else moved.
		next := tree()
		next.Components = append(next.Components, zlib)
		next.Dependencies = append(next.Dependencies, graph.Dependency{Parent: curl, Child: zlib})

		applied, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), next)
		if err != nil {
			t.Fatal(err)
		}
		want := graph.Applied{NodesOpened: 1, EdgesOpened: 1}
		if applied != want {
			t.Errorf("applied %+v, want %+v", applied, want)
		}
	})
}

// TestAVersionBumpClosesTheOldComponent checks that a bump is a close and an
// open rather than an edit. Editing the row in place would silently rewrite
// what every past release contained.
func TestAVersionBumpClosesTheOldComponent(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		first := f.scan(t)
		if _, err := f.store.Apply(t.Context(), f.targetID, first, tree()); err != nil {
			t.Fatal(err)
		}

		bumped := at("openssl", "3.0.12")
		next := graph.Snapshot{
			Root:       root,
			Components: []graph.Described{bumped, curl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: curl},
				{Parent: root, Child: bumped},
				{Parent: curl, Child: bumped},
			},
		}
		second := f.scan(t)
		applied, err := f.store.Apply(t.Context(), f.targetID, second, next)
		if err != nil {
			t.Fatal(err)
		}
		want := graph.Applied{NodesOpened: 1, NodesClosed: 1, EdgesOpened: 2, EdgesClosed: 2}
		if applied != want {
			t.Errorf("applied %+v, want %+v", applied, want)
		}

		nodes, err := f.store.CurrentNodes(t.Context(), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 3 {
			t.Errorf("%d nodes present after a bump, want 3", len(nodes))
		}
		// The closed row is still there, stamped with the scan that ended it.
		var closed []graph.Node
		if err := f.store.DB().NewSelect().Model(&closed).
			Where("target_id = ?", f.targetID).
			Where("closed_scan_id IS NOT NULL").Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(closed) != 1 || *closed[0].ClosedScanID != second {
			t.Errorf("closed history is %+v, want one node closed by scan %d", closed, second)
		}
	})
}

// TestAComponentIsSharedAcrossVariants checks the deduplication that keeps the
// component table sized by the portfolio rather than by scans times variants.
func TestAComponentIsSharedAcrossVariants(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), tree()); err != nil {
			t.Fatal(err)
		}
		before := rowCounts(t, f)["component"]
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), tree()); err != nil {
			t.Fatal(err)
		}
		if after := rowCounts(t, f)["component"]; after != before {
			t.Errorf("%d components after a repeat, want %d", after, before)
		}
	})
}

func TestADependencyOnAnUnlistedComponentIsRefused(t *testing.T) {
	// A file that names an edge to something it never described is malformed.
	// Inventing the missing component would report a dependency nobody
	// declared; failing says so where it can be fixed.
	each(t, func(t *testing.T, f *fixture) {
		bad := tree()
		bad.Dependencies = append(bad.Dependencies, graph.Dependency{Parent: curl, Child: zlib})
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), bad); err == nil {
			t.Fatal("an edge to an undescribed component was accepted")
		}
	})
}

func TestAComponentWithoutAVersionIsStillTracked(t *testing.T) {
	// The format requires a type and a name, nothing else, so a component with
	// no version is ordinary output. Refusing it would discard every other
	// component in the same document. Nothing can match a vulnerability
	// against a version nobody stated, but it ships, and something that ships
	// and cannot be checked is worth being able to see.
	each(t, func(t *testing.T, f *fixture) {
		snap := tree()
		snap.Components = append(snap.Components, graph.Described{Name: "mystery"})
		applied, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap)
		if err != nil {
			t.Fatalf("a component with no version was refused: %v", err)
		}
		if applied.NodesOpened != 4 {
			t.Errorf("opened %d nodes, want 4", applied.NodesOpened)
		}
	})
}

func TestAComponentWithoutANameIsRefused(t *testing.T) {
	// Nothing can identify it, so nothing can track it.
	each(t, func(t *testing.T, f *fixture) {
		bad := tree()
		bad.Components = append(bad.Components, graph.Described{Version: "1.0"})
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), bad); err == nil {
			t.Fatal("a component with no name was accepted")
		}
	})
}

func rowCounts(t *testing.T, f *fixture) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, table := range []string{"component", "graph_node", "graph_edge"} {
		n, err := f.store.DB().NewSelect().Table(table).Count(t.Context())
		if err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		counts[table] = n
	}
	return counts
}

func TestAGraphLargerThanOneStatementApplies(t *testing.T) {
	// Two of the four engines cap how large a single statement may be, and the
	// cap is server configuration rather than anything a client can discover.
	// A real image opens tens of thousands of nodes and edges in one run; sent
	// as one statement that is tens of megabytes of SQL.
	each(t, func(t *testing.T, f *fixture) {
		const many = 1200 // comfortably over the batch size
		snap := graph.Snapshot{Root: root}
		for i := range many {
			c := at(fmt.Sprintf("pkg-%04d", i), "1.0")
			// One supplier across the whole inventory, which is what a
			// distribution's document looks like: the write that fills them in
			// groups by the name, so that group is every component. Without a
			// supplier on any of them the write was skipped, and the statement
			// this test exists to size was never issued at all.
			c.Supplier = "Debian"
			snap.Components = append(snap.Components, c)
			snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: c})
		}

		applied, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap)
		if err != nil {
			t.Fatalf("applying a graph larger than one statement: %v", err)
		}
		if applied.NodesOpened != many+1 || applied.EdgesOpened != many {
			t.Fatalf("opened %+v", applied)
		}

		// The supplier is filled in on a second sight of the same components,
		// which is the path that names every one of them in one statement:
		// the first scan carries it on the insert.
		second := snap
		second.Components = append([]graph.Described{}, snap.Components...)
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), second); err != nil {
			t.Fatalf("applying a graph whose suppliers are filled in: %v", err)
		}
		// Counted rather than read: the point is the statement that wrote
		// them, not the rows.
		supplied, err := f.db.DB.NewSelect().Model((*graph.Component)(nil)).
			Where("supplier = ?", "Debian").Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if supplied != many {
			t.Errorf("%d of %d components carry the supplier the document named",
				supplied, many)
		}

		// And closing them again, which names as many identifiers as opening
		// wrote rows.
		applied, err = f.store.Apply(t.Context(), f.targetID, f.scan(t), graph.Snapshot{Root: root})
		if err != nil {
			t.Fatalf("closing a graph larger than one statement: %v", err)
		}
		if applied.NodesClosed != many || applied.EdgesClosed != many {
			t.Errorf("closed %+v", applied)
		}
	})
}

func TestTheRootMovesWhenTheDocumentSaysItDid(t *testing.T) {
	// Whether a node is the build's root was only ever written on an insert.
	// A component already in the graph that a later document puts at the top —
	// a base-image component promoted, a restructured build — kept its old
	// answer, and the build then reported no root of its own.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// A component named and nothing else, which is the identity a root
		// is stored under — so the same row can be a child in one document
		// and the root of the next.
		base := graph.Described{Name: "base"}
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{base},
			Dependencies: []graph.Dependency{{Parent: root, Child: base}},
		}); err != nil {
			t.Fatal(err)
		}

		// The next document is rooted at it instead.
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:         base,
			Components:   []graph.Described{openssl},
			Dependencies: []graph.Dependency{{Parent: base, Child: openssl}},
		}); err != nil {
			t.Fatal(err)
		}

		top, _, err := f.store.Roots(ctx, everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if top == nil {
			t.Fatal("the build reports no root of its own after the document moved it")
		}
		if top.Name != base.Name {
			t.Errorf("the build reports %q as its root, and the document named %q",
				top.Name, base.Name)
		}

		// And the other way: rooted back at the product, the promoted
		// component reads as a component again.
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{base},
			Dependencies: []graph.Dependency{{Parent: root, Child: base}},
		}); err != nil {
			t.Fatal(err)
		}
		back, _, err := f.store.Roots(ctx, everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if back == nil || back.Name != root.Name {
			t.Errorf("the build reports %+v as its root after the document moved it back", back)
		}
	})
}

func TestWhatACountSaysIsIssuesWhicheverWayTheComponentIsReached(t *testing.T) {
	// The number beside a component is issues rather than finding rows, which
	// is what browsing to it answers. Searching for it counted rows, so a
	// library reachable under three parents reported three times its real
	// number — and the results are ordered by it, so deeply-vendored
	// components with few real issues outranked shallow ones with many.
	//
	// And the build's component count excludes the build's own root, which is
	// what the component list beside it already does: counted, the header read
	// one higher than the rows below it on every build.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), tree()); err != nil {
			t.Fatal(err)
		}

		// One issue at openssl, open at two places — which is ordinary: a
		// finding is a component at a place, and openssl sits under two.
		issue := f.anIssue(t, "CVE-2026-SSL")
		componentID := f.componentNamed(t, openssl.Name)
		for _, place := range []string{"under-curl", "under-root"} {
			f.opens(t, issue, componentID, place)
		}

		found, err := f.store.Search(ctx, everyone(f), f.targetID, "ssl", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 {
			t.Fatalf("searching found %d components, want the one: %+v", len(found), found)
		}
		if found[0].Findings != 1 {
			t.Errorf("the search says %d findings, and one issue is open there — it is "+
				"counting the places", found[0].Findings)
		}

		// The count in the header and the list beside it answer about the
		// same thing.
		components, _, err := f.store.Counts(ctx, everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		listed, err := f.store.CurrentComponents(ctx, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if components != len(listed) {
			t.Errorf("the build counts %d components and lists %d", components, len(listed))
		}
	})
}

// anIssue records a vulnerability to open findings against.
func (f *fixture) anIssue(t *testing.T, identifier string) int64 {
	t.Helper()
	interned, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(),
		[]finding.Named{{Identifier: identifier, Severity: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	return interned[strings.ToUpper(identifier)]
}

// componentNamed is the identifier of a component the graph holds.
func (f *fixture) componentNamed(t *testing.T, name string) int64 {
	t.Helper()
	var id int64
	if err := f.db.DB.NewSelect().TableExpr(`component AS "c"`).
		ColumnExpr("c.id").Where("c.name = ?", name).
		Limit(1).Scan(t.Context(), &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// opens puts one finding of an issue at one place of a component.
func (f *fixture) opens(t *testing.T, issue, componentID int64, place string) {
	t.Helper()
	row := &finding.Finding{
		TargetID: f.targetID, Kind: finding.Vulnerable, VulnerabilityID: issue,
		Visibility: access.Public, ComponentID: componentID, PlaceIdentity: place,
		LastChangedAt: time.Now().UTC().Truncate(time.Microsecond),
		OpenedAt:      time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestARefusalAroundAComponentDoesNotSayWhetherTheBuildHoldsIt(t *testing.T) {
	// A request is authorized before any name in it is resolved. The other way
	// round the refusal was informative: a name the build does not hold
	// answered one way, a name it holds twice answered with every version and
	// ecosystem it holds, and a name it holds once answered a third — so a
	// subject who may not read findings here could read the build's inventory
	// back one name at a time.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// One name at two versions, which is what makes the answers differ.
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{curl, at(curl.Name, "8.5.0"), zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: curl},
				{Parent: root, Child: at(curl.Name, "8.5.0")},
				{Parent: root, Child: zlib},
			},
		}); err != nil {
			t.Fatal(err)
		}

		// An administrator reaches every product and holds no read role, so
		// they pass the question about the product and fail the one about
		// what they may read.
		outside := access.NewPerson(2, "admin", true, nil, 0)

		var said []string
		for _, name := range []string{zlib.Name, curl.Name, "nothing-is-called-this"} {
			_, _, err := f.store.Around(ctx, outside, f.targetID, name, "", "")
			if err == nil {
				t.Fatalf("%q was answered for somebody who may read nothing here", name)
			}
			said = append(said, err.Error())
		}
		for i := 1; i < len(said); i++ {
			if said[i] != said[0] {
				t.Errorf("the build answers differently for a name it holds and one it does "+
					"not:\n  %s\n  %s", said[0], said[i])
			}
		}
	})
}

func TestTwoNamesThatDifferInsideTheColumnAreTwoComponents(t *testing.T) {
	// The fold key is a hash of the folded name cut to the width of the column
	// that carries it. Cut at that many bytes rather than characters, a name
	// written in a script taking three bytes a character kept a third of them
	// — so two components differing only past that third hashed alike and were
	// one bump, one decision and one row.
	each(t, func(t *testing.T, f *fixture) {
		const wide = 191
		one := graph.Described{Name: strings.Repeat("漢", wide-1) + "一", Version: "1.0"}
		two := graph.Described{Name: strings.Repeat("漢", wide-1) + "二", Version: "1.0"}
		if graph.Folded(one.Name) == graph.Folded(two.Name) {
			t.Fatal("two names differing before the column's width fold to one")
		}
		if one.FoldKey() == two.FoldKey() {
			t.Fatal("two names differing before the column's width share a fold key")
		}

		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{one, two},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: one}, {Parent: root, Child: two},
			},
		}); err != nil {
			t.Fatal(err)
		}
		listed, err := f.store.CurrentComponents(t.Context(), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 2 {
			t.Errorf("the build holds %d components, want the two the document named", len(listed))
		}
	})
}
