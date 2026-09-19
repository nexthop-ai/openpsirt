package finding_test

// The fixture every test file in this package builds on: one migrated
// database, a variant, a stored graph, and a way to mint scan runs in order.
//
// Everything else here went to files named for the invariant each block
// pins — what a scan opens and closes, one issue under many names, what the
// build already argued, who may read what, and what a run says about itself.
// This file is what they all share, and nothing else.

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// fixture is one migrated database with a variant, a stored graph, and a way
// to mint scan runs in order.
type fixture struct {
	db        *database.DB
	store     *finding.Store
	graph     *graph.Store
	target    int64
	productID int64
	// scope is the fixture's own build as a selection, which is what the
	// lists take: one build is a selection with all three levels named.
	scope    finding.Scope
	lastScan int64
	scans    *ingest.Store
	built    time.Time
	seq      int
}

func at(name, version string) graph.Described {
	return graph.Described{
		Purl: "pkg:deb/debian/" + name + "@" + version, Name: name, Version: version,
	}
}

var (
	root     = at("sonic", "1.0")
	swss     = at("libswsscommon", "1.0.0")
	teamd    = at("teamd", "1.31")
	libnl    = at("libnl-3-200", "3.7.0")
	libnlNew = at("libnl-3-200", "3.9.0")
)

// shipped stores a graph: libnl sits under two consumers, which is the case
// the whole place definition exists for.
func (f *fixture) shipped(t *testing.T, snap graph.Snapshot) {
	t.Helper()
	f.seq++
	f.built = f.built.Add(time.Hour)
	scan, outcome, err := f.scans.Record(t.Context(), ingest.Arriving{
		TargetID: f.target, ContentHash: fmt.Sprintf("hash-%d", f.seq), BuiltAt: f.built,
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := f.graph.Apply(t.Context(), f.target, scan.ID, snap); err != nil {
		t.Fatalf("apply graph: %v", err)
	}
	f.lastScan = scan.ID
}

// anotherBuild declares a second release of the same product, as a tag, and
// returns its target.
//
// Anything reporting *per build* has to be tested against more than one, or
// the grouping is enforced by there being nothing to group.
func (f *fixture) anotherBuild(t *testing.T, stream string) int64 {
	t.Helper()
	return f.buildOfKind(t, stream, catalog.Tag)
}

// anotherBranch is the same for a release that moves, which is what a test
// about deadlines needs: a tag was built once and carries none.
func (f *fixture) anotherBranch(t *testing.T, stream string) int64 {
	t.Helper()
	return f.buildOfKind(t, stream, catalog.Branch)
}

func (f *fixture) buildOfKind(t *testing.T, stream string, kind catalog.Kind) int64 {
	t.Helper()
	return f.buildOfKindIn(t, f.productID, stream, kind)
}

// anotherBranchOf is anotherBranch in a product other than the fixture's own,
// for the checks about what reaches one product and not another.
func (f *fixture) anotherBranchOf(t *testing.T, productID int64, stream string) int64 {
	t.Helper()
	return f.buildOfKindIn(t, productID, stream, catalog.Branch)
}

func (f *fixture) buildOfKindIn(t *testing.T, productID int64, stream string,
	kind catalog.Kind) int64 {

	t.Helper()
	cat := catalog.NewStore(f.db.DB)
	declared, err := cat.DeclareStream(t.Context(), productID, stream, kind, nil)
	if err != nil {
		t.Fatalf("declare %s: %v", stream, err)
	}
	variant, err := cat.VariantByName(t.Context(), productID, "broadcom")
	if err != nil {
		t.Fatalf("variant: %v", err)
	}
	target, err := cat.TargetFor(t.Context(), declared.ID, variant.ID)
	if err != nil {
		t.Fatalf("target for %s: %v", stream, err)
	}
	return target.ID
}

// shippedTo stores a graph against a build other than the fixture's own.
func (f *fixture) shippedTo(t *testing.T, target int64, snap graph.Snapshot) {
	t.Helper()
	f.seq++
	f.built = f.built.Add(time.Hour)
	scan, outcome, err := f.scans.Record(t.Context(), ingest.Arriving{
		TargetID: target, ContentHash: fmt.Sprintf("hash-%d", f.seq), BuiltAt: f.built,
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := f.graph.Apply(t.Context(), target, scan.ID, snap); err != nil {
		t.Fatalf("apply graph: %v", err)
	}
}

// runOn starts a scan run against a build other than the fixture's own.
func (f *fixture) runOn(t *testing.T, target int64) int64 {
	t.Helper()
	r, err := f.store.Begin(t.Context(), finding.Run{
		TargetID: target, Scanner: "grype", ScannerVersion: "0.100.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// twoConsumers is the graph most of these tests use.
func twoConsumers() graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{swss, teamd, libnl},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss},
			{Parent: root, Child: teamd},
			{Parent: swss, Child: libnl},
			{Parent: teamd, Child: libnl},
		},
	}
}

// run starts a scan run and returns its identifier.
func (f *fixture) run(t *testing.T) int64 {
	t.Helper()
	r, err := f.store.Begin(t.Context(), finding.Run{
		TargetID: f.target, Scanner: "grype", ScannerVersion: "0.100.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// found is one reported issue against a component.
func found(id string, component graph.Described, aliases ...string) finding.Reported {
	return finding.Reported{
		Issue:     finding.Named{Identifier: id, Aliases: aliases, Severity: "high"},
		Component: component,
		FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
	}
}

// openClaims is what the build currently argues about what it ships, read
// straight from the table. It was a store method once, exported and reached by
// nothing but these two tests — which is the shape AGENTS.md calls a defect
// rather than spare capacity, and a test reading the row it is asserting about
// is the honest way to assert it.
func (f *fixture) openClaims(t *testing.T) []finding.Claim {
	t.Helper()
	var rows []finding.Claim
	if err := f.db.DB.NewSelect().Model(&rows).
		Where("target_id = ?", f.target).Where("closed_scan_id IS NULL").
		Order("id").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

func (f *fixture) open(t *testing.T) []finding.Finding {
	t.Helper()
	var rows []finding.Finding
	err := f.db.DB.NewSelect().Model(&rows).
		Where("target_id = ?", f.target).Where("closed_at IS NULL").Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}

		fn(t, &fixture{
			db: db, store: finding.NewStore(db.DB), graph: graph.NewStore(db.DB),
			target: target.ID, productID: product.ID, scans: ingest.NewStore(db.DB),
			scope: finding.Scope{
				ProductID: &product.ID, StreamID: &stream.ID, VariantID: &variant.ID,
			},
			built: time.Now().UTC().Add(-72 * time.Hour),
		})
	})
}

// planner is somebody who exists, holding triage on this fixture's product.
//
// Recorded rather than invented, because a declaration names who made it and
// the schema says that has to be a person — a plan attributed to nobody is a
// plan nobody can be asked about.
func (f *fixture) planner(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	person, err := access.NewStore(f.db.DB).Ensure(t.Context(), "them@example.com", "Them", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPerson(person.ID, "them@example.com", false,
		map[int64][]access.Role{f.productID: roles}, 0)
}
