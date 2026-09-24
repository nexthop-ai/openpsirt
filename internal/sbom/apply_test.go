// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// TestAProducerDocumentBecomesTheStoredGraph reads a document the way an
// arriving scan is read and stores it, on every engine. The two halves are
// written separately and have to agree: a reader that produced a graph the
// store refuses, or one whose edges named components it did not list, would
// pass every test in either package alone.
func TestAProducerDocumentBecomesTheStoredGraph(t *testing.T) {
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
		filedAgainst, err := cat.TargetFor(ctx, stream.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}

		doc, err := sbom.Read(fixture(t, "image.cdx.json"), sbom.Limits{})
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		// The build the scan was filed against, which stands in as the root
		// for a document that names no component of its own.
		target := graph.Described{Name: "sonic", Version: "master"}

		scans := ingest.NewStore(db.DB)
		store := graph.NewStore(db.DB)
		built := time.Now().UTC().Add(-24 * time.Hour)

		record := func(hash string, at time.Time) int64 {
			t.Helper()
			rec, outcome, err := scans.Record(ctx, ingest.Arriving{
				TargetID: filedAgainst.ID, ContentHash: hash, BuiltAt: at, ParserVersion: "test",
			})
			if err != nil || outcome != ingest.Accept {
				t.Fatalf("record: outcome %v, err %v", outcome, err)
			}
			return rec.ID
		}

		applied, err := store.Apply(ctx, filedAgainst.ID, record("first", built), doc.Snapshot(target))
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		// The root is stored as a node like any other, so the count is the
		// components plus it.
		if want := len(doc.Components) + 1; applied.NodesOpened != want {
			t.Errorf("opened %d nodes, want %d", applied.NodesOpened, want)
		}
		if applied.EdgesOpened != len(doc.Dependencies) {
			t.Errorf("opened %d edges, want %d", applied.EdgesOpened, len(doc.Dependencies))
		}

		// The same build, sent again the next night. Nothing changed, so
		// nothing is written — not a row, not a re-stamped timestamp.
		again, err := sbom.Read(fixture(t, "image.cdx.json"), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		applied, err = store.Apply(ctx, filedAgainst.ID, record("second", built.Add(time.Hour)), again.Snapshot(target))
		if err != nil {
			t.Fatalf("re-apply: %v", err)
		}
		if !applied.Unchanged() {
			t.Errorf("an unchanged build wrote %+v", applied)
		}
	})
}

// TestALicenseReadFromAnElementReachesTheStoredComponent stores a document
// whose licenses are elements of their own, attached by relationships after
// the packages were read. An edge carries its endpoints, and every copy of a
// component is interned: an edge holding the copy from before the licenses
// were resolved stores the component without one.
func TestALicenseReadFromAnElementReachesTheStoredComponent(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "app", "App")
		if err != nil {
			t.Fatal(err)
		}
		stream, err := cat.DeclareStream(ctx, product.ID, "main", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "linux", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := sbom.Read(fixture(t, "rust-app.spdx3.json"), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		rec, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "spdx3", BuiltAt: time.Now().UTC(), ParserVersion: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := graph.NewStore(db.DB).Apply(ctx, target.ID, rec.ID,
			doc.Snapshot(graph.Described{Name: "app", Version: "main"})); err != nil {
			t.Fatal(err)
		}

		// hyper is a dependency, so it is an edge's child as well as a
		// component of the document.
		var license string
		if err := db.DB.NewSelect().TableExpr(`"component" AS "c"`).
			ColumnExpr("COALESCE(c.license, '')").Where("c.name = ?", "hyper").
			Scan(ctx, &license); err != nil {
			t.Fatal(err)
		}
		if license != "MIT" {
			t.Errorf("hyper is stored under the license %q, want MIT", license)
		}
	})
}
