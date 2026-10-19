// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/publish"
)

// row writes one published document straight to the table, withdrawn or not,
// and returns it.
func row(t *testing.T, db bun.IDB, productID int64, kind, subject, path string,
	withdrawn bool) *publish.Document {

	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	sum := sha256.Sum256([]byte(path))
	doc := &publish.Document{
		ProductID: productID, Kind: kind, Subject: subject,
		Path: path, PathDigest: hex.EncodeToString(sum[:]),
		TrackingID: "x", Title: "x", Version: 1, FirstAt: at, CurrentAt: at,
		Statuses: "all", Settled: hex.EncodeToString(sum[:]), Body: "{}",
	}
	if withdrawn {
		doc.WithdrawnAt = &at
	}
	if _, err := db.NewInsert().Model(doc).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	return doc
}

// emptied removes every published document.
func emptied(t *testing.T, db bun.IDB) {
	t.Helper()
	if _, err := db.NewDelete().Model((*publish.Document)(nil)).Where("1 = 1").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// A served document holds the names it was built from, withdrawn or not. A
// product counts any document about it. A release counts its own OpenVEX
// document, and every CSAF VEX document of its product once it has a scanned
// build. A variant counts every document of its product once it has a scanned
// build. A release or variant nothing was scanned for is in no document.
func TestAServedDocumentHoldsOnlyTheNamesItMayCarry(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		ctx := t.Context()
		w := newWorld(t, f)
		w.shipped()
		db := w.DB.DB
		other := w.DeclareProduct("other-os", "Other OS")

		type asked struct {
			what string
			ask  func() (bool, error)
			want bool
		}
		product := func(id int64) func() (bool, error) {
			return func() (bool, error) { return publish.AnyPublishedForProduct(ctx, db, id) }
		}
		stream := func(s *catalog.Stream) func() (bool, error) {
			return func() (bool, error) { return publish.AnyPublishedForStream(ctx, db, s.ID) }
		}
		variant := func(v *catalog.Variant) func() (bool, error) {
			return func() (bool, error) { return publish.AnyPublishedForVariant(ctx, db, v.ID) }
		}
		check := func(held string, cases []asked) {
			t.Helper()
			for _, c := range cases {
				got, err := c.ask()
				if err != nil {
					t.Fatal(err)
				}
				if got != c.want {
					t.Errorf("with %s, %s answered %v, want %v", held, c.what, got, c.want)
				}
			}
		}

		check("nothing served", []asked{
			{"the product", product(w.Product.ID), false},
			{"the scanned release", stream(w.Branch), false},
			{"the scanned variant", variant(w.Customer), false},
		})

		row(t, db, w.Product.ID, publish.CSAFVEX, "CVE-2026-1001",
			publish.DirectoryPath+"2026/vex-sonic-cve-2026-1001.json", true)
		check("one withdrawn CSAF VEX document", []asked{
			{"the product", product(w.Product.ID), true},
			{"another product", product(other.ID), false},
			{"the scanned release", stream(w.Branch), true},
			{"a release nothing was scanned for", stream(w.Tag), false},
			{"the scanned variant", variant(w.Customer), true},
			{"a variant nothing was scanned for", variant(w.Internal), false},
		})

		emptied(t, db)
		row(t, db, w.Product.ID, publish.OpenVEX, w.Tag.Name,
			publish.OpenVEXPath+"sonic/"+w.Tag.Name+".json", false)
		check("one OpenVEX document about the release nothing was scanned for", []asked{
			{"the product", product(w.Product.ID), true},
			{"the release it is about", stream(w.Tag), true},
			{"another release", stream(w.Branch), false},
			{"the scanned variant", variant(w.Customer), true},
			{"a variant nothing was scanned for", variant(w.Internal), false},
		})
	})
}

// Turning a product's publishing off withdraws every document of that product
// in the one write, and no other product's.
func TestWithdrawingAProductLeavesTheOthers(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		ctx := t.Context()
		db := f.DB.DB
		other := f.DeclareProduct("other-os", "Other OS")
		mine := []*publish.Document{
			row(t, db, f.Product.ID, publish.CSAFVEX, "CVE-2026-1001",
				publish.DirectoryPath+"2026/vex-sonic-cve-2026-1001.json", false),
			row(t, db, f.Product.ID, publish.OpenVEX, f.Branch.Name,
				publish.OpenVEXPath+"sonic/master.json", false),
		}
		theirs := row(t, db, other.ID, publish.OpenVEX, "main", publish.OpenVEXPath+"other-os/main.json", false)
		if err := publish.NewStore(db).WithdrawProduct(ctx, f.Product.ID); err != nil {
			t.Fatal(err)
		}
		for _, one := range append(mine, theirs) {
			held := new(publish.Document)
			if err := db.NewSelect().Model(held).Where(`"pub"."id" = ?`, one.ID).Scan(ctx); err != nil {
				t.Fatal(err)
			}
			switch {
			case one.ProductID == f.Product.ID && held.WithdrawnAt == nil:
				t.Errorf("%s is still served after its product was withdrawn", one.Path)
			case one.ProductID == other.ID && held.WithdrawnAt != nil:
				t.Errorf("%s of another product was withdrawn", one.Path)
			}
		}
	})
}

// A product whose name folds like another's under the standard's filename
// rule would publish at that product's paths. The other counts while it
// publishes and once it has published anything, since a withdrawn document
// keeps its path, and a product never folds against itself.
func TestANameFoldedLikeAnotherProductsIsFound(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		ctx := t.Context()
		db := f.DB.DB
		publishing := f.DeclareProduct("edge.os", "Edge OS")
		if err := f.Catalog.SetPublishes(ctx, publishing.ID, true); err != nil {
			t.Fatal(err)
		}
		published := f.DeclareProduct("core.os", "Core OS")
		row(t, db, published.ID, publish.OpenVEX, "main", publish.OpenVEXPath+"core.os/main.json", true)
		f.DeclareProduct("lab.os", "Lab OS")

		for _, c := range []struct {
			what, name string
			self       int64
			want       string
		}{
			{"a product that publishes", "edge os", f.Product.ID, "Edge OS"},
			{"a product whose documents were withdrawn", "CORE_OS", f.Product.ID, "Core OS"},
			{"a product that never published", "lab os", f.Product.ID, ""},
			{"a name that folds apart", "edge-os", f.Product.ID, ""},
			{"the product itself", "edge os", publishing.ID, ""},
		} {
			got, err := publish.FoldsLike(ctx, db, c.self, c.name)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("%s: %q folds like %q, want %q", c.what, c.name, got, c.want)
			}
		}
	})
}
