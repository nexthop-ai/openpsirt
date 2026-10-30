// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// declareBeforeV0110 seeds the fixture's default world in a database a
// release before v0.11.0 built, where a branch or tag is a "stream" and a
// build is a "target". The catalog writes the tables by their v0.11.0 names,
// so the two renamed tables are written here by hand.
func declareBeforeV0110(ctx context.Context, db *database.DB) (world.Declared, error) {
	cat := catalog.NewStore(db.DB)
	var d world.Declared
	var err error
	if d.Product, err = cat.DeclareProduct(ctx, world.ProductName, world.ProductDisplayName); err != nil {
		return world.Declared{}, fmt.Errorf("declare the product %q: %w", world.ProductName, err)
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	id := func(query string, args ...any) (int64, error) {
		var out int64
		err := db.DB.NewRaw(query, args...).Scan(ctx, &out)
		return out, err
	}
	stream := func(name string, kind catalog.Kind, parent *int64) (*catalog.BranchOrTag, error) {
		if _, err := db.DB.NewRaw(`INSERT INTO "stream" ("product_id", "name", "display_name", "kind", "parent_id", "created_at")
			VALUES (?, ?, ?, ?, ?, ?)`, d.Product.ID, name, name, kind, parent, at).Exec(ctx); err != nil {
			return nil, fmt.Errorf("declare the %s %q: %w", kind, name, err)
		}
		got, err := id(`SELECT "id" FROM "stream" WHERE "product_id" = ? AND "name" = ?`, d.Product.ID, name)
		if err != nil {
			return nil, err
		}
		return &catalog.BranchOrTag{ID: got, ProductID: d.Product.ID, Name: name, DisplayName: name,
			Kind: kind, ParentID: parent}, nil
	}
	if d.Branch, err = stream(world.BranchName, catalog.Branch, nil); err != nil {
		return world.Declared{}, err
	}
	if d.Tag, err = stream(world.TagName, catalog.Tag, &d.Branch.ID); err != nil {
		return world.Declared{}, err
	}
	if d.Customer, err = cat.DeclareVariant(ctx, d.Product.ID, world.CustomerVariant, true); err != nil {
		return world.Declared{}, fmt.Errorf("declare the variant %q: %w", world.CustomerVariant, err)
	}
	if d.Internal, err = cat.DeclareVariant(ctx, d.Product.ID, world.InternalVariant, false); err != nil {
		return world.Declared{}, fmt.Errorf("declare the variant %q: %w", world.InternalVariant, err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "target" ("stream_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
		d.Branch.ID, d.Customer.ID, at).Exec(ctx); err != nil {
		return world.Declared{}, fmt.Errorf("place %s as %s: %w", world.BranchName, world.CustomerVariant, err)
	}
	build, err := id(`SELECT "id" FROM "target" WHERE "stream_id" = ? AND "variant_id" = ?`, d.Branch.ID, d.Customer.ID)
	if err != nil {
		return world.Declared{}, err
	}
	d.Build = &catalog.Build{ID: build, BranchOrTagID: d.Branch.ID, VariantID: d.Customer.ID, CreatedAt: at}
	if d.Person, err = access.NewStore(db.DB).Ensure(ctx, world.PersonIdentity, world.PersonDisplayName,
		new(false), nil); err != nil {
		return world.Declared{}, fmt.Errorf("declare %q: %w", world.PersonIdentity, err)
	}
	return d, nil
}

// worldBeforeV0110 is the default world in a database a release before
// v0.11.0 built, declared where nothing seeded before has, so seeds written
// into one database share one product, build and person. A world read back
// carries the product, the build and the person, which is all a seed reads.
func worldBeforeV0110(t *testing.T, ctx context.Context, db *database.DB) world.Declared {
	t.Helper()
	var products int
	if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "product"`).Scan(ctx, &products); err != nil {
		t.Fatal(err)
	}
	if products == 0 {
		declared, err := declareBeforeV0110(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		return declared
	}
	var product catalog.Product
	if err := db.DB.NewRaw(`SELECT "id" FROM "product" WHERE "name" = ?`, world.ProductName).
		Scan(ctx, &product.ID); err != nil {
		t.Fatal(err)
	}
	var build catalog.Build
	if err := db.DB.NewRaw(`SELECT "t"."id" FROM "target" AS "t"
		JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"
		JOIN "variant" AS "v" ON "v"."id" = "t"."variant_id"
		WHERE "s"."product_id" = ? AND "s"."name" = ? AND "v"."name" = ?`,
		product.ID, world.BranchName, world.CustomerVariant).Scan(ctx, &build.ID); err != nil {
		t.Fatal(err)
	}
	var person access.Account
	if err := db.DB.NewRaw(`SELECT "id" FROM "person" WHERE "identity" = ?`, world.PersonIdentity).
		Scan(ctx, &person.ID); err != nil {
		t.Fatal(err)
	}
	return world.Declared{Product: &product, Build: &build, Person: &person}
}
