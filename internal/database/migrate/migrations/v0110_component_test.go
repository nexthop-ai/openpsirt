// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// spacedComponentV0100 is a component a producer stated with space around
// every text, a non-breaking space among them, and one stating nothing but
// its name and version.
var spacedComponentV0100 = []struct {
	identity                                string
	purl, cpe                               sql.NullString
	name, version                           string
	upstreamName, upstreamVersion, supplier sql.NullString
}{
	{
		identity: "spaced-libz",
		purl:     sql.NullString{String: " pkg:deb/debian/libz@1.0 ", Valid: true},
		cpe:      sql.NullString{String: "cpe:2.3:a:zlib:zlib:1.0:*:*:*:*:*:*:* ", Valid: true},
		name:     " libz", version: "1.0 ",
		upstreamName:    sql.NullString{String: "zlib ", Valid: true},
		upstreamVersion: sql.NullString{String: " 1.0", Valid: true},
		supplier:        sql.NullString{String: " Debian ", Valid: true},
	},
	{identity: "spaced-bare", name: "bare ", version: " 2.0"},
	{identity: "spaced-clean", name: "clean", version: "3.0",
		purl: sql.NullString{String: "pkg:generic/clean@3.0", Valid: true}},
}

// seedSpacedComponentsV0100 writes spacedComponentV0100's components into a
// v0.10.0 database, or one at v0.11.0's schema, whose component table v0.11.0
// leaves as it was.
func seedSpacedComponentsV0100(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	at := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
	for _, c := range spacedComponentV0100 {
		if _, err := db.DB.NewRaw(`INSERT INTO "component" ("identity", "purl", "cpe", "name", "version",
			"upstream_name", "upstream_version", "supplier", "name_folded", "fold_key", "first_seen_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, c.identity, c.purl, c.cpe, c.name, c.version,
			c.upstreamName, c.upstreamVersion, c.supplier, c.identity, c.identity, at).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// componentsAreTrimmed asserts every text of spacedComponentV0100's
// components reads with surrounding space taken off, and a column stating
// nothing still states nothing.
func componentsAreTrimmed(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	for _, c := range spacedComponentV0100 {
		var row struct {
			Purl            sql.NullString `bun:"purl"`
			CPE             sql.NullString `bun:"cpe"`
			Name            string         `bun:"name"`
			Version         string         `bun:"version"`
			UpstreamName    sql.NullString `bun:"upstream_name"`
			UpstreamVersion sql.NullString `bun:"upstream_version"`
			Supplier        sql.NullString `bun:"supplier"`
		}
		if err := db.DB.NewRaw(`SELECT "purl", "cpe", "name", "version", "upstream_name", "upstream_version",
			"supplier" FROM "component" WHERE "identity" = ?`, c.identity).Scan(ctx, &row); err != nil {
			t.Fatal(err)
		}
		for column, got := range map[string][2]sql.NullString{
			"purl": {row.Purl, c.purl}, "cpe": {row.CPE, c.cpe},
			"name":          {{String: row.Name, Valid: true}, {String: c.name, Valid: true}},
			"version":       {{String: row.Version, Valid: true}, {String: c.version, Valid: true}},
			"upstream name": {row.UpstreamName, c.upstreamName}, "upstream version": {row.UpstreamVersion, c.upstreamVersion},
			"supplier": {row.Supplier, c.supplier},
		} {
			stored, stated := got[0], got[1]
			if stored.Valid != stated.Valid || stored.String != strings.TrimSpace(stated.String) {
				t.Errorf("%s's %s reads %+v, want %q trimmed", c.identity, column, stored, stated.String)
			}
		}
	}
}

// Every component is read across batches, and a second run finds nothing to
// change: four components read two at a time trim to what one run leaves.
func TestTheV0110UpgradeTrimsEveryComponentAcrossBatches(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0110)
		seedSpacedComponentsV0100(t, ctx, db)
		if _, err := db.DB.NewRaw(`INSERT INTO "component" ("identity", "name", "version", "name_folded",
			"fold_key", "first_seen_at") VALUES (?, ?, ?, ?, ?, ?)`, "spaced-last", "last", "4.0 ",
			"last", "last", time.Now().UTC()).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := migrations.TrimV0110Components(ctx, db, 2); err != nil {
				t.Fatal(err)
			}
			componentsAreTrimmed(t, ctx, db)
			var last string
			if err := db.DB.NewRaw(`SELECT "version" FROM "component" WHERE "identity" = ?`, "spaced-last").
				Scan(ctx, &last); err != nil {
				t.Fatal(err)
			}
			if last != "4.0" {
				t.Errorf("the fourth component, in the last batch, reads %q", last)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}
