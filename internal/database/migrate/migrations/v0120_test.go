// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v0120 is the migration v0.12.0 carries v0.11.0's schema across with.
const v0120 = 46

// The former tests a stopped start of the v0.12.0 upgrade is checked by, each
// a subtest of the one below under its own name.
const (
	columnsAlreadyThere = "TheV0120UpgradeStepsOverColumnsAlreadyThere"
	checkedRunResumes   = "AV0120UpgradeStoppedPartWayThroughTheCheckedRunResumes"
	stoppedAfterColumn  = "AV0120UpgradeStoppedAfterItsColumnStillMarks"
	replacedOwesNoCheck = "ABranchInventoryReplacedBeforeTheUpgradeOwesNoCheck"
)

// stopV0120 is what a start of the v0.12.0 upgrade that stopped at one point
// left, made by hand.
type stopV0120 struct {
	test, name string
	// servers is a stop SQLite never makes: it changes a table in one
	// transaction.
	servers bool
	make    func(t *testing.T, db *database.DB)
}

// Two v0.11.0 databases per engine, each holding a replaced inventory and a
// current one, are stopped at the points of the v0.12.0 upgrade checked here
// and upgraded once each. The stops of one former test are alternatives, a
// few of the dates against all of them and the run's column against its
// index, so each database takes one of each, in the order the upgrade
// reaches them; building a database to v0.11.0 is most of what such a test
// costs. The upgrade that does not stop is checked by
// TestEachReleaseBuildsTheSchemaItTagged, which reaches v0.11.0 on its way.
func TestAV0110DatabaseResumesTheV0120UpgradeFromEveryStop(t *testing.T) {
	dates := func(made int) stopV0120 {
		return stopV0120{test: columnsAlreadyThere, name: fmt.Sprintf("%d of the dates", made),
			make: func(t *testing.T, db *database.DB) {
				// On MySQL and MariaDB each column commits by itself.
				for _, column := range []string{"published_at", "modified_at", "dates_asked_at"}[:made] {
					if _, err := db.ExecContext(t.Context(), `ALTER TABLE "vulnerability" ADD COLUMN "`+column+`" `+
						timestampOn(db.Server.Engine)+` NULL`); err != nil {
						t.Fatalf("make what a stopped upgrade left: %v", err)
					}
				}
			}}
	}
	// Stopped after the run's column, or after its key and index: the upgrade
	// makes what is missing and replaces nothing already made.
	runColumn := stopV0120{test: checkedRunResumes, name: "after the column", servers: true,
		make: func(t *testing.T, db *database.DB) {
			if _, err := db.ExecContext(t.Context(),
				`ALTER TABLE "scan_run" ADD COLUMN "checked_scan_id" BIGINT NULL`); err != nil {
				t.Fatalf("make what a stopped upgrade left: %v", err)
			}
		}}
	runIndex := stopV0120{test: checkedRunResumes, name: "after the index",
		make: func(t *testing.T, db *database.DB) {
			if err := migrations.RunV0120CheckedStep(t.Context(), db); err != nil {
				t.Fatalf("make what a stopped upgrade left: %v", err)
			}
		}}
	// Stopped after adding the column marking an inventory replaced before
	// the upgrade: the upgrade still marks it.
	scanColumn := stopV0120{test: stoppedAfterColumn,
		make: func(t *testing.T, db *database.DB) {
			if _, err := db.ExecContext(t.Context(),
				`ALTER TABLE "scan" ADD COLUMN "replaced_unchecked" BOOLEAN DEFAULT FALSE NOT NULL`); err != nil {
				t.Fatalf("make what a stopped upgrade left: %v", err)
			}
		}}

	for _, build := range []struct {
		name  string
		stops []stopV0120
		// marked is the former test whose subject is which inventory owes a
		// check after this database's upgrade.
		marked string
	}{
		{"some of each step", []stopV0120{dates(1), runColumn, scanColumn}, stoppedAfterColumn},
		{"the rest of each step", []stopV0120{dates(3), runIndex}, replacedOwesNoCheck},
	} {
		t.Run(build.name, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				ctx := t.Context()
				dbtest.Empty(t, db)
				dbtest.MigrateTo(t, db, v0110)
				inventories := seedReplacedV0110(t, db)
				for _, stop := range build.stops {
					if stop.servers && db.Server.Engine == database.SQLite {
						continue // SQLite changes a table in one transaction, so it never stops there.
					}
					name := stop.test
					if stop.name != "" {
						name += "/" + stop.name
					}
					// A failed stop leaves the database somewhere the later
					// stops were not written for, so it ends the test.
					if !t.Run("stopped/"+name, func(t *testing.T) { stop.make(t, db) }) {
						t.FailNow()
					}
				}
				dbtest.MigrateTo(t, db, v0120)
				t.Run("resumed/TheV0120DeclarationsAreBuiltAfterEveryStop", func(t *testing.T) {
					declarationsAreBuilt(t, ctx, db, migrations.StatementsV0120(db.Server.Engine))
				})
				// An inventory v0.11.0 left replaced owes no check after the
				// upgrade; the one still current owes one once something
				// replaces it.
				t.Run("resumed/"+build.marked, func(t *testing.T) {
					inventories.oweChecks(t, db)
				})
				leaveAtLatest(t, ctx, db)
			})
		})
	}
}

// timestampOn is how an engine declares a moment, as the migrations do.
func timestampOn(engine database.Engine) string {
	switch engine {
	case database.Postgres:
		return "TIMESTAMPTZ"
	case database.SQLite:
		return "DATETIME"
	default:
		return "DATETIME(6)"
	}
}

// inventoriesV0110 is a v0.11.0 build with a replaced inventory and a current
// one, and a way to receive another.
type inventoriesV0110 struct {
	replaced, current int64
	scanned           func(t *testing.T, n int) int64
}

// seedReplacedV0110 seeds a v0.11.0 build with a replaced inventory and a
// current one.
func seedReplacedV0110(t *testing.T, db *database.DB) inventoriesV0110 {
	t.Helper()
	ctx := t.Context()
	at := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
	exec, id := seedSQL(ctx, db)
	exec(t, `INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
	product := id(t, `SELECT MAX("id") FROM "product"`)
	exec(t, `INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
		VALUES (?, ?, ?, ?, ?)`, product, "main", "main", "branch", at)
	line := id(t, `SELECT MAX("id") FROM "branch_or_tag"`)
	exec(t, `INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
		VALUES (?, ?, ?, ?, ?)`, product, "image", "Image", true, at)
	variant := id(t, `SELECT MAX("id") FROM "variant"`)
	exec(t, `INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`, line, variant, at)
	build := id(t, `SELECT MAX("id") FROM "build"`)
	out := inventoriesV0110{scanned: func(t *testing.T, n int) int64 {
		exec(t, `INSERT INTO "scan" ("build_id", "content_hash", "built_at", "received_at", "parser_version",
			"status", "components") VALUES (?, ?, ?, ?, ?, ?, ?)`,
			build, fmt.Sprintf("hash-%d", n), at.Add(time.Duration(n)*time.Hour),
			at.Add(time.Duration(n)*time.Hour), "test", "accepted", 1)
		return id(t, `SELECT MAX("id") FROM "scan"`)
	}}
	out.replaced, out.current = out.scanned(t, 1), out.scanned(t, 2)
	return out
}

// oweChecks receives an inventory after the upgrade and checks which of the
// build's inventories owes a check.
func (is inventoriesV0110) oweChecks(t *testing.T, db *database.DB) {
	t.Helper()
	after := is.scanned(t, 3)
	unchecked := func(scan int64) bool {
		var out bool
		if err := db.DB.NewRaw(`SELECT "replaced_unchecked" FROM "scan" WHERE "id" = ?`, scan).
			Scan(t.Context(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	switch {
	case !unchecked(is.replaced):
		t.Error("an inventory replaced before the upgrade owes a check")
	case unchecked(is.current):
		t.Error("an inventory replaced after the upgrade owes none")
	case unchecked(after):
		t.Error("an inventory arriving after the upgrade owes none")
	}
}
