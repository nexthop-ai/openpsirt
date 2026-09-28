// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// v050 is the migration v0.5.0 carries v0.4.0's schema and rows across with.
const v050 = 39

// Upgraded, a name in configuration is administration of its own, and the
// column administration granted here is written to holds only that. What a
// group derived stays derived, and a grant made here with no name beside it
// stays. Rolled back, the name is written back into the column v0.4.0 reads.
func TestAnUpgradeLeavesConfigurationsAdministrationToTheName(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)

		// The rows v0.4.0 leaves: every named administrator's column set.
		store := access.NewStore(db.DB)
		for _, row := range []struct {
			identity       string
			named, derived bool
		}{
			{"named", true, false},
			{"named-and-derived", true, true},
			{"granted-here", false, false},
		} {
			person, err := store.Ensure(ctx, row.identity, "", access.Stated(true), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.NewRaw(`UPDATE "person" SET "is_bootstrap" = ?, "admin_derived" = ?`+
				` WHERE "id" = ?`, row.named, row.derived, person.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		dbtest.MigrateTo(t, db, v050)
		want := map[string]bool{"named": false, "named-and-derived": true, "granted-here": true}
		for identity, admin := range want {
			if got := columnSaysAdministers(t, ctx, db, identity); got != admin {
				t.Errorf("upgraded, %s's column says %v, want %v", identity, got, admin)
			}
		}
		// Still an administrator, through the name.
		if subject, err := store.Resolve(ctx, "named"); err != nil || !subject.Admin {
			t.Errorf("upgraded, a named administrator does not administer: %v", err)
		}

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		for identity := range want {
			if !columnSaysAdministers(t, ctx, db, identity) {
				t.Errorf("rolled back, %s's column no longer says they administer", identity)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

func columnSaysAdministers(t *testing.T, ctx context.Context, db *database.DB, identity string) bool {
	t.Helper()
	var admin bool
	if err := db.DB.NewRaw(`SELECT "is_admin" FROM "person" WHERE "identity" = ?`, identity).
		Scan(ctx, &admin); err != nil {
		t.Fatalf("read %s: %v", identity, err)
	}
	return admin
}

// Upgraded, every name an issue answers to is marked as not recorded by hand,
// and a name recorded afterwards can say it was. Rolled back, the column is
// gone and the names are still there.
func TestAnUpgradeMarksEveryNameAsNotRecordedByHand(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)

		if _, err := db.DB.NewRaw(`INSERT INTO "vulnerability"
			("identifier", "identifier_folded", "exploited", "first_seen_at")
			VALUES (?, ?, ?, ?)`, "CVE-2026-0001", "cve-2026-0001", false,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		var issue int64
		if err := db.DB.NewRaw(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`,
			"CVE-2026-0001").Scan(ctx, &issue); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "vulnerability_alias"
			("vulnerability_id", "identifier", "identifier_folded") VALUES (?, ?, ?)`,
			issue, "GHSA-2222-3333-4444", "ghsa-2222-3333-4444").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		dbtest.MigrateTo(t, db, v050)
		if byHand(t, ctx, db, "GHSA-2222-3333-4444") {
			t.Error("upgraded, a name v0.4.0 held reads as recorded by hand")
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "vulnerability_alias"
			("vulnerability_id", "identifier", "identifier_folded", "by_hand") VALUES (?, ?, ?, ?)`,
			issue, "CVE-2026-0002", "cve-2026-0002", true).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if !byHand(t, ctx, db, "CVE-2026-0002") {
			t.Error("upgraded, a name recorded by hand does not say so")
		}

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		var names int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "vulnerability_alias"`).Scan(ctx, &names); err != nil {
			t.Fatal(err)
		}
		if names != 2 {
			t.Errorf("rolled back, %d names remain, want 2", names)
		}
		if err := db.DB.NewRaw(`SELECT "by_hand" FROM "vulnerability_alias"`).Scan(ctx, new(bool)); err == nil {
			t.Error("rolled back, the column is still there")
		}
		leaveAtLatest(t, ctx, db)
	})
}

func byHand(t *testing.T, ctx context.Context, db *database.DB, name string) bool {
	t.Helper()
	var held bool
	if err := db.DB.NewRaw(`SELECT "by_hand" FROM "vulnerability_alias" WHERE "identifier" = ?`, name).
		Scan(ctx, &held); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return held
}
