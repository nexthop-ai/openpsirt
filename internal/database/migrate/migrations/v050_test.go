// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/uptrace/bun"
)

// v050 is the migration v0.5.0 carries v0.4.0's schema and rows across with.
const v050 = 39

// upgradeCheck is one thing the upgrade to v0.5.0 holds to: the rows it puts
// in a v0.4.0 database, what it asserts once that database is upgraded, what
// a roll back it expects to be refused, and what it asserts once rolled back.
// A phase a check has nothing to say in is nil.
//
// Every check's rows sit in one database, so a check reads its own rows by
// what identifies them rather than by counting a table. The checks are built
// once and seeded once per engine, so a seed resets whatever state it keeps.
type upgradeCheck struct {
	name       string
	seed       func(t *testing.T, ctx context.Context, db *database.DB)
	upgraded   func(t *testing.T, ctx context.Context, db *database.DB)
	refused    func(t *testing.T, ctx context.Context, db *database.DB)
	rolledBack func(t *testing.T, ctx context.Context, db *database.DB)
}

// A v0.4.0 database holding the rows every check puts in it is upgraded once
// and rolled back once, and each check asserts its half at each step as a
// subtest named for what it holds.
//
// One build serves every check. Building v0.4.0 walks every migration down and
// up again, 1.4 s to 2.6 s on SQLite and most of what a check costs.
func TestAV040DatabaseUpgradesToV050AndBack(t *testing.T) {
	checks := []upgradeCheck{
		administrationIsLeftToTheName(),
		everyNameIsMarkedAsNotRecordedByHand(),
		identitiesNodesAndSendersComeAcross(),
		everyIssueIsReadAsItself(),
		everyTrailRowIsAPersons(),
		everyDestinationIsAWebhook(),
		keyNamesAreFoldedAndClashesWithdrawn(),
		tokenNamesAreFoldedAndClashesWithdrawn(),
		claimSubjectsAreFolded(),
		theV050DeclarationsAreTheTablesTheMigrationsBuild(),
	}
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)
		for _, check := range checks {
			if check.seed != nil {
				check.seed(t, ctx, db)
			}
		}

		dbtest.MigrateTo(t, db, v050)
		phase(t, ctx, db, "upgraded", checks, func(c upgradeCheck) phaseFunc { return c.upgraded })
		phase(t, ctx, db, "refused", checks, func(c upgradeCheck) phaseFunc { return c.refused })
		// A refusal that was not refused rolled the database back, and every
		// check after it would fail for that rather than for what it names.
		if at, err := schema.Version(ctx, db); err != nil || at != v050 {
			t.Fatalf("after the refused roll backs the database is at %d, want %d: %v", at, v050, err)
		}

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		phase(t, ctx, db, "rolled back", checks, func(c upgradeCheck) phaseFunc { return c.rolledBack })
		leaveAtLatest(t, ctx, db)
	})
}

type phaseFunc = func(t *testing.T, ctx context.Context, db *database.DB)

// phase runs one step's assertions, each check's as a subtest of its own.
func phase(t *testing.T, ctx context.Context, db *database.DB, name string, checks []upgradeCheck,
	step func(upgradeCheck) phaseFunc) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		for _, check := range checks {
			if fn := step(check); fn != nil {
				t.Run(check.name, func(t *testing.T) { fn(t, ctx, db) })
			}
		}
	})
}

// Upgraded, a name in configuration is administration of its own, and the
// column administration granted here is written to holds only that. What a
// group derived stays derived, and a grant made here with no name beside it
// stays. Rolled back, the name is written back into the column v0.4.0 reads.
func administrationIsLeftToTheName() upgradeCheck {
	want := map[string]bool{"named": false, "named-and-derived": true, "granted-here": true}
	return upgradeCheck{
		name: "AnUpgradeLeavesConfigurationsAdministrationToTheName",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
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
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			for identity, admin := range want {
				if got := columnSaysAdministers(t, ctx, db, identity); got != admin {
					t.Errorf("upgraded, %s's column says %v, want %v", identity, got, admin)
				}
			}
			// Still an administrator, through the name.
			if subject, err := access.NewStore(db.DB).Resolve(ctx, "named"); err != nil || !subject.Admin {
				t.Errorf("upgraded, a named administrator does not administer: %v", err)
			}
		},
		rolledBack: func(t *testing.T, ctx context.Context, db *database.DB) {
			for identity := range want {
				if !columnSaysAdministers(t, ctx, db, identity) {
					t.Errorf("rolled back, %s's column no longer says they administer", identity)
				}
			}
		},
	}
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
func everyNameIsMarkedAsNotRecordedByHand() upgradeCheck {
	var issue int64
	return upgradeCheck{
		name: "AnUpgradeMarksEveryNameAsNotRecordedByHand",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			issue = insertIssue(t, ctx, db, "CVE-2026-0001")
			if _, err := db.DB.NewRaw(`INSERT INTO "vulnerability_alias"
				("vulnerability_id", "identifier", "identifier_folded") VALUES (?, ?, ?)`,
				issue, "GHSA-2222-3333-4444", "ghsa-2222-3333-4444").Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
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
		},
		rolledBack: func(t *testing.T, ctx context.Context, db *database.DB) {
			var names int
			if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "vulnerability_alias" WHERE "vulnerability_id" = ?`,
				issue).Scan(ctx, &names); err != nil {
				t.Fatal(err)
			}
			if names != 2 {
				t.Errorf("rolled back, %d names remain, want 2", names)
			}
			if err := db.DB.NewRaw(`SELECT "by_hand" FROM "vulnerability_alias"`).Scan(ctx, new(bool)); err == nil {
				t.Error("rolled back, the column is still there")
			}
		},
	}
}

// insertIssue writes an issue as v0.4.0 held one and returns its identifier.
func insertIssue(t *testing.T, ctx context.Context, db *database.DB, name string) int64 {
	t.Helper()
	if _, err := db.DB.NewRaw(`INSERT INTO "vulnerability"
		("identifier", "identifier_folded", "exploited", "first_seen_at")
		VALUES (?, ?, ?, ?)`, name, strings.ToLower(name), false,
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.DB.NewRaw(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, name).
		Scan(ctx, &id); err != nil {
		t.Fatal(err)
	}
	return id
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

// Upgraded, every destination v0.4.0 held is a webhook belonging to the
// deployment. Rolled back, a chat channel goes, because v0.4.0 cannot reach
// one, and the webhook stays as it was.
func everyDestinationIsAWebhook() upgradeCheck {
	// The webhook v0.4.0 held and the chat channel added once upgraded. Other
	// checks may write destinations too, so these are the rows it reads.
	destinations := []string{"paging", "psirt"}
	var admin int64
	return upgradeCheck{
		name: "AnUpgradeLeavesEveryDestinationAWebhook",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			person, err := access.NewStore(db.DB).Ensure(ctx, "destination-admin", "", access.Stated(true), nil)
			if err != nil {
				t.Fatal(err)
			}
			admin = person.ID
			if _, err := db.DB.NewRaw(`INSERT INTO "outbound" ("name", "kind", "url", "secret", `+
				`"created_by", "created_at") VALUES (?, ?, ?, ?, ?, ?)`,
				destinations[0], "*", "https://paging.example/hook", "a-shared-secret-long-enough",
				admin, time.Now().UTC().Truncate(time.Microsecond)).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			var platform string
			var product, team sql.NullInt64
			if err := db.DB.NewRaw(`SELECT "platform", "product_id", "team_id" FROM "outbound" `+
				`WHERE "name" = ?`, destinations[0]).Scan(ctx, &platform, &product, &team); err != nil {
				t.Fatal(err)
			}
			if platform != "webhook" || product.Valid || team.Valid {
				t.Errorf("upgraded, a v0.4.0 destination is %q for product %v and team %v, "+
					"want a webhook for the deployment", platform, product, team)
			}
			if _, err := db.DB.NewRaw(`INSERT INTO "outbound" ("name", "kind", "url", "secret", `+
				`"created_by", "created_at", "platform", "channel") VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				destinations[1], "*", "", "", admin, time.Now().UTC().Truncate(time.Microsecond),
				"slack", "C0123").Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		rolledBack: func(t *testing.T, ctx context.Context, db *database.DB) {
			var names []string
			if err := db.DB.NewRaw(`SELECT "name" FROM "outbound" WHERE "name" IN (?) ORDER BY "name"`,
				bun.List(destinations)).Scan(ctx, &names); err != nil {
				t.Fatal(err)
			}
			if len(names) != 1 || names[0] != destinations[0] {
				t.Errorf("rolled back, the destinations are %v, want the webhook alone", names)
			}
		},
	}
}
