// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// settingsHeld is every stored setting, by name.
func settingsHeld(t *testing.T, ctx context.Context, db *database.DB) map[string]string {
	t.Helper()
	var rows []struct {
		Name  string `bun:"name"`
		Value string `bun:"value"`
	}
	if err := db.NewRaw(`SELECT "name", "value" FROM "application_setting"`).Scan(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, row := range rows {
		out[row.Name] = row.Value
	}
	return out
}

// A disclosure movement threshold an operator set under the name v0.1.0 gave
// it is in force after the upgrade, under the name read since; one set under
// the new name stands over the old one; and the patch branch switch, which the
// deployment's configuration now holds, is not left behind unread.
func TestASettingRenamedSinceV010IsCarriedAndAnUnreadOneRemoved(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		at := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)

		for _, from := range []struct {
			name    string
			version int64
		}{{"v0.1.0", v010}, {"v0.2.0", v020}} {
			rollBack(t, ctx, db)
			dbtest.MigrateTo(t, db, from.version)
			exec(t, ctx, db, `DELETE FROM "application_setting"`)
			exec(t, ctx, db, `INSERT INTO "application_setting" ("name", "value", "updated_at")
				VALUES (?, ?, ?), (?, ?, ?)`,
				"disclosure.extension-threshold", "720h0m0s", at,
				"patch.branches", "on", at)
			dbtest.MigrateTo(t, db, v030)
			held := settingsHeld(t, ctx, db)
			if held["disclosure.movement-threshold"] != "720h0m0s" {
				t.Errorf("from %s, the threshold set under its old name reads %q under its new one",
					from.name, held["disclosure.movement-threshold"])
			}
			for _, gone := range []string{"disclosure.extension-threshold", "patch.branches"} {
				if _, ok := held[gone]; ok {
					t.Errorf("from %s, %s is still stored and nothing reads it", from.name, gone)
				}
			}
		}

		// Both names set: the new one is what v0.2.0 read, so it stands.
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v020)
		exec(t, ctx, db, `DELETE FROM "application_setting"`)
		exec(t, ctx, db, `INSERT INTO "application_setting" ("name", "value", "updated_at")
			VALUES (?, ?, ?), (?, ?, ?)`,
			"disclosure.extension-threshold", "720h0m0s", at,
			"disclosure.movement-threshold", "240h0m0s", at)
		dbtest.MigrateTo(t, db, v030)
		if got := settingsHeld(t, ctx, db)["disclosure.movement-threshold"]; got != "240h0m0s" {
			t.Errorf("the threshold set under its new name was replaced by the old one: %q", got)
		}

		// Rolled back, the carried value stays under the name v0.2.0 reads.
		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatal(err)
		}
		if got := settingsHeld(t, ctx, db)["disclosure.movement-threshold"]; got != "240h0m0s" {
			t.Errorf("rolled back, the threshold v0.2.0 reads is %q", got)
		}
		exec(t, ctx, db, `DELETE FROM "application_setting"`)
		leaveAtLatest(t, ctx, db)
	})
}
