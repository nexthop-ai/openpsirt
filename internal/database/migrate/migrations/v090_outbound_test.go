// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A v0.8.0 database's destinations are upgraded to names held folded beside
// the spelling typed. Two names one kind held that fold to one key stay two
// destinations: the one already spelled as the key keeps it, or else the
// earliest, and the other takes the key with its own number.
func TestAV080DatabaseFoldsItsDestinationNames(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v080)
		who, err := access.NewStore(db.DB).Ensure(ctx, "admin", "", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]int64{}
		for _, each := range []struct{ name, kind string }{
			{"Ops", "*"}, {"ops", "*"}, {" Pager ", "assigned"}, {"PAGER", "assigned"},
			{"Chat", "*"}, {"Chat", "assigned"},
		} {
			var id int64
			if _, err := db.DB.NewRaw(`INSERT INTO "outbound" ("name", "kind", "url", "secret", `+
				`"created_by", "created_at", "platform") VALUES (?, ?, ?, ?, ?, ?, ?)`,
				each.name, each.kind, "https://hooks.example/x", "a-secret", who.ID,
				time.Now().UTC().Truncate(time.Second), "webhook").Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if err := db.DB.NewRaw(`SELECT MAX("id") FROM "outbound"`).Scan(ctx, &id); err != nil {
				t.Fatal(err)
			}
			ids[each.name+"|"+each.kind] = id
		}
		dbtest.MigrateTo(t, db, v090)

		var rows []struct {
			ID          int64  `bun:"id"`
			Name        string `bun:"name"`
			DisplayName string `bun:"display_name"`
		}
		if err := db.DB.NewRaw(`SELECT "id", "name", "display_name" FROM "outbound"`).
			Scan(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		got := map[int64][2]string{}
		for _, row := range rows {
			got[row.ID] = [2]string{row.Name, row.DisplayName}
		}
		for at, want := range map[string][2]string{
			"ops|*":            {"ops", "ops"},
			"Ops|*":            {"ops-" + strconv.FormatInt(ids["Ops|*"], 10), "Ops"},
			" Pager |assigned": {"pager", "Pager"},
			"PAGER|assigned":   {"pager-" + strconv.FormatInt(ids["PAGER|assigned"], 10), "PAGER"},
			"Chat|*":           {"chat", "Chat"},
			"Chat|assigned":    {"chat", "Chat"},
		} {
			if got[ids[at]] != want {
				t.Errorf("%s was upgraded to %q, want %q", at, got[ids[at]], want)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}
