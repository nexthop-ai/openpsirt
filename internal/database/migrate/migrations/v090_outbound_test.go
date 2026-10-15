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
// destinations: one still in use keeps the key before a retired one, then the
// one already spelled as the key, then the earliest. The other takes the key
// with its own number and is listed under it, so retiring it by the name shown
// reaches it.
func TestAV080DatabaseFoldsItsDestinationNames(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v080)
		who, err := access.NewStore(db.DB).Ensure(ctx, "admin", "", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]int64{}
		for _, each := range []struct {
			name, kind string
			retired    bool
		}{
			{"Ops", "*", false}, {"ops", "*", false}, {" Pager ", "assigned", false},
			{"PAGER", "assigned", false}, {"Chat", "*", false}, {"Chat", "assigned", false},
			{"Feed", "*", false}, {"feed", "*", true},
		} {
			var retired *time.Time
			if each.retired {
				at := time.Now().UTC().Truncate(time.Second)
				retired = &at
			}
			var id int64
			if _, err := db.DB.NewRaw(`INSERT INTO "outbound" ("name", "kind", "url", "secret", `+
				`"created_by", "created_at", "platform", "retired_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				each.name, each.kind, "https://hooks.example/x", "a-secret", who.ID,
				time.Now().UTC().Truncate(time.Second), "webhook", retired).Exec(ctx); err != nil {
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
			"Ops|*":            {"ops-" + strconv.FormatInt(ids["Ops|*"], 10), "ops-" + strconv.FormatInt(ids["Ops|*"], 10)},
			" Pager |assigned": {"pager", "Pager"},
			"PAGER|assigned":   {"pager-" + strconv.FormatInt(ids["PAGER|assigned"], 10), "pager-" + strconv.FormatInt(ids["PAGER|assigned"], 10)},
			"Chat|*":           {"chat", "Chat"},
			"Chat|assigned":    {"chat", "Chat"},
			"Feed|*":           {"feed", "Feed"},
			"feed|*":           {"feed-" + strconv.FormatInt(ids["feed|*"], 10), "feed-" + strconv.FormatInt(ids["feed|*"], 10)},
		} {
			if got[ids[at]] != want {
				t.Errorf("%s was upgraded to %q, want %q", at, got[ids[at]], want)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}
