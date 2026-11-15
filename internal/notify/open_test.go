// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A batch refused because another replica opened one of its conditions first
// opens the rest a row at a time, leaves that one to the other replica, and
// keeps what the transaction wrote before the batch: a refused statement on
// PostgreSQL would otherwise poison the transaction and its commit would
// throw that write away.
func TestABatchAnotherReplicaGotToFirstOpensTheRestAndKeepsTheTransaction(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		person, err := access.NewStore(db.DB).Ensure(ctx, "me@example.com", "Me", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		condition := func(about string) Notification {
			return Notification{
				PersonID: person.ID, Kind: BuildQuiet, Lifetime: Condition,
				About: about, AboutOpen: &about, Body: "quiet", CreatedAt: now,
			}
		}
		earlier, other := condition("earlier"), condition("x")
		if _, err := db.DB.NewInsert().Model(&earlier).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewInsert().Model(&other).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		var opened int
		if err := database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
			if _, err := tx.NewUpdate().Model((*Notification)(nil)).
				Set(`"body" = ?`, "kept").Where(`"id" = ?`, earlier.ID).Exec(ctx); err != nil {
				return err
			}
			var err error
			opened, err = openBatch(ctx, tx, []Notification{condition("x"), condition("y")})
			return err
		}); err != nil {
			t.Fatalf("a batch another replica got to first failed the transaction: %v", err)
		}
		if opened != 1 {
			t.Errorf("opened %d, want the one nobody else opened", opened)
		}

		var held []Notification
		if err := db.DB.NewSelect().Model(&held).Where(`"person_id" = ?`, person.ID).
			OrderExpr(`"about"`).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		var abouts []string
		for _, n := range held {
			abouts = append(abouts, n.About+"="+n.Body)
		}
		if want := "[earlier=kept x=quiet y=quiet]"; fmt.Sprint(abouts) != want {
			t.Errorf("the table holds %v, want %s", abouts, want)
		}
	})
}
