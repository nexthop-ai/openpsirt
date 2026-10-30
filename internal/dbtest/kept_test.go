// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Rows a seed wrote on a server and the harness wrote back read the same as
// they did when the seed wrote them: every column, a moment to the
// microsecond, a date, a true and a false, an absent value, text outside
// ASCII, and a row referencing another of its own table.
func TestSeededRowsWrittenBackReadAsTheSeedWroteThem(t *testing.T) {
	Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		at := time.Date(2026, 10, 30, 12, 34, 56, 123456000, time.UTC)
		on := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, query, args...); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}
		exec(`INSERT INTO "product" ("name", "display_name", "eol_on", "pair_share", "created_at")
			VALUES (?, ?, ?, ?, ?)`, "kept", "Kept ünïcode — 製品", on, 40, at)
		var product int64
		if err := db.NewSelect().TableExpr(`"product"`).ColumnExpr(`"id"`).Scan(ctx, &product); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "master", "Master", "branch", at)
		var branch int64
		if err := db.NewSelect().TableExpr(`"branch_or_tag"`).ColumnExpr(`"id"`).Scan(ctx, &branch); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "parent_id",
			"released_on", "created_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
			product, "v1", "V1", "tag", branch, on, at)
		for _, facing := range []bool{true, false} {
			exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
				VALUES (?, ?, ?, ?, ?)`, product, fmt.Sprint(facing), "Variant", facing, at)
		}

		seeded, err := keep(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if err := clear(ctx, db); err != nil {
			t.Fatal(err)
		}
		if err := restore(ctx, db, seeded); err != nil {
			t.Fatal(err)
		}
		again, err := keep(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := render(again), render(seeded); got != want {
			t.Errorf("written back, the rows read\n%s\nand the seed wrote\n%s", got, want)
		}

		var row struct {
			Display string     `bun:"display_name"`
			EOL     time.Time  `bun:"eol_on"`
			Share   *int       `bun:"pair_share"`
			Created time.Time  `bun:"created_at"`
			Retired *time.Time `bun:"retired_at"`
		}
		if err := db.NewSelect().TableExpr(`"product"`).
			ColumnExpr(`"display_name", "eol_on", "pair_share", "created_at", "retired_at"`).
			Where(`"id" = ?`, product).Scan(ctx, &row); err != nil {
			t.Fatalf("the product is not at the identifier it was written with: %v", err)
		}
		if row.Display != "Kept ünïcode — 製品" || !row.EOL.Equal(on) || row.Share == nil || *row.Share != 40 ||
			!row.Created.Equal(at) || row.Retired != nil {
			t.Errorf("the product reads back as %+v", row)
		}
		var facing []bool
		if err := db.NewSelect().TableExpr(`"variant"`).ColumnExpr(`"customer_facing"`).
			OrderExpr(`"id"`).Scan(ctx, &facing); err != nil {
			t.Fatal(err)
		}
		if len(facing) != 2 || !facing[0] || facing[1] {
			t.Errorf("the variants read back as reaching customers %v, want [true false]", facing)
		}
	})
}

// render spells kept rows so two reads compare as text, a moment by its
// instant, whatever location the driver handed it in.
func render(kept []keptTable) string {
	out := ""
	for _, table := range kept {
		out += table.name + fmt.Sprint(table.columns) + "\n"
		for _, row := range table.rows {
			for _, value := range row {
				switch v := value.(type) {
				case time.Time:
					out += " " + v.UTC().Format(time.RFC3339Nano)
				case []byte:
					out += fmt.Sprintf(" %q", v)
				default:
					out += fmt.Sprintf(" %#v", v)
				}
			}
			out += "\n"
		}
	}
	return out
}
