package schema_test

import (
	"context"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

func TestAReservedWordIsUsableAsAColumnName(t *testing.T) {
	// The reason every identifier in the data definition is quoted, and the
	// reason two of the engines are asked for standard quoting on connect.
	//
	// A column named for a word one engine happens to reserve is refused
	// outright there and accepted everywhere else — a failure that appears
	// only on whichever engine somebody is least likely to be developing
	// against. Quoting makes the question stop arising, and this is what says
	// the quoting is actually in force rather than merely written down.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := context.Background()
		// Reserved somewhere among the four: a window function, two clauses,
		// and a statement keyword.
		probe := probeTable(t)
		create := `CREATE TABLE "` + probe + `" (
			"rank" BIGINT NOT NULL, "order" INT, "select" INT, "group" INT)`
		if _, err := db.ExecContext(ctx, create); err != nil {
			t.Fatalf("a table of reserved names was refused: %v", err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DROP TABLE "`+probe+`"`) })

		if _, err := db.ExecContext(ctx,
			`INSERT INTO "`+probe+`" ("rank", "order", "select", "group") VALUES (1, 2, 3, 4)`); err != nil {
			t.Fatalf("insert: %v", err)
		}
		var rank int
		if err := db.QueryRowContext(ctx,
			`SELECT "rank" FROM "`+probe+`" WHERE "order" = 2`).Scan(&rank); err != nil {
			t.Fatalf("select: %v", err)
		}
		if rank != 1 {
			t.Errorf("read %d, want 1", rank)
		}
	})
}
