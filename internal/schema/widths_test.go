package schema_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

func TestProducerSuppliedTextIsNotBoundedByAColumn(t *testing.T) {
	// A component's name and version are whatever a producer put in a scan
	// file. Nothing in any format bounds them, and a column that does turns a
	// merely unusual value into a failure of the whole scan that carried it —
	// which is indistinguishable from a product that stopped having problems.
	//
	// Two of the four engines gave this class a 64 KB type while giving the
	// operator-typed class beside it 16 MB, which is the inversion of what the
	// two are declared to mean: typed text is at least bounded at submission,
	// and this is not bounded anywhere.
	//
	// A hundred kilobytes because it is past the smaller type and nowhere near
	// the larger, so this fails on exactly the engines that get it wrong.
	const size = 100 * 1024
	oversized := strings.Repeat("v", size)

	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		// A hex digest, because identity and fold_key are digest columns and
		// are 64 characters wide on every engine. What is under test is the
		// class beside them.
		identity := fmt.Sprintf("%064x", probeCounter.Add(1)+time.Now().UnixNano())
		if _, err := db.ExecContext(ctx,
			`INSERT INTO "component" ("identity", "name", "version", "fold_key", "first_seen_at")
			 VALUES (?, ?, ?, ?, ?)`,
			identity, oversized, oversized, identity, time.Now().UTC()); err != nil {
			t.Fatalf("a %d-byte value a producer supplied was refused: %v", size, err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(ctx, `DELETE FROM "component" WHERE "identity" = ?`, identity)
		})

		var name, version string
		if err := db.QueryRowContext(ctx,
			`SELECT "name", "version" FROM "component" WHERE "identity" = ?`, identity).
			Scan(&name, &version); err != nil {
			t.Fatalf("read back: %v", err)
		}
		for what, got := range map[string]string{"name": name, "version": version} {
			if got != oversized {
				t.Errorf("%s came back %d bytes, wrote %d", what, len(got), size)
			}
		}
	})
}
