package notify_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

func TestTheSweepClearsSessionsThatHaveRunOut(t *testing.T) {
	// Sessions are the one table that grows with use, and an expired one is
	// refused on sight — so without a caller for the clearing, the table
	// grows for as long as the deployment lives. The sweep is that caller.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		person, err := rights.Ensure(ctx, "someone", "", true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rights.StartSession(ctx, person.ID, time.Hour); err != nil {
			t.Fatal(err)
		}
		// Aged directly rather than through a clock: what is pinned is that
		// the sweep reaches the table, not how a session is judged expired.
		if _, err := db.DB.NewUpdate().Table("session").
			Set("expires_at = ?", time.Now().UTC().Add(-time.Minute)).
			Where("person_id = ?", person.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		live, err := rights.StartSession(ctx, person.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		gone, err := notify.NewWatch(db.DB, quiet).Tidy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if gone != 1 {
			t.Errorf("the sweep cleared %d sessions, want 1", gone)
		}
		if _, _, err := rights.ResolveSession(ctx, live.Token); err != nil {
			t.Errorf("the live session went with the expired one: %v", err)
		}
		var remaining int
		if err := db.DB.NewSelect().Table("session").ColumnExpr("COUNT(*)").Scan(ctx, &remaining); err != nil {
			t.Fatal(err)
		}
		if remaining != 1 {
			t.Errorf("%d sessions remain, want the live one alone", remaining)
		}
	})
}
