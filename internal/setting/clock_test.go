package setting

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// TestTwoWritesInOneInstantStillRecordTheSetting pins why existence is asked
// rather than read from the number of rows an update touched.
//
// Two of the four engines count rows *changed*, not rows matched: an update
// writing values identical to the stored ones reports zero, which is the same
// number "no such row" reports. Ordinarily the timestamp moves and hides this,
// so the only way to reach it is to stop the clock — which is exactly what a
// second write inside the same microsecond does.
//
// Measured directly on MySQL 8.4: updating a row to the value it already holds
// reports 0, updating it to a different value reports 1, and updating a row
// that does not exist reports 0.
func TestTwoWritesInOneInstantStillRecordTheSetting(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)

		frozen := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
		store := &Store{db: db.DB, now: func() time.Time { return frozen }}

		ctx := t.Context()
		if err := store.Set(ctx, SessionLifetime, "8h"); err != nil {
			t.Fatal(err)
		}
		if err := store.Set(ctx, SessionLifetime, "8h"); err != nil {
			t.Fatalf("writing the same value at the same instant: %v", err)
		}

		got, err := store.Duration(ctx, SessionLifetime, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got != 8*time.Hour {
			t.Errorf("read back %v, want 8h", got)
		}
	})
}
