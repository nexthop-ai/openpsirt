// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// manyHeld is a list of conditions long enough to need three statements, one
// past two full batches, with every other one about a product.
func manyHeld(productID int64, body string) []notify.Holds {
	held := make([]notify.Holds, 2*database.BatchSize+1)
	for i := range held {
		held[i] = notify.Holds{
			About: fmt.Sprintf("claim-waiting %05d", i),
			Body:  fmt.Sprintf("%s %d", body, i),
			Link:  "/review",
		}
		if i%2 == 0 {
			held[i].ProductID = &productID
		}
	}
	return held
}

// writesTo is how many statements sent begin with verb and name the
// notification table.
func writesTo(s *sentQueries, verb string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, query := range s.sent {
		if strings.HasPrefix(query, verb) && strings.Contains(query, `"notification"`) {
			n++
		}
	}
	return n
}

// openNow is every open condition of one kind held by one person, by what it
// is about.
func openNow(t *testing.T, db bun.IDB, personID int64, kind notify.Kind) map[string]notify.Notification {
	t.Helper()
	var rows []notify.Notification
	if err := db.NewSelect().Model(&rows).
		Where("person_id = ?", personID).Where("kind = ?", kind).Where("cleared_at IS NULL").
		Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]notify.Notification, len(rows))
	for _, row := range rows {
		if _, twice := out[row.About]; twice {
			t.Errorf("%q is open twice", row.About)
		}
		out[row.About] = row
	}
	return out
}

// saysExactly fails where the open conditions are not the list handed over.
func saysExactly(t *testing.T, open map[string]notify.Notification, held []notify.Holds) {
	t.Helper()
	if len(open) != len(held) {
		t.Fatalf("%d conditions are open, want %d", len(open), len(held))
	}
	for _, h := range held {
		row, ok := open[h.About]
		switch {
		case !ok:
			t.Errorf("%q is not open", h.About)
		case row.Body != h.Body || row.Link != h.Link || row.Private != h.Private ||
			fmt.Sprint(deref(row.ProductID)) != fmt.Sprint(deref(h.ProductID)) ||
			row.TeamID != nil || row.VulnerabilityID != nil ||
			row.AboutOpen == nil || *row.AboutOpen != h.About:
			t.Errorf("%q is stored as %+v, want %+v", h.About, row, h)
		}
	}
}

func deref(id *int64) any {
	if id == nil {
		return nil
	}
	return *id
}

func TestAReconcileWritesABatchAStatementHoweverManyConditionsMove(t *testing.T) {
	// One sweep can open, restate or clear tens of thousands of conditions
	// for one person, and a statement each is a round trip each. The writes
	// go a batch to a statement, so three batches' worth is three statements
	// whichever of the three it is — and what is stored is still exactly the
	// list handed over, a different sentence on every row.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		who, err := access.NewStore(w.DB.DB).Ensure(ctx, "me@example.com", "Me", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(w.DB.DB)
		sent := &sentQueries{}
		w.DB.AddQueryHook(sent)
		reconcile := func(held []notify.Holds) (int, int) {
			t.Helper()
			sent.mu.Lock()
			sent.sent = nil
			sent.mu.Unlock()
			opened, cleared, err := store.Reconcile(ctx, who.ID, notify.ClaimWaiting, held)
			if err != nil {
				t.Fatal(err)
			}
			return opened, cleared
		}

		held := manyHeld(w.Product.ID, "waiting")
		if opened, cleared := reconcile(held); opened != len(held) || cleared != 0 {
			t.Fatalf("opened %d cleared %d, want %d and 0", opened, cleared, len(held))
		}
		if n := writesTo(sent, "INSERT"); n != 3 {
			t.Errorf("%d conditions were opened in %d statements, want 3", len(held), n)
		}
		saysExactly(t, openNow(t, w.DB.DB, who.ID, notify.ClaimWaiting), held)

		// Every sentence moves, and which rows name a product swaps over:
		// the ones that named it stop, and the others name it undisclosed.
		moved := manyHeld(w.Product.ID, "still waiting")
		for i := range moved {
			if i%2 == 0 {
				moved[i].ProductID = nil
			} else {
				moved[i].ProductID, moved[i].Private = &w.Product.ID, true
			}
		}
		if opened, cleared := reconcile(moved); opened != 0 || cleared != 0 {
			t.Fatalf("restating opened %d cleared %d, want nothing", opened, cleared)
		}
		if n := writesTo(sent, "UPDATE"); n != 3 {
			t.Errorf("%d conditions were restated in %d statements, want 3", len(moved), n)
		}
		saysExactly(t, openNow(t, w.DB.DB, who.ID, notify.ClaimWaiting), moved)

		if opened, cleared := reconcile(nil); opened != 0 || cleared != len(moved) {
			t.Fatalf("clearing opened %d cleared %d, want 0 and %d", opened, cleared, len(moved))
		}
		if n := writesTo(sent, "UPDATE"); n != 3 {
			t.Errorf("%d conditions were cleared in %d statements, want 3", len(moved), n)
		}
		saysExactly(t, openNow(t, w.DB.DB, who.ID, notify.ClaimWaiting), nil)
	})
}

func TestAConditionAnotherSweepOpensMidBatchIsLeftToItAndTheRestStillOpen(t *testing.T) {
	// Two replicas sweep at once. When the other one opens a condition
	// between this one reading what is open and writing what is new, the
	// batch carrying it is refused for the duplicate, and every other
	// condition in it still opens. Aborting instead leaves everybody after
	// this person told nothing that cycle.
	//
	// Servers only: SQLite takes the write lock as a transaction begins, so
	// the second writer this needs waits for the first to finish.
	dbtest.Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		who, err := access.NewStore(db.DB).Ensure(ctx, "me@example.com", "Me", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		held := make([]notify.Holds, database.BatchSize+1)
		for i := range held {
			held[i] = notify.Holds{About: fmt.Sprintf("build %04d", i), Body: fmt.Sprintf("quiet %d", i)}
		}
		other := held[database.BatchSize/2]
		hooked, rival := dbtest.RivalAfterRead(t, db, "notification", "notification", 5*time.Second, func() error {
			opened, _, err := notify.NewStore(db.DB).Reconcile(ctx, who.ID, notify.BuildQuiet,
				[]notify.Holds{other})
			if err == nil && opened != 1 {
				err = fmt.Errorf("opened %d, want 1", opened)
			}
			return err
		})

		opened, cleared, err := notify.NewStore(hooked).Reconcile(ctx, who.ID, notify.BuildQuiet, held)
		if err != nil {
			t.Fatalf("a sweep failed because another opened one of its conditions first: %v", err)
		}
		if err := rival(); err != nil {
			t.Errorf("the other sweep: %v", err)
		}
		if opened != len(held)-1 || cleared != 0 {
			t.Errorf("opened %d cleared %d, want %d and 0", opened, cleared, len(held)-1)
		}
		saysExactly(t, openNow(t, db.DB, who.ID, notify.BuildQuiet), held)
	})
}

func TestAReconcileThatLosesItsCommitCountsWhatTheRetryWrote(t *testing.T) {
	// A cluster can refuse a transaction at COMMIT after every statement in
	// it succeeded, and the helper runs the whole closure again. The counts
	// are what the run that committed wrote, never the sum of both runs.
	db, race := dbtest.Racing(t, nil)
	ctx := t.Context()
	who, err := access.NewStore(db.DB).Ensure(ctx, "me@example.com", "Me", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	held := make([]notify.Holds, database.BatchSize+1)
	for i := range held {
		held[i] = notify.Holds{About: fmt.Sprintf("build %04d", i), Body: "quiet"}
	}
	race.Arm(1)
	opened, cleared, err := notify.NewStore(db.DB).Reconcile(ctx, who.ID, notify.BuildQuiet, held)
	if err != nil {
		t.Fatal(err)
	}
	if race.Unspent() != 0 {
		t.Fatal("no commit lost its race, so this checked nothing")
	}
	if opened != len(held) || cleared != 0 {
		t.Errorf("opened %d cleared %d, want %d and 0", opened, cleared, len(held))
	}
	saysExactly(t, openNow(t, db.DB, who.ID, notify.BuildQuiet), held)
}
