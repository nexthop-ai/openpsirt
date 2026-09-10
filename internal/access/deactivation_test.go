package access_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// REQ-45: we cannot detect that somebody has left. A provider never tells us an
// account was disabled, and somebody who left never signs in again — so their
// account stays live, holding whatever it held, being served everything.
//
// **Every way in is one way in.** A session, a personal token and a
// group-bound sign-in all resolve by identity, so the date is read there once
// rather than in three places that can disagree.
func TestSomebodyWhoHasLeftIsRefusedAtEveryWayIn(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		person, err := rights.Ensure(ctx, "leaver@example.com", "Leaver", false)
		if err != nil {
			t.Fatal(err)
		}
		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, person.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		if _, err := rights.Resolve(ctx, person.Identity); err != nil {
			t.Fatalf("they could not sign in before leaving: %v", err)
		}

		moved, err := rights.Deactivate(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !moved {
			t.Fatal("deactivating somebody active reported that nothing changed")
		}
		if _, err := rights.Resolve(ctx, person.Identity); err == nil {
			t.Error("somebody who has left signed in")
		}

		// The roles are deliberately still there. What they held is part of
		// why the record reads as it does, and bringing them back should not
		// mean reconstructing it.
		held, err := rights.Grants(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) == 0 {
			t.Error("leaving withdrew their roles, so bringing them back means granting again")
		}

		// Twice is not an error and does not move the date: the date is when
		// they left, and an administrator clicking again is the ordinary case.
		again, err := rights.Deactivate(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if again {
			t.Error("deactivating somebody who had already left moved the date")
		}

		back, err := rights.Reactivate(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !back {
			t.Fatal("reactivating somebody who had left reported that nothing changed")
		}
		if _, err := rights.Resolve(ctx, person.Identity); err != nil {
			t.Errorf("somebody brought back could not sign in: %v", err)
		}
	})
}
