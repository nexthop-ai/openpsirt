package notify_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// The notification area is the one read surface that was not narrowed by a
// subject: the query was person, unread, uncleared and nothing else, so
// visibility was checked only at the moment of telling. Somebody whose right to
// read undisclosed work was withdrawn kept a list naming undisclosed findings
// in a product that is supposed to read to them as not existing.
//
// Filtered rather than deleted, on purpose. Destroying the row destroys the
// record that somebody was told, which is exactly what an auditor wants after a
// leak — and restoring the role brings the line back, because they were told.
func TestWithdrawingTheRoleTakesAwayWhatItLetSomebodyBeTold(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		reader, err := rights.Ensure(ctx, "reader@example.com", "Reader", nil)
		if err != nil {
			t.Fatal(err)
		}
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, reader.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		ids, err := finding.NewVulnerabilities(db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "SONIC-2026-7001", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := ids["SONIC-2026-7001"]

		store := notify.NewStore(db.DB)
		// One about something undisclosed, and one about something anybody
		// there may read. Only the first is the role's to take away.
		if err := store.Tell(ctx, notify.Telling{
			PersonID: reader.ID, Kind: notify.Assigned,
			Body: "SONIC-2026-7001, which nobody has announced", Link: "/findings",
			Private: true, ProductID: &product.ID, VulnerabilityID: &issue,
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.Tell(ctx, notify.Telling{
			PersonID: reader.ID, Kind: notify.Assigned,
			Body: "something already public", Link: "/findings",
			ProductID: &product.ID,
		}); err != nil {
			t.Fatal(err)
		}

		// The list and the count go through the same conditions. A badge
		// counting what the list will not show is the leak as a number, which
		// still answers "is there something here about this".
		waiting := func() (int, int) {
			t.Helper()
			rows, total, err := store.Waiting(ctx, asks(t, db, reader), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return len(rows), total
		}

		if rows, total := waiting(); rows != 2 || total != 2 {
			t.Fatalf("holding the role: %d rows and a count of %d, want 2 and 2", rows, total)
		}

		if err := rights.Withdraw(ctx, reader.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, reader.ID, product.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		if rows, total := waiting(); rows != 1 || total != 1 {
			t.Fatalf("after the role was withdrawn: %d rows and a count of %d, want 1 and 1", rows, total)
		}

		// It was not deleted. Granting the role back returns it, because they
		// were told and that is a fact about a moment.
		if err := rights.GrantRole(ctx, reader.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		if rows, total := waiting(); rows != 2 || total != 2 {
			t.Fatalf("after the role came back: %d rows and a count of %d, want 2 and 2", rows, total)
		}
	})
}

// A collaborator holds no role on the product at all — that is the whole of
// what a case grant is — so the pair is what reaches the line, and widening it
// to the product would hand them the rest of that product's embargo list.
func TestACaseGrantReachesWhatSomebodyWasToldAboutThatIssueAndNoOther(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		guest, err := rights.Ensure(ctx, "guest@example.com", "Guest", nil)
		if err != nil {
			t.Fatal(err)
		}
		granter, err := rights.Ensure(ctx, "granter@example.com", "Granter", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		ids, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "SONIC-2026-7002", Severity: "high"},
			{Identifier: "SONIC-2026-7003", Severity: "high"},
		})
		if err != nil {
			t.Fatal(err)
		}
		theirs, other := ids["SONIC-2026-7002"], ids["SONIC-2026-7003"]
		if err := rights.AddToCase(ctx, product.ID, theirs, guest.ID, granter.ID); err != nil {
			t.Fatal(err)
		}

		store := notify.NewStore(db.DB)
		for _, issue := range []int64{theirs, other} {
			if err := store.Tell(ctx, notify.Telling{
				PersonID: guest.ID, Kind: notify.BroughtIn,
				Body: "an undisclosed finding", Link: "/findings",
				Private: true, ProductID: &product.ID, VulnerabilityID: &issue,
			}); err != nil {
				t.Fatal(err)
			}
		}

		rows, total, err := store.Waiting(ctx, asks(t, db, guest), 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || total != 1 {
			t.Fatalf("a collaborator saw %d rows and a count of %d, want 1 and 1", len(rows), total)
		}
		if rows[0].VulnerabilityID == nil || *rows[0].VulnerabilityID != theirs {
			t.Errorf("the row they can read is not the case they were brought into")
		}
	})
}

// A private telling that names no product cannot be narrowed by anything, so
// it would have to be shown to everybody or to nobody. Refused where it is
// written instead, which makes it a failure at the producer rather than a leak
// or a silent disappearance at the reader.
func TestSomethingUndisclosedThatNamesNoProductIsRefused(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		person, err := access.NewStore(db.DB).Ensure(ctx, "someone@example.com", "Someone", nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		if err := store.Tell(ctx, notify.Telling{
			PersonID: person.ID, Kind: notify.Assigned,
			Body: "something undisclosed", Link: "/findings", Private: true,
		}); err == nil {
			t.Fatal("a private telling with no product was recorded, and nothing could narrow it")
		}
		if _, _, err := store.Reconcile(ctx, person.ID, notify.DisclosureDue, []notify.Holds{{
			About: "x", Body: "something undisclosed", Link: "/findings", Private: true,
		}}); err == nil {
			t.Fatal("a private condition with no product was recorded")
		}
	})
}

// Reading a list addressed to somebody else is an administrator's act and
// nobody else's. Every other read of this table is somebody reading their own;
// this one exists so a leak can be investigated, which is the only reason to
// look at what was sent to another person.
func TestOnlyAnAdministratorReadsWhatSomebodyElseWasTold(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		subjectOf, err := rights.Ensure(ctx, "told@example.com", "Told", nil)
		if err != nil {
			t.Fatal(err)
		}
		nosy, err := rights.Ensure(ctx, "nosy@example.com", "Nosy", nil)
		if err != nil {
			t.Fatal(err)
		}
		boss, err := rights.Ensure(ctx, "boss@example.com", "Boss", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		// Everything the ordinary reader could hold, so that being refused is
		// about not administering rather than about holding nothing.
		if err := rights.GrantRole(ctx, nosy.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}

		store := notify.NewStore(db.DB)
		if err := store.Tell(ctx, notify.Telling{
			PersonID: subjectOf.ID, Kind: notify.Assigned,
			Body: "something", Link: "/findings", ProductID: &product.ID,
		}); err != nil {
			t.Fatal(err)
		}

		if _, _, err := store.ToldTo(ctx, asks(t, db, nosy), subjectOf.ID, 50, 0); err == nil {
			t.Error("somebody who is not an administrator read another person's list")
		}
		rows, total, err := store.ToldTo(ctx, asks(t, db, boss), subjectOf.ID, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || total != 1 {
			t.Errorf("an administrator saw %d rows and a count of %d, want 1 and 1", len(rows), total)
		}
	})
}
