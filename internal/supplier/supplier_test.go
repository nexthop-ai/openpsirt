// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
)

// The address of a publisher's description of what they publish, as every
// test here names one.
const described = "https://supplier.example/.well-known/csaf/provider-metadata.json"

// configured is a product, an administrator and somebody who is not one.
type configured struct {
	db      *database.DB
	product int64
	admin   access.Subject
	anybody access.Subject
}

func each(t *testing.T, fn func(t *testing.T, f *configured)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		rights := access.NewStore(db.DB)
		boss, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		other, err := rights.Ensure(ctx, "sam@example.com", "Sam", access.Stated(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, &configured{
			db: db, product: product.ID,
			admin:   access.Subject{Kind: access.Person, ID: boss.ID, Identity: boss.Email, Admin: true},
			anybody: access.Subject{Kind: access.Person, ID: other.ID, Identity: other.Email},
		})
	})
}

func TestASupplierIsConfiguredListedAndWithdrawn(t *testing.T) {
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)

		if _, err := store.Add(ctx, f.admin, f.product, "SUSE", described); err != nil {
			t.Fatal(err)
		}
		rows, err := store.For(ctx, f.admin, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Display != "SUSE" || rows[0].URL != described {
			t.Fatalf("the product reads as configured with %+v", rows)
		}

		if err := store.Retire(ctx, f.admin, f.product, "SUSE"); err != nil {
			t.Fatal(err)
		}
		rows, err = store.For(ctx, f.admin, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("a withdrawn supplier is still listed: %+v", rows)
		}
		// And the pass no longer reaches it, which is the half that matters:
		// a supplier believed withdrawn that was not is a request leaving this
		// deployment that somebody thought they had stopped.
		due, err := store.Due(ctx, access.Everything("the pass"), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 0 {
			t.Fatalf("a withdrawn supplier is still due a read: %+v", due)
		}
	})
}

func TestAWithdrawnSupplierTakenUpAgainResumesWhereItStopped(t *testing.T) {
	// It takes what was issued while it was away and nothing it already read,
	// and never further back than a new supplier would read.
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)

		row, err := store.Add(ctx, f.admin, f.product, "SUSE", described)
		if err != nil {
			t.Fatal(err)
		}
		lastMonth := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Microsecond)
		if err := store.Reached(ctx, row.ID, lastMonth, supplier.Mark("a"), nil); err != nil {
			t.Fatal(err)
		}
		if err := store.Retire(ctx, f.admin, f.product, "SUSE"); err != nil {
			t.Fatal(err)
		}

		again, err := store.Add(ctx, f.admin, f.product, "SUSE",
			"https://supplier.example/.well-known/csaf/provider-metadata.json")
		if err != nil {
			t.Fatal(err)
		}
		if again.ID != row.ID {
			t.Errorf("a second row was made rather than the first taken up again")
		}
		if again.FetchedAt != nil {
			t.Errorf("it reads as already read: %v", again.FetchedAt)
		}
		year := 365 * 24 * time.Hour
		if from, mark := again.From(year); !from.Equal(lastMonth) || mark != supplier.Mark("a") {
			t.Errorf("inside the window it starts at %v %q, want where it stopped", from, mark)
		}
		week := 7 * 24 * time.Hour
		if from, _ := again.From(week); from.Before(again.CreatedAt.Add(-week)) {
			t.Errorf("it starts at %v, further back than the window", from)
		}
	})
}

func TestASupplierTakenUpAgainAtAnotherAddressStartsAfresh(t *testing.T) {
	// Nothing at the new address has been read, so the mark from the old one
	// would skip what is there without saying so.
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)

		row, err := store.Add(ctx, f.admin, f.product, "SUSE", described)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Reached(ctx, row.ID, time.Now().UTC(), supplier.Mark("a"), nil); err != nil {
			t.Fatal(err)
		}
		if err := store.Retire(ctx, f.admin, f.product, "SUSE"); err != nil {
			t.Fatal(err)
		}
		again, err := store.Add(ctx, f.admin, f.product, "SUSE",
			"https://elsewhere.example/.well-known/csaf/provider-metadata.json")
		if err != nil {
			t.Fatal(err)
		}
		if again.CaughtUpTo != nil || again.CaughtUpMark != "" {
			t.Errorf("a new address carries the old mark: %v %q", again.CaughtUpTo, again.CaughtUpMark)
		}
	})
}

func TestOnlyAnAdministratorConfiguresASupplier(t *testing.T) {
	// Configuring one admits a third party's judgment into this deployment's
	// evidence and points it at an address of their choosing.
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)

		if _, err := store.Add(ctx, f.anybody, f.product, "SUSE", described); err == nil {
			t.Error("somebody who administers nothing configured a supplier")
		}
		if _, err := store.Add(ctx, f.admin, f.product, "SUSE", described); err != nil {
			t.Fatal(err)
		}
		if _, err := store.For(ctx, f.anybody, f.product); err == nil {
			t.Error("somebody who administers nothing read which suppliers are configured")
		}
		if err := store.Retire(ctx, f.anybody, f.product, "SUSE"); err == nil {
			t.Error("somebody who administers nothing withdrew a supplier")
		}
		// And a key, which holds no person at all.
		key := access.Subject{Kind: access.Pipeline, ID: 7, Identity: "a pipeline", Admin: true}
		if _, err := store.Add(ctx, key, f.product, "Red Hat", described); err == nil {
			t.Error("a pipeline's key configured a supplier")
		}
	})
}

func TestAnAddressThatIsNotAPublishersDirectoryIsRefused(t *testing.T) {
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)

		for _, address := range []string{
			"http://supplier.example/provider-metadata.json",
			"ftp://supplier.example/provider-metadata.json",
			"https://name:secret@supplier.example/provider-metadata.json",
			"/provider-metadata.json",
			"https:///provider-metadata.json",
		} {
			if _, err := store.Add(ctx, f.admin, f.product, "SUSE", address); err == nil {
				t.Errorf("%q was stored", address)
			}
		}
	})
}

func TestANameOrAddressPastWhatIsRecordedIsRefused(t *testing.T) {
	// Refused rather than shortened. Two names shortened to one length are one
	// supplier, and withdrawing either withdraws both — and on two of the four
	// engines an over-long value is truncated rather than refused outside
	// strict mode, so the refusal has to be here.
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)

		long := strings.Repeat("s", supplier.MostName+1)
		if _, err := store.Add(ctx, f.admin, f.product, long, described); err == nil {
			t.Error("a name past the width it is recorded in was stored")
		}
		far := "https://supplier.example/" + strings.Repeat("p", supplier.MostURL)
		if _, err := store.Add(ctx, f.admin, f.product, "SUSE", far); err == nil {
			t.Error("an address past the width it is recorded in was stored")
		}
		// And the widths themselves are accepted, so the refusal is a bound
		// rather than a rejection of anything long.
		fits := strings.Repeat("s", supplier.MostName)
		if _, err := store.Add(ctx, f.admin, f.product, fits, described); err != nil {
			t.Errorf("a name of exactly the width recorded was refused: %v", err)
		}
	})
}

func TestASupplierNeverReadIsDueAndOneJustReadIsNot(t *testing.T) {
	// A supplier named this morning is read this afternoon rather than
	// tomorrow, and one read an hour ago is not read again every cycle.
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)
		now := time.Now().UTC()

		row, err := store.Add(ctx, f.admin, f.product, "SUSE", described)
		if err != nil {
			t.Fatal(err)
		}
		due, err := store.Due(ctx, access.Everything("the pass"), now.Add(-24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 1 {
			t.Fatalf("a supplier never read is due %d times", len(due))
		}

		if err := store.Reached(ctx, row.ID, time.Time{}, supplier.Mark("a"), nil); err != nil {
			t.Fatal(err)
		}
		due, err = store.Due(ctx, access.Everything("the pass"), now.Add(-24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 0 {
			t.Fatalf("a supplier read a moment ago is due again: %+v", due)
		}
		// And is due once the interval has passed.
		due, err = store.Due(ctx, access.Everything("the pass"), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 1 {
			t.Fatalf("a supplier read a day ago is due %d times", len(due))
		}
	})
}

func TestTheMarkMovesForwardOnly(t *testing.T) {
	// A publisher that revises an old document stamps it with the moment of
	// the revision, so a feed entry older than the mark is one already taken.
	// A mark that could go backwards would make a publisher who re-stamped one
	// document replay their whole history.
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)

		row, err := store.Add(ctx, f.admin, f.product, "SUSE", described)
		if err != nil {
			t.Fatal(err)
		}
		ahead := time.Now().UTC().Truncate(time.Microsecond)
		behind := ahead.Add(-48 * time.Hour)
		if err := store.Reached(ctx, row.ID, ahead, supplier.Mark("a"), nil); err != nil {
			t.Fatal(err)
		}
		if err := store.Reached(ctx, row.ID, behind, supplier.Mark("a"), nil); err != nil {
			t.Fatal(err)
		}
		rows, err := store.For(ctx, f.admin, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].CaughtUpTo == nil {
			t.Fatalf("the supplier reads as %+v", rows)
		}
		if got := rows[0].CaughtUpTo.UTC(); !got.Equal(ahead) {
			t.Errorf("the mark moved back to %v from %v", got, ahead)
		}
	})
}

func TestWhyASupplierCouldNotBeReadIsRecorded(t *testing.T) {
	// "This publisher has been unreachable for a week" is only visible as a
	// moment that has stopped moving. Nothing else reports it.
	each(t, func(t *testing.T, f *configured) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)

		row, err := store.Add(ctx, f.admin, f.product, "SUSE", described)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Reached(ctx, row.ID, time.Time{}, "",
			errNothingAnswered); err != nil {
			t.Fatal(err)
		}
		rows, err := store.For(ctx, f.admin, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].FetchedAt == nil {
			t.Fatalf("the attempt was not recorded: %+v", rows)
		}
		if !strings.Contains(rows[0].Failed, "nothing answered") {
			t.Errorf("the reason reads as %q", rows[0].Failed)
		}
		// And it stays due, because nothing was read.
		if rows[0].CaughtUpTo != nil {
			t.Errorf("a failed attempt moved the mark to %v", rows[0].CaughtUpTo)
		}
	})
}

// errNothingAnswered stands for a publisher that could not be reached.
var errNothingAnswered = errNothing("nothing answered at that address")

type errNothing string

func (e errNothing) Error() string { return string(e) }
