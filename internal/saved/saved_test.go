package saved_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/saved"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// fixture is one migrated database with a product to keep filters against.
type fixture struct {
	rights   *access.Store
	store    *saved.Store
	products map[string]int64
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)
		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		fn(t, &fixture{
			rights:   access.NewStore(db.DB),
			store:    saved.NewStore(db.DB),
			products: map[string]int64{"sonic": product.ID},
		})
	})
}

// What a saved filter prepares, at the store.
//
// The endpoint's own schema refuses a prefill with no reasoning before the
// store sees it, which is where a caller meets the rule. It is checked here as
// well because the store is what anything else in this process calls, and a
// rule that lives only in a request schema is one the next caller walks past.
func TestAPreparedClaimHasToCarryTheWordsSomebodyWillSign(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		person, err := f.rights.Ensure(t.Context(), "someone@example.com", "Someone", false)
		if err != nil {
			t.Fatal(err)
		}

		// An outcome with nothing to say is a button that proposes a
		// dismissal saying nothing, and the person who submits it is the one
		// putting their name to it.
		_, err = f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"], "kernel", "component=linux",
			saved.Filter{Outcome: "not-applicable", Justification: "vulnerable_code_not_present"})
		if err == nil {
			t.Fatal("a prefill with no reasoning was kept")
		}
		if !strings.Contains(err.Error(), "reasoning") {
			t.Errorf("refused with %q, which does not say what is missing", err)
		}

		// With the words, it is kept and read back.
		kept, err := f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"], "kernel",
			"component=linux", saved.Filter{
				Outcome: "deferred", Reasoning: "Waiting on the next kernel bump.",
				DeferDays: 90,
			})
		if err != nil {
			t.Fatal(err)
		}
		if !kept.Prepares() || kept.DeferDays != 90 {
			t.Fatalf("it was kept as %+v", kept)
		}

		// A justification or a deferral beside no outcome is a prefill that
		// half-fires, so nothing prepared is nothing carried.
		half, err := f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"], "plain",
			"component=linux", saved.Filter{Justification: "vulnerable_code_not_present",
				DeferDays: 30})
		if err != nil {
			t.Fatal(err)
		}
		if half.Prepares() || half.Justification != "" || half.DeferDays != 0 {
			t.Errorf("a filter with no outcome carried %+v", half)
		}

		// Saving over a name is deciding what that name means now: the
		// prefill goes with it, or one fires on a filter somebody had made
		// ordinary.
		if _, err := f.store.SaveFilterPreparing(t.Context(), person.ID,
			f.products["sonic"], "kernel", "component=linux", saved.Filter{}); err != nil {
			t.Fatal(err)
		}
		mine, err := f.store.SavedFilters(t.Context(), person.ID, f.products["sonic"])
		if err != nil {
			t.Fatal(err)
		}
		for _, one := range mine {
			if one.Name == "kernel" && one.Prepares() {
				t.Errorf("the prefill survived being saved over: %+v", one)
			}
		}
	})
}
