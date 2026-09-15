package saved_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/saved"
)

// fixture is the seeded world with a place to keep filters against.
type fixture struct {
	*fixtures.World
	rights   *access.Store
	store    *saved.Store
	products map[string]int64
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		fn(t, &fixture{
			World:    w,
			rights:   w.Access,
			store:    saved.NewStore(w.DB.DB),
			products: map[string]int64{fixtures.ProductName: w.Product.ID},
		})
	})
}

// How long a prepared deferral defers for, at the store.
//
// A deferral is the one outcome that needs a date, and what is kept is the
// length rather than the date: the date is worked out from it whenever
// somebody submits the claim, so a rule saved in March means "put this off for
// a quarter" rather than "until 3 March".
func TestAPreparedDeferralHasToCarryHowLongItDefersFor(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		person, err := f.rights.Ensure(t.Context(), "someone@example.com", "Someone", nil)
		if err != nil {
			t.Fatal(err)
		}

		// Without a length, the form opens with the outcome chosen and no
		// date, which cannot be submitted — a prefill that half-fires.
		_, err = f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"], "someday",
			"component=linux", saved.Filter{Outcome: "deferred", Reasoning: "Not this quarter."})
		if err == nil {
			t.Fatal("a deferral with no length was kept")
		}
		if !strings.Contains(err.Error(), "defers for") {
			t.Errorf("refused with %q, which does not say what is missing", err)
		}

		// Beside any other outcome it is a value somebody set that nothing
		// reads, and it is refused rather than dropped — which is the answer a
		// decision itself gives to a date beside an outcome that is not a
		// deferral.
		_, err = f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"],
			"gone", "component=linux", saved.Filter{Outcome: "wont-fix",
				Reasoning: "Not built into this image.", DeferDays: 90})
		if err == nil {
			t.Fatal("a length was kept beside an outcome that is not a deferral")
		}
		if !strings.Contains(err.Error(), "only means something") {
			t.Errorf("refused with %q, which does not say why", err)
		}

		// With both, it is kept and read back.
		kept, err := f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"],
			"quarter", "component=linux", saved.Filter{Outcome: "deferred",
				Reasoning: "Waiting on the next kernel bump.", DeferDays: 90})
		if err != nil {
			t.Fatal(err)
		}
		if !kept.Prepares() || kept.DeferDays != 90 {
			t.Fatalf("it was kept as %+v", kept)
		}
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
		person, err := f.rights.Ensure(t.Context(), "someone@example.com", "Someone", nil)
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
