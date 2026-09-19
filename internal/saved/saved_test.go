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

// The length a prepared deferral defers for, at the store.
//
// A deferral is the one outcome that needs a date, and what is kept is the
// length rather than the date: the date is worked out from it whenever
// somebody submits the claim, so a rule saved in March means "put this off for
// a quarter" rather than "until 3 March".
func TestAPreparedDeferralHasToCarryHowLongItDefersFor(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		person, err := f.rights.Ensure(t.Context(), "someone@example.com", "Someone", nil, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Without a length, the form opens with the outcome chosen and no
		// date, which cannot be submitted — a prefill that half-fires.
		_, err = f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"], "someday",
			"component=linux", saved.Filter{Outcome: "deferred", Reasoning: "Not this quarter."}, 0)
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
				Reasoning: "Not built into this image.", DeferDays: 90}, 0)
		if err == nil {
			t.Fatal("a length was kept beside an outcome that is not a deferral")
		}
		if !strings.Contains(err.Error(), "only means something") {
			t.Errorf("refused with %q, which does not say why", err)
		}

		// With both, it is kept and read back.
		kept, err := f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"],
			"quarter", "component=linux", saved.Filter{Outcome: "deferred",
				Reasoning: "Waiting on the next kernel bump.", DeferDays: 90}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !kept.Prepares() || kept.DeferDays != 90 {
			t.Fatalf("it was kept as %+v", kept)
		}
	})
}

// The claim a saved filter prepares, at the store.
//
// The endpoint's own schema refuses a prefill with no reasoning before the
// store sees it, which is where a caller meets the rule. It is checked here as
// well because the store is what anything else in this process calls, and a
// rule that lives only in a request schema is one the next caller walks past.
func TestAPreparedClaimHasToCarryTheWordsSomebodyWillSign(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		person, err := f.rights.Ensure(t.Context(), "someone@example.com", "Someone", nil, nil)
		if err != nil {
			t.Fatal(err)
		}

		// An outcome with nothing to say is a button that proposes a
		// dismissal saying nothing, and the person who submits it is the one
		// putting their name to it.
		_, err = f.store.SaveFilterPreparing(t.Context(), person.ID, f.products["sonic"], "kernel", "component=linux",
			saved.Filter{Outcome: "not-applicable", Justification: "vulnerable_code_not_present"}, 0)
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
			}, 0)
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
				DeferDays: 30}, 0)
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
			f.products["sonic"], "kernel", "component=linux", saved.Filter{}, 0); err != nil {
			t.Fatal(err)
		}
		mine, err := f.store.SavedFilters(t.Context(), person.ID, f.products["sonic"], 0)
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

// The submission rules, asked where the claim is prepared.
//
// A saved filter prefills a decision, so a combination the decision store
// refuses is a refusal that lands when somebody presses the button rather than
// when they saved the thing that fills it in. The store is what anything else
// in this process calls, so the rule is asked here rather than in a schema.
func TestAFilterMayNotPrepareAClaimTheDecisionStoreWouldRefuse(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		person, err := f.rights.Ensure(t.Context(), "someone@example.com", "Someone", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		keeps := func(name string, prepares saved.Filter) error {
			_, err := f.store.SaveFilterPreparing(t.Context(), person.ID,
				f.products[fixtures.ProductName], name, "component=linux", prepares, 0)
			return err
		}

		for _, each := range []struct {
			name     string
			prepares saved.Filter
			says     string
		}{
			{"unknown", saved.Filter{Outcome: "not-a-thing", Reasoning: "Whatever."},
				"is not an outcome"},
			{"reasoned", saved.Filter{
				Outcome: "affected", Justification: "vulnerable_code_not_present",
				Reasoning: "It applies.",
			}, "does not claim"},
			{"unrecognized", saved.Filter{
				Outcome: "not-applicable", Justification: "because-i-said-so",
				Reasoning: "It does not apply.",
			}, "not a recognized reason"},
			{"mitigated", saved.Filter{
				Outcome: "not-applicable", Justification: "inline_mitigations_already_exist",
				Reasoning: "The setting is off.",
			}, "say what stops it"},
		} {
			t.Run(each.name, func(t *testing.T) {
				err := keeps(each.name, each.prepares)
				if err == nil {
					t.Fatalf("a filter preparing %+v was kept, and applying it is refused",
						each.prepares)
				}
				if !strings.Contains(err.Error(), each.says) {
					t.Errorf("refused with %q, which does not say why", err)
				}
			})
		}

		// And the markdown policy, which is what the decision store runs
		// before it stores any typed prose.
		if err := keeps("raw", saved.Filter{
			Outcome: "wont-fix", Reasoning: "Not worth it <script>alert(1)</script>",
		}); err == nil {
			t.Error("reasoning carrying raw markup was kept, and proposing it is refused")
		}
	})
}

func TestOnePersonMayNotKeepAnUnboundedNumberOfFilters(t *testing.T) {
	// Many actions writing one row each is the neighbouring case to one action
	// writing many, and it fills the same table — and the panel that lists
	// them read every row it found on every open.
	each(t, func(t *testing.T, f *fixture) {
		person, err := f.rights.Ensure(t.Context(), "someone@example.com", "Someone", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		product := f.products[fixtures.ProductName]
		for _, name := range []string{"first", "second"} {
			if _, err := f.store.SaveFilterPreparing(t.Context(), person.ID, product,
				name, "component=linux", saved.Filter{}, 2); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.store.SaveFilterPreparing(t.Context(), person.ID, product,
			"third", "component=linux", saved.Filter{}, 2); err == nil {
			t.Error("a filter past the limit was kept")
		}
		// Replacing one of their own is not how a table fills up.
		if _, err := f.store.SaveFilterPreparing(t.Context(), person.ID, product,
			"first", "component=busybox", saved.Filter{}, 2); err != nil {
			t.Errorf("replacing a filter they already keep was refused: %v", err)
		}

		// And the read is bounded by the same number.
		kept, err := f.store.SavedFilters(t.Context(), person.ID, product, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(kept) != 1 {
			t.Errorf("the list returned %d rows against a ceiling of one", len(kept))
		}
	})
}
