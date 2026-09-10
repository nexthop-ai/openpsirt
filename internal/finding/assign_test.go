package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// assigned reads who holds each open finding of this target.
func (f *fixture) assigned(t *testing.T) map[int64]int64 {
	t.Helper()
	held := map[int64]int64{}
	for _, row := range f.open(t) {
		if row.AssignedTo != nil {
			held[row.ID] = *row.AssignedTo
		}
	}
	return held
}

func TestAssigningCoversEveryPlaceOfOneIssue(t *testing.T) {
	// A group is one issue in one component, seen from several parents.
	// Assigning one of its places and not another is not something anybody
	// means to do, so the whole group moves together.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("expected one issue at two places, got %d", len(open))
		}

		moved, _, err := f.store.Assign(t.Context(), f.holding(t, access.PublicTriage, access.Assigner),
			f.target, open[0].VulnerabilityID, open[0].ComponentID, ptr(int64(7)))
		if err != nil {
			t.Fatal(err)
		}
		if moved != 2 {
			t.Errorf("assigning covered %d places, want both", moved)
		}
		for id, who := range f.assigned(t) {
			if who != 7 {
				t.Errorf("finding %d went to %d", id, who)
			}
		}
	})
}

func TestHandingSomethingBackIsTheSameActionAsGivingItOut(t *testing.T) {
	// Taking work back is not a different kind of act, and making it one
	// produces two paths that drift apart.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		who := f.holding(t, access.PublicTriage, access.Assigner)

		if _, _, err := f.store.Assign(t.Context(), who, f.target,
			open[0].VulnerabilityID, open[0].ComponentID, ptr(int64(7))); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.Assign(t.Context(), who, f.target,
			open[0].VulnerabilityID, open[0].ComponentID, nil); err != nil {
			t.Fatal(err)
		}
		if held := f.assigned(t); len(held) != 0 {
			t.Errorf("%d findings are still assigned after being handed back", len(held))
		}
	})
}

func TestWhenSomebodyGoesTheirWorkComesBack(t *testing.T) {
	// The case this exists for. Work assigned to somebody who has gone is in
	// no view at all — not in the shared list because it is assigned, and not
	// in anybody's own list because they are not here.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl), found("CVE-2026-2", swss)}); err != nil {
			t.Fatal(err)
		}
		triager := f.holding(t, access.PublicTriage, access.Assigner)
		for _, row := range f.open(t) {
			if _, _, err := f.store.Assign(t.Context(), triager, f.target,
				row.VulnerabilityID, row.ComponentID, ptr(int64(7))); err != nil {
				t.Fatal(err)
			}
		}
		if len(f.assigned(t)) == 0 {
			t.Fatal("nothing was assigned to begin with")
		}

		// Only an administrator moves work somebody else was given.
		if _, err := f.store.Release(t.Context(), triager, 7); err == nil {
			t.Error("a triager released somebody else's work")
		}

		admin := access.NewPerson(99, "admin", true, nil, 199)
		released, err := f.store.Release(t.Context(), admin, 7)
		if err != nil {
			t.Fatal(err)
		}
		if released == 0 {
			t.Error("releasing an absent person's work moved nothing")
		}
		if held := f.assigned(t); len(held) != 0 {
			t.Errorf("%d findings are still held by somebody who has gone", len(held))
		}
	})
}

func TestWorkCanBeHandedToSomebodyElse(t *testing.T) {
	// The other answer, and a different question: handing over says who is
	// dealing with it now, where releasing says nobody is.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if _, _, err := f.store.Assign(t.Context(), f.holding(t, access.PublicTriage, access.Assigner), f.target,
			open[0].VulnerabilityID, open[0].ComponentID, ptr(int64(7))); err != nil {
			t.Fatal(err)
		}

		admin := access.NewPerson(99, "admin", true, nil, 199)
		if _, err := f.store.HandOver(t.Context(), admin, 7, 7); err == nil {
			t.Error("work was handed to the person who already had it")
		}
		if _, err := f.store.HandOver(t.Context(), admin, 7, 8); err != nil {
			t.Fatal(err)
		}
		for id, who := range f.assigned(t) {
			if who != 8 {
				t.Errorf("finding %d is held by %d after being handed on", id, who)
			}
		}
	})
}

func TestSomebodyWhoMayNotSeeAFindingCannotAssignIt(t *testing.T) {
	// Assignment is narrowed the way every other query is. A finding nobody
	// has disclosed is not one somebody may hand around.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)

		outsider := access.NewPerson(5, "outsider", false, nil, 105)
		if _, _, err := f.store.Assign(t.Context(), outsider, f.target,
			open[0].VulnerabilityID, open[0].ComponentID, ptr(int64(7))); err == nil {
			t.Error("somebody holding nothing assigned a finding")
		}
	})
}

func TestTheAssignerRightDoesNotStandOnItsOwn(t *testing.T) {
	// Assigning is triage *and* assigner. Somebody holding the capability
	// without the triage right it sits on can read the product and nothing
	// more, and handing work around a product you may not argue about is
	// not a narrower version of triaging — it is a different act on work
	// somebody else has to do.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)

		dispatcher := f.holding(t, access.PublicRead, access.Assigner)
		if _, _, err := f.store.Assign(t.Context(), dispatcher, f.target,
			open[0].VulnerabilityID, open[0].ComponentID, ptr(int64(7))); err == nil {
			t.Error("the assigner right alone gave work to somebody")
		}
		// Nor to themselves: taking unowned work is the triager's exception,
		// and this identity is not one.
		theirs := dispatcher.Party()
		if _, _, err := f.store.Assign(t.Context(), dispatcher, f.target,
			open[0].VulnerabilityID, open[0].ComponentID, &theirs); err == nil {
			t.Error("the assigner right alone took work")
		}
		if held := f.assigned(t); len(held) != 0 {
			t.Errorf("%d findings were handed out by somebody who may not triage", len(held))
		}
	})
}

func ptr[T any](v T) *T { return &v }

func TestWorkComesBackWhenTheirLastRoleOnAProductGoes(t *testing.T) {
	// the half that has a trigger today. Without it their work is in no
	// list at all — assigned, so not in the shared one, and assigned to
	// somebody who can no longer open it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		triager := f.holding(t, access.PublicTriage, access.Assigner)
		if _, _, err := f.store.Assign(t.Context(), triager, f.target,
			open[0].VulnerabilityID, open[0].ComponentID, ptr(int64(7))); err != nil {
			t.Fatal(err)
		}

		// Administrative, like every other move of somebody else's work.
		if _, err := f.store.ReleaseIn(t.Context(), triager, 7, f.productID); err == nil {
			t.Error("a triager handed back somebody else's work")
		}

		admin := access.NewPerson(99, "admin", true, nil, 199)
		// Another product's findings are not this product's business.
		released, err := f.store.ReleaseIn(t.Context(), admin, 7, f.productID+1000)
		if err != nil {
			t.Fatal(err)
		}
		if released != 0 {
			t.Errorf("handing back in one product moved %d findings in another", released)
		}
		if len(f.assigned(t)) == 0 {
			t.Fatal("the work was released by a product it does not belong to")
		}

		released, err = f.store.ReleaseIn(t.Context(), admin, 7, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if released == 0 {
			t.Error("handing back in this product moved nothing")
		}
		if held := f.assigned(t); len(held) != 0 {
			t.Errorf("%d findings are still held by somebody with no role here", len(held))
		}
	})
}

func TestTheCountsBesideTheseListsAreAskedForOnEveryEngine(t *testing.T) {
	// Both lists carry a total, and both totals come from a derived table
	// wrapped around the grouped query. That shape is the one that breaks
	// per-engine: the obvious alias for it, "groups", is a reserved word
	// in MySQL 8 — it names a window frame type — so the statement parses
	// on three engines and is a syntax error on the fourth.
	//
	// Nothing else reaches these two, so without this the first anybody
	// knew was a 500 from a handler that had swallowed the driver's
	// message.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl), found("CVE-2026-2", swss)}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage, access.Assigner)

		nobodys, total, err := f.store.Unassigned(t.Context(), who, finding.Scope{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		// Two issues, one of them at two places. The total counts issues at
		// components, not finding rows, which is what the list shows.
		if total != 2 || len(nobodys) != 2 {
			t.Errorf("%d rows and a total of %d, want 2 and 2", len(nobodys), total)
		}

		// Named, not whichever row came back first. Two components carry
		// findings here and they hold different numbers of places, so
		// indexing into an unordered read makes this assert a different
		// thing on different runs.
		library, err := graph.NewStore(f.db.DB).ComponentAt(t.Context(), f.target, libnl.Name)
		if err != nil {
			t.Fatal(err)
		}
		at, atTotal, err := f.store.AtComponent(t.Context(), who, f.target,
			library, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if atTotal != 1 {
			t.Errorf("the component holds a total of %d issues, want 1", atTotal)
		}
		// Every place of it, because that is what a claim is written against.
		if len(at) != 2 {
			t.Errorf("one issue at that component came back as %d places, want 2", len(at))
		}
	})
}

func TestTheSameWorkInTwoVariantsIsOneItemToDealWith(t *testing.T) {
	// Variants are mostly the same thing built twice, and a judgment
	// carries no variant — so answering this on one build answers it on
	// the other. Listed per build, importing a second variant doubled the
	// list of what nobody is dealing with while doubling none of the work,
	// which is how a queue stops being read.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage, access.Assigner)

		alone, one, err := f.store.Unassigned(ctx, who, finding.Scope{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if one != 1 || len(alone) != 1 {
			t.Fatalf("one build holds %d items: %+v", one, alone)
		}
		if alone[0].Builds != 1 {
			t.Errorf("one build reported as %d", alone[0].Builds)
		}
		places := alone[0].Places

		second := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, second, twoConsumers())
		if _, err := f.store.Apply(ctx, second, f.runOn(t, second),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		both, total, err := f.store.Unassigned(ctx, who, finding.Scope{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(both) != 1 {
			t.Fatalf("a second variant made %d items out of one piece of work: %+v", total, both)
		}
		if both[0].Builds != 2 {
			t.Errorf("the item covers %d builds, want 2", both[0].Builds)
		}
		// The places do double, and should: they are what a judgment here
		// would be written against, and there are now twice as many.
		if both[0].Places != places*2 {
			t.Errorf("it covers %d places, want %d — twice the one build's %d",
				both[0].Places, places*2, places)
		}
		// And it still names a build, because a screen has to link somewhere
		// and an action has to name a finding.
		if both[0].Stream == "" || both[0].Variant == "" {
			t.Errorf("the item names no build to act through: %+v", both[0])
		}
	})
}

func TestVariantsAtDifferentVersionsAreDifferentWork(t *testing.T) {
	// The other half of showing variants as one item: only genuine
	// differences are broken out. A component row is one name at one version, shared
	// by every build shipping it, so this falls out of the model rather
	// than being decided anywhere.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		second := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, second, movedTo(libnlNew))
		if _, err := f.store.Apply(ctx, second, f.runOn(t, second),
			[]finding.Reported{found("CVE-2026-1", libnlNew)}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage, access.Assigner)
		rows, total, err := f.store.Unassigned(ctx, who, finding.Scope{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("two versions of the same component made %d items: %+v", total, rows)
		}
		versions := map[string]int{}
		for _, row := range rows {
			if row.Component != libnl.Name {
				t.Errorf("a row is about %q, want the one component under two versions", row.Component)
			}
			versions[row.Version] = row.Builds
		}
		for version, builds := range versions {
			if builds != 1 {
				t.Errorf("%s %s reads as %d builds, want 1 each", libnl.Name, version, builds)
			}
		}
		if len(versions) != 2 {
			t.Errorf("the two rows are not the two versions: %v", versions)
		}
	})
}

func TestTheSameComponentInTwoProductsIsTwoPiecesOfWork(t *testing.T) {
	// The limit of collapsing. A decision is a claim about one product's code,
	// so two products shipping the identical component at the identical
	// version are two judgments — answered separately, and usually by
	// different people.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		elsewhere := f.inAnotherProduct(t, "another-product")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		who := f.holdingIn(t, []int64{f.productID, f.productOf(t, elsewhere)},
			access.PrivateRead)
		rows, total, err := f.store.Unassigned(ctx, who, finding.Scope{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("two products holding the same component made %d items: %+v", total, rows)
		}
		products := map[string]bool{}
		for _, row := range rows {
			if row.Builds != 1 {
				t.Errorf("%s reads as %d builds, want 1 each", row.Product, row.Builds)
			}
			products[row.Product] = true
		}
		if len(products) != 2 {
			t.Errorf("the two rows are not two products: %v", products)
		}
	})
}

func TestAssigningCoversEveryBuildOfTheProductHoldingIt(t *testing.T) {
	// The other side of collapsing the list: an item covering two builds has
	// to be assignable as one, or it comes straight back. Assigning one build
	// leaves the identical work unassigned beside it, and the person holds
	// half of what they think they hold.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		second := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, second, twoConsumers())
		if _, err := f.store.Apply(ctx, second, f.runOn(t, second),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		f.recorded(t, 7, "somebody")
		who := f.holding(t, access.PublicTriage, access.Assigner)
		issue := f.issue(t, "CVE-2026-1")
		component := f.componentID(t, libnl.Name)
		person := int64(7)

		// Named by the build being looked at; what is assigned is the work it
		// belongs to.
		moved, _, err := f.store.Assign(ctx, who, f.target, issue, component, &person)
		if err != nil {
			t.Fatal(err)
		}
		if moved == 0 {
			t.Fatal("assigning moved nothing")
		}
		rows, total, err := f.store.Unassigned(ctx, who, finding.Scope{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("%d items are still unassigned after one assignment: %+v", total, rows)
		}
	})
}

func TestTakingUnownedWorkIsTriageAndGivingItAwayIsNot(t *testing.T) {
	// Deciding who deals with something is a different act from deciding
	// what it is, so it asks for a different right — with the exception
	// that keeps the common case unblocked: findings arriving under an
	// already-assigned component start unowned, so there is a constant
	// stream of work to pick up, and needing somebody's attention before
	// anybody can start would make the queue somebody's full-time job.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		issue, component := f.issue(t, "CVE-2026-1"), f.componentID(t, libnl.Name)
		f.recorded(t, 1, "someone")
		f.recorded(t, 2, "somebody-else")

		triager := f.holding(t, access.PublicTriage)
		mine, other := triager.Party(), int64(2)

		// Taking what nobody owns, for yourself: triage is enough.
		if _, _, err := f.store.Assign(ctx, triager, f.target, issue, component, &mine); err != nil {
			t.Fatalf("a triager could not pick up unowned work: %v", err)
		}
		// And handing their own back.
		if _, _, err := f.store.Assign(ctx, triager, f.target, issue, component, nil); err != nil {
			t.Fatalf("a triager could not hand back their own work: %v", err)
		}

		// Giving it to somebody else is the other right.
		_, _, err := f.store.Assign(ctx, triager, f.target, issue, component, &other)
		if !errors.Is(err, access.ErrDenied) {
			t.Errorf("a triager gave work to somebody else: %v", err)
		}

		// And so is taking what somebody else is holding, even for yourself:
		// taking work off a colleague is the act the right exists to name,
		// and doing it to yourself is still doing it.
		dispatcher := f.holding(t, access.PublicTriage, access.Assigner)
		if _, _, err := f.store.Assign(ctx, dispatcher, f.target, issue, component, &other); err != nil {
			t.Fatalf("an assigner could not give work away: %v", err)
		}
		if _, _, err := f.store.Assign(ctx, triager, f.target, issue, component, &mine); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a triager took work off somebody else: %v", err)
		}
		if _, _, err := f.store.Assign(ctx, dispatcher, f.target, issue, component, &mine); err != nil {
			t.Errorf("an assigner could not take work off somebody else: %v", err)
		}
	})
}
