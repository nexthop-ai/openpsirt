package access_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
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
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		person, err := rights.Ensure(ctx, "leaver@example.com", "Leaver", nil, nil)
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

// TestSomebodyWhoHasLeftIsClearedForNothing pins the rule the package comment
// states: every question of the form "may this person do this" excludes a
// deactivated account.
//
// Grant rows are left in place when somebody is deactivated, on purpose — it is
// the recorded act of leaving. So a query that reads only grants answers that
// they are still cleared, and three did. One of them gates handing an
// undisclosed finding to a person or a team, where the assignment itself is
// the disclosure.
func TestSomebodyWhoHasLeftIsClearedForNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		product := f.products["sonic"]

		person, err := f.store.Ensure(ctx, "ana", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, product, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		team, err := f.store.DeclareTeam(ctx, "kernel", "Kernel")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.AddToTeam(ctx, team.ID, person.ID, person.ID); err != nil {
			t.Fatal(err)
		}

		// While they are here, all three answer yes — otherwise the checks
		// below prove nothing.
		for _, c := range []struct {
			what string
			ask  func() (bool, error)
		}{
			{"they may read an embargoed finding", func() (bool, error) {
				return f.store.PersonReads(ctx, person.ID, product, access.Private)
			}},
			{"their team may", func() (bool, error) {
				return f.store.AnyMemberReads(ctx, team.ID, product, access.Private)
			}},
			{"they hold something here", func() (bool, error) {
				return f.store.HoldsAnythingIn(ctx, person.ID, product)
			}},
		} {
			held, err := c.ask()
			if err != nil {
				t.Fatal(err)
			}
			if !held {
				t.Fatalf("before anybody left, %s answered no", c.what)
			}
		}

		// They leave. The grants stay, deliberately.
		if left, err := f.store.Deactivate(ctx, person.ID); err != nil || !left {
			t.Fatalf("deactivating: left=%v %v", left, err)
		}
		held, err := f.store.Grants(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) == 0 {
			t.Fatal("deactivating removed the grants, so this tests something else")
		}

		for _, c := range []struct {
			what string
			ask  func() (bool, error)
		}{
			{"handing them an embargoed finding", func() (bool, error) {
				return f.store.PersonReads(ctx, person.ID, product, access.Private)
			}},
			{"handing their team one", func() (bool, error) {
				return f.store.AnyMemberReads(ctx, team.ID, product, access.Private)
			}},
			{"keeping their work with them", func() (bool, error) {
				return f.store.HoldsAnythingIn(ctx, person.ID, product)
			}},
		} {
			cleared, err := c.ask()
			if err != nil {
				t.Fatal(err)
			}
			if cleared {
				t.Errorf("somebody who has left still reads as cleared: %s", c.what)
			}
		}
	})
}

// TestADeploymentCannotBeAdministeredBySomebodyWhoHasLeft is the lockout.
//
// In group-bound mode a deactivated bootstrap administrator made the startup
// check pass on their strength alone — so the last admin group could be
// unbound and the deployment started cleanly with nobody able to administer
// it, and the documented way back in did not work either, because nothing
// cleared the date.
func TestADeploymentCannotBeAdministeredBySomebodyWhoHasLeft(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()

		if err := f.store.NameBootstrapAdmins(ctx, []string{"ana"}); err != nil {
			t.Fatal(err)
		}
		can, err := f.store.CanAdminister(ctx, access.GroupBound)
		if err != nil {
			t.Fatal(err)
		}
		if !can {
			t.Fatal("a named administrator does not satisfy the startup check")
		}

		person, err := f.store.ByIdentity(ctx, "ana")
		if err != nil {
			t.Fatal(err)
		}
		if left, err := f.store.Deactivate(ctx, person.ID); err != nil || !left {
			t.Fatalf("deactivating: left=%v %v", left, err)
		}
		can, err = f.store.CanAdminister(ctx, access.GroupBound)
		if err != nil {
			t.Fatal(err)
		}
		if can {
			t.Error("a deployment whose only administrator has left reports that it " +
				"can be administered")
		}

		// And the documented way back in works: naming them in configuration
		// is the deliberate act of letting them back, so it readmits them.
		if err := f.store.NameBootstrapAdmins(ctx, []string{"ana"}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Resolve(ctx, "ana"); err != nil {
			t.Errorf("naming a departed administrator in configuration did not let "+
				"them sign in: %v", err)
		}
		can, err = f.store.CanAdminister(ctx, access.GroupBound)
		if err != nil {
			t.Fatal(err)
		}
		if !can {
			t.Error("naming them again did not restore administration")
		}
	})
}
