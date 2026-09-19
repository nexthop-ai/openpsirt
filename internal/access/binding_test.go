package access_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

func TestAGroupBringsTheRolesItIsBoundTo(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := f.store.Bind(ctx, "platform", f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Bind(ctx, "security", f.products["sonic"], access.PrivateTriage); err != nil {
			t.Fatal(err)
		}

		subject, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "someone"}, []string{"platform", "security"})
		if err != nil {
			t.Fatalf("somebody in two mapped groups was refused: %v", err)
		}
		if !subject.Reads(access.Public, f.products["sonic"]) ||
			!subject.Holds(access.PrivateTriage, f.products["sonic"]) {
			t.Errorf("reached %+v", subject)
		}
		if subject.Reads(access.Public, f.products["onie"]) {
			t.Error("a binding on one product reached another")
		}
	})
}

func TestLosingAGroupLosesWhatItGranted(t *testing.T) {
	// A bound role is a statement about current membership. Leaving the group
	// and keeping the access would make the binding decorative, and it is
	// exactly the case an access review is meant to catch.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := f.store.Bind(ctx, "platform", f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "someone"}, []string{"platform"}); err != nil {
			t.Fatal(err)
		}

		// Signing in again, no longer in the group.
		if _, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "someone"}, []string{"unrelated"}); err == nil {
			t.Error("somebody in no mapped group was still admitted")
		}
		if _, err := f.store.Resolve(ctx, "someone"); err == nil {
			t.Error("the role survived leaving the group that granted it")
		}
	})
}

func TestSomebodyInNoMappedGroupIsRefusedAndNotRecorded(t *testing.T) {
	// The mapping is the pre-authorization. Somebody it does not cover was
	// never authorized, and recording them would leave a person row behind for
	// everybody who ever tried to sign in.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := f.store.Bind(ctx, "platform", f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		for _, groups := range [][]string{nil, {}, {"unmapped"}, {""}} {
			if _, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "a-stranger"}, groups); err == nil {
				t.Errorf("%v admitted somebody", groups)
			}
		}
		if _, err := f.store.ByIdentity(ctx, "a-stranger"); err == nil {
			t.Error("somebody nobody authorized was recorded anyway")
		}
	})
}

func TestNoGroupsMeansNoRolesEvenForSomebodyAnAdministratorAssigned(t *testing.T) {
	// Two rules meeting. Membership that is missing or unreadable yields no
	// roles rather than unrestricted access, and per-person assignment grants
	// nothing while this mode is on — so an assignment made before the switch
	// cannot be a way in behind the groups' back.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "someone", "Someone", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Bind(ctx, "platform", f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		// The switch is what a deployment actually does before any of this
		// runs, and it is what sets the assignment aside.
		if err := f.store.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}

		for _, groups := range [][]string{nil, {}, {"unmapped"}} {
			if _, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "someone"}, groups); err == nil {
				t.Errorf("%v admitted somebody on an assignment that was set aside", groups)
			}
		}

		// And the group route still works, which is what makes the refusals
		// above mean something.
		if _, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "someone"}, []string{"platform"}); err != nil {
			t.Errorf("the mapped group did not admit them: %v", err)
		}
	})
}

func TestAGroupCanCarryAdministration(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := f.store.BindOver(ctx, "platform-leads", access.Administers); err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "a-lead"}, []string{"platform-leads"})
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Admin {
			t.Error("a group bound to administration granted none")
		}

		// And loses it on leaving.
		if _, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "a-lead"}, []string{"nothing-mapped"}); err == nil {
			t.Error("somebody who left the administrators' group was still admitted")
		}
		person, err := f.store.ByIdentity(ctx, "a-lead")
		if err != nil {
			t.Fatal(err)
		}
		if person.IsAdmin {
			t.Error("administration survived leaving the group that carried it")
		}
	})
}

func TestSomebodyNamedInConfigurationKeepsAdministrationWhateverTheGroupsSay(t *testing.T) {
	// The documented way back in when the mapping is wrong or the provider is
	// unreachable. A re-derivation that stripped it would take the recovery
	// path away at exactly the moment it is needed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := f.store.NameBootstrapAdmins(ctx, []string{"the-operator"}); err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "the-operator"}, []string{"nothing-mapped"})
		if err != nil {
			t.Fatalf("somebody named in configuration was refused: %v", err)
		}
		if !subject.Admin {
			t.Error("somebody named in configuration lost administration to a sign-in")
		}
	})
}

func TestNamingAdministratorsIsWhatConfigurationSaysAndNotMore(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := f.store.NameBootstrapAdmins(ctx, []string{"first", "second"}); err != nil {
			t.Fatal(err)
		}
		// Removed from configuration and restarted.
		if err := f.store.NameBootstrapAdmins(ctx, []string{"first"}); err != nil {
			t.Fatal(err)
		}

		second, err := f.store.ByIdentity(ctx, "second")
		if err != nil {
			t.Fatal(err)
		}
		if second.IsBootstrap {
			t.Error("somebody removed from configuration is still named by it")
		}
		first, err := f.store.ByIdentity(ctx, "first")
		if err != nil {
			t.Fatal(err)
		}
		if !first.IsBootstrap || !first.IsAdmin {
			t.Error("somebody still named lost it")
		}
	})
}

func TestSwitchingToGroupBoundSetsAssignmentsAsideRatherThanDeletingThem(t *testing.T) {
	// People switch back, usually on discovering their groups do not map to
	// how the team actually divides work.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "someone", "Someone", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}

		if err := f.store.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Resolve(ctx, "someone"); err == nil {
			t.Error("an assignment set aside still granted something")
		}

		if err := f.store.SwitchTo(ctx, access.Direct); err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.Resolve(ctx, "someone")
		if err != nil {
			t.Fatalf("switching back did not restore what was assigned: %v", err)
		}
		if !subject.Reads(access.Public, f.products["sonic"]) {
			t.Error("what was assigned did not come back")
		}
	})
}

func TestSwitchingBackToDirectClearsWhatGroupsDerived(t *testing.T) {
	// Derived grants are a cache of what a provider said at somebody's last
	// sign-in. Keeping them once nothing refreshes them would leave roles
	// nobody assigned and nothing will ever withdraw.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := f.store.Bind(ctx, "platform", f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		if err := f.store.BindOver(ctx, "leads", access.Administers); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: "someone"}, []string{"platform", "leads"}); err != nil {
			t.Fatal(err)
		}

		if err := f.store.SwitchTo(ctx, access.Direct); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Resolve(ctx, "someone"); err == nil {
			t.Error("a role derived from a group outlived the mode that derived it")
		}
		person, err := f.store.ByIdentity(ctx, "someone")
		if err != nil {
			t.Fatal(err)
		}
		if person.IsAdmin {
			t.Error("administration derived from a group outlived the mode that derived it")
		}
	})
}

// groupBound is the mode read, for a test that is about the counting rather
// than about where the mode comes from.
func groupBound(context.Context, bun.IDB) (access.Mode, error) { return access.GroupBound, nil }

func TestADeploymentIsNotAllowedToLockItselfOut(t *testing.T) {
	// The only route back is editing the database by hand, and nobody
	// discovers that at a good moment.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()

		can, err := f.store.CanAdminister(ctx, access.GroupBound)
		if err != nil {
			t.Fatal(err)
		}
		if can {
			t.Error("group-bound mode with no admin group and nobody named looked survivable")
		}

		if err := f.store.BindOver(ctx, "leads", access.Administers); err != nil {
			t.Fatal(err)
		}
		if can, err = f.store.CanAdminister(ctx, access.GroupBound); err != nil || !can {
			t.Errorf("a group bound to administration was not enough: %v %v", can, err)
		}

		// Unbinding it while it is the only thing granting administration is
		// refused, and the row is still there afterwards. Refused inside the
		// write rather than deleted and put back: a compensating re-insert
		// that failed left the binding gone and nobody able to administer.
		if err := f.store.UnbindAdminIfOthersRemain(ctx, "leads", groupBound); !errors.Is(
			err, access.ErrLastAdministrator) {
			t.Errorf("unbinding the last administrators' group answered %v, want a refusal", err)
		}
		groups, err := f.store.GroupsOver(ctx, access.Administers)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 || groups[0] != "leads" {
			t.Errorf("a refused unbind left %v, want the binding still there", groups)
		}

		// Naming somebody in configuration is enough in either mode, and with
		// that in place the group can be unbound.
		if err := f.store.NameBootstrapAdmins(ctx, []string{"the-operator"}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.UnbindAdminIfOthersRemain(ctx, "leads", groupBound); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []access.Mode{access.Direct, access.GroupBound} {
			if can, err = f.store.CanAdminister(ctx, mode); err != nil || !can {
				t.Errorf("somebody named in configuration was not enough in %s mode", mode)
			}
		}
	})
}

func TestAnUnreadableModeReadsAsTheOneThatDerivesNothing(t *testing.T) {
	// A value nobody can parse must not turn group membership into roles.
	for _, raw := range []string{"", "groupbound", "Group-Bound", "nonsense", "direct"} {
		if got := access.AsMode(raw); got != access.Direct {
			t.Errorf("%q read as %q, want direct", raw, got)
		}
	}
	if got := access.AsMode("group-bound"); got != access.GroupBound {
		t.Errorf("the group-bound mode read as %q", got)
	}
}

func TestAProxyCanReportMembershipToo(t *testing.T) {
	// This extends no trust that was not already extended: anybody able to
	// forge the group header could forge the username header and claim to be
	// an administrator outright. It is what lets a deployment run entirely
	// behind existing ingress authentication with no provider configured here.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := f.store.Bind(ctx, "platform", f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		sources, err := access.ParseSources("192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		resolver := access.NewResolver(f.store, access.Trust{
			Header: "X-Remote-User", From: sources,
			GroupsHeader: "X-Remote-Groups", GroupsDelimiter: ",",
		}).WithMode(func(context.Context) access.Mode { return access.GroupBound })

		ask := func(user, groups string) (access.Subject, error) {
			req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
			req.RemoteAddr = "192.0.2.1:5000"
			req.Header.Set("X-Remote-User", user)
			if groups != "" {
				req.Header.Set("X-Remote-Groups", groups)
			}
			subject, _, err := resolver.Resolve(ctx, req)
			return subject, err
		}

		subject, err := ask("someone", "platform, unrelated")
		if err != nil {
			t.Fatalf("somebody the proxy put in a mapped group was refused: %v", err)
		}
		if !subject.Reads(access.Public, f.products["sonic"]) {
			t.Error("the mapped group granted nothing")
		}

		// And membership that is absent or unmapped grants nothing rather than
		// everything, which is the failure that would otherwise be silent.
		for _, groups := range []string{"", "unmapped", "  ,  "} {
			if _, err := ask("nobody-here", groups); err == nil {
				t.Errorf("groups %q admitted somebody", groups)
			}
		}
	})
}

// Administration granted in the application survives a group that never gave
// it.
//
// The column recording where administration came from was rewritten on every
// sign-in as "whatever the groups say this time", which destroyed the input
// the rule above it depends on: somebody promoted here who also happened to
// be in an admin-bound group was recorded as derived, and being taken out of
// that group then removed administration the group never granted. A switch
// back to direct roles clears exactly the rows marked derived, so it was not
// recoverable that way either.
func TestPromotionInTheApplicationSurvivesAGroupThatNeverGaveIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Promoted here, not by a group.
		person, err := f.store.Ensure(ctx, "bob", "Bob", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		// The door they come through, recorded like anybody else's.
		if err := f.store.Claim(ctx, person.ID, "bob"); err != nil {
			t.Fatal(err)
		}
		if err := f.store.BindOver(ctx, "platform-admins", access.Administers); err != nil {
			t.Fatal(err)
		}

		arriving := access.Arrival{
			ViaProxy: true, Username: "bob", DisplayName: "Bob",
		}
		if _, err := f.store.AdmitByGroups(ctx, arriving,
			[]string{"platform-admins"}); err != nil {
			t.Fatal(err)
		}
		// Out of the group, and back.
		back, err := f.store.AdmitByGroups(ctx, arriving, nil)
		if err != nil {
			t.Fatalf("somebody promoted here was refused once a group dropped them: %v", err)
		}
		if !back.Admin {
			t.Error("a group that never granted administration took it away")
		}
		account, err := f.store.ByIdentity(ctx, "bob")
		if err != nil {
			t.Fatal(err)
		}
		if account.AdminDerived {
			t.Error("administration granted here reads as a group's")
		}
	})
}

// TestUnbindingAGroupTakesTheRoleAtTheNextSignIn pins what withdrawing a
// mapping does, which nothing demonstrated: Unbind was at 0.0%.
//
// Group membership is read at sign-in, so a mapping withdrawn takes effect at
// each member's next one — which is what the endpoint's own description says,
// and what "end their sessions" exists beside. The half worth pinning is that
// it takes effect at all: the binding row goes, and the derived grant goes
// with the next arrival rather than surviving it.
func TestUnbindingAGroupTakesTheRoleAtTheNextSignIn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		product := f.products["sonic"]

		if err := f.store.Bind(ctx, "security", product, access.PrivateRead); err != nil {
			t.Fatal(err)
		}
		// Binding what is already bound is not a failure — the branch
		// DESIGN-access.md states in prose and nothing executed.
		if err := f.store.Bind(ctx, "security", product, access.PrivateRead); err != nil {
			t.Errorf("binding twice: %v", err)
		}
		bindings, err := f.store.Bindings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(bindings) != 1 {
			t.Fatalf("binding twice left %d rows", len(bindings))
		}

		arrival := access.Arrival{ViaProxy: true, Username: "ana"}
		subject, err := f.store.AdmitByGroups(ctx, arrival, []string{"security"})
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Reads(access.Private, product) {
			t.Fatal("arriving in a bound group granted nothing, so this proves nothing")
		}

		// Withdrawn, and then they arrive again.
		if err := f.store.Unbind(ctx, "security", product, access.PrivateRead); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AdmitByGroups(ctx, arrival, []string{"security"}); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody whose only group was unbound was admitted: %v", err)
		}
		// And nothing of theirs stands: a derived grant is replaced at every
		// arrival, so the one the withdrawn binding made is gone.
		held, err := f.store.Grants(ctx, mustPerson(t, f, "ana").ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, grant := range held {
			if grant.Active {
				t.Errorf("a role from a withdrawn binding still stands: %+v", grant)
			}
		}
	})
}

// TestABindingIsMatchedWithItsCapitals pins the cost the Bind doc comment
// states: a group name is the provider's identity rather than a name typed
// here, so it is matched exactly.
func TestABindingIsMatchedWithItsCapitals(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		product := f.products["sonic"]

		if err := f.store.Bind(ctx, "security", product, access.PrivateRead); err != nil {
			t.Fatal(err)
		}
		// A different name as far as a provider is concerned, so it withdraws
		// nothing — and says so, rather than reporting a withdrawal that did
		// not happen and leaving the row.
		err := f.store.Unbind(ctx, "Security", product, access.PrivateRead)
		if !errors.Is(err, access.ErrNothingMatched) {
			t.Errorf("unbinding a differently spelled group answered %v, "+
				"want a refusal saying it matched nothing", err)
		}
		bindings, err := f.store.Bindings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(bindings) != 1 || bindings[0].GroupName != "security" {
			t.Errorf("unbinding a differently spelled group removed it: %+v", bindings)
		}
	})
}

// mustPerson reads somebody the fixture expects to exist.
func mustPerson(t *testing.T, f *fixture, identity string) *access.Account {
	t.Helper()
	person, err := f.store.ByIdentity(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return person
}
