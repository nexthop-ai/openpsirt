package access_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

func TestATeamHoldsPeopleAndGrantsNothing(t *testing.T) {
	// Belonging to a team says nothing about what somebody may read or do,
	// which is what lets one carry mixed clearance — the ordinary
	// arrangement rather than a misconfiguration.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		admin, err := f.store.Ensure(ctx, "admin", "Admin", true)
		if err != nil {
			t.Fatal(err)
		}
		cleared, err := f.store.Ensure(ctx, "cleared", "Cleared", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, cleared.ID, f.products["sonic"],
			access.PrivateRead); err != nil {
			t.Fatal(err)
		}
		plain, err := f.store.Ensure(ctx, "plain", "Plain", false)
		if err != nil {
			t.Fatal(err)
		}

		team, err := f.store.DeclareTeam(ctx, "Kernel", "Kernel")
		if err != nil {
			t.Fatal(err)
		}
		// Matched without regard to capitals and stored normalized,
		// like every other name people type.
		if team.Name != "kernel" || team.Called() != "Kernel" {
			t.Errorf("a team named Kernel matches as %q and shows as %q",
				team.Name, team.Called())
		}
		if team.PartyID == 0 {
			t.Fatal("a team nothing can be routed to is not a team")
		}

		for _, who := range []int64{cleared.ID, plain.ID} {
			if err := f.store.AddToTeam(ctx, team.ID, who, admin.ID); err != nil {
				t.Fatal(err)
			}
		}
		// Saying it twice asserts the same thing.
		if err := f.store.AddToTeam(ctx, team.ID, plain.ID, admin.ID); err != nil {
			t.Errorf("adding somebody already on the team was refused: %v", err)
		}
		members, err := f.store.MembersOf(ctx, team.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(members) != 2 {
			t.Fatalf("the team holds %d people, want the two put on it", len(members))
		}

		// The point of a team that grants no roles: one team, two
		// clearances, and membership moved neither of them. Somebody
		// on the team who was granted nothing is still refused, which
		// is the whole of what a team grants.
		if _, err := f.store.Resolve(ctx, "plain"); !errors.Is(err, access.ErrDenied) {
			t.Errorf("joining a team let somebody in who holds nothing: %v", err)
		}
		// And somebody who does hold something counts their team as theirs.
		them, err := f.store.Resolve(ctx, "cleared")
		if err != nil {
			t.Fatal(err)
		}
		// Read through what the queries actually use, which is the list of
		// parties whose work counts as this subject's.
		mine := false
		for _, party := range them.Mine() {
			if party == team.PartyID {
				mine = true
			}
		}
		if !mine {
			t.Error("a member does not count their team's work as theirs")
		}
		if them.Sees(f.products["onie"]) {
			t.Error("joining a team granted reading on a product nobody granted")
		}

		// A person and a team never share an identifier, which is what
		// keeps "who holds this" one question.
		if team.PartyID == plain.PartyID || team.PartyID == cleared.PartyID {
			t.Error("a team and a person answer to the same name")
		}
	})
}

func TestARetiredTeamStopsTakingWorkAndKeepsItsName(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		admin, err := f.store.Ensure(ctx, "admin", "Admin", true)
		if err != nil {
			t.Fatal(err)
		}
		team, err := f.store.DeclareTeam(ctx, "kernel", "Kernel")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.AddToTeam(ctx, team.ID, admin.ID, admin.ID); err != nil {
			t.Fatal(err)
		}
		if err := f.store.RetireTeam(ctx, team.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.TeamByName(ctx, "kernel"); !errors.Is(err, access.ErrNoSuchTeam) {
			t.Errorf("a retired team still answers to its name: %v", err)
		}
		on, err := f.store.TeamsOf(ctx, admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(on) != 0 {
			t.Errorf("somebody is still on %d retired team(s)", len(on))
		}
		// Retiring twice says the same thing, and says it once.
		if err := f.store.RetireTeam(ctx, team.ID); !errors.Is(err, access.ErrNoSuchTeam) {
			t.Errorf("retiring a retired team answered %v", err)
		}
	})
}

func TestDeclaringATeamTwiceIsOneTeam(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first, err := f.store.DeclareTeam(t.Context(), "kernel", "Kernel")
		if err != nil {
			t.Fatal(err)
		}
		again, err := f.store.DeclareTeam(ctx, "KERNEL", "Kernel team")
		if err != nil {
			t.Fatal(err)
		}
		if again.ID != first.ID {
			t.Errorf("the same name declared twice made two teams, %d and %d",
				first.ID, again.ID)
		}
	})
}

func TestDeclaringARetiredTeamsNameBringsItBack(t *testing.T) {
	// The lookup said a retired team's name was free to be declared again and
	// it was not: the row stays, so that work already routed to it resolves to
	// something a screen can name, and the unique index refused a second team
	// under the same name — with a message about a team nobody could see.
	// Declaring is idempotent everywhere else here, and this is what somebody
	// typing a name they retired last week means.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()

		first, err := f.store.DeclareTeam(ctx, "platform", "Platform")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.RetireTeam(ctx, first.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.TeamByName(ctx, "platform"); err == nil {
			t.Fatal("a retired team is still found by name")
		}

		again, err := f.store.DeclareTeam(ctx, "platform", "Platform Team")
		if err != nil {
			t.Fatalf("declaring a retired team's name again: %v", err)
		}
		if again.ID != first.ID {
			t.Errorf("declaring it again made a second team: %d then %d", first.ID, again.ID)
		}
		if again.RetiredAt != nil {
			t.Error("the team came back still retired")
		}
		if again.DisplayName != "Platform Team" {
			t.Errorf("the spelling somebody typed was not taken: %q", again.DisplayName)
		}
		if found, err := f.store.TeamByName(ctx, "platform"); err != nil {
			t.Errorf("it is not found after being declared again: %v", err)
		} else if found.ID != first.ID {
			t.Error("a different team answers to the name now")
		}
	})
}
