// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// Each administrative act that can take reading away hands back, in its own
// transaction, the work it leaves with a holder who no longer reads it. What
// each holder keeps is pinned on every engine in the finding package; these
// pin that each route asks.

// heldAt makes the scanned finding one of this visibility and puts it with a
// party, and returns how to ask whether that party still holds it.
func heldAt(t *testing.T, r *httpapitest.Reach, visibility access.Visibility,
	party int64) func() bool {

	t.Helper()
	ctx := t.Context()
	if _, err := r.DB.DB.NewUpdate().Table("finding").
		Set(`"visibility" = ?`, visibility).Set(`"assigned_to" = ?`, party).
		Where(`"closed_at" IS NULL`).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return func() bool {
		t.Helper()
		n, err := r.DB.DB.NewSelect().Table("finding").
			Where(`"assigned_to" = ?`, party).Where(`"closed_at" IS NULL`).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
}

func partyOf(t *testing.T, r *httpapitest.Reach, identity string) int64 {
	t.Helper()
	person, err := r.Rights.ByIdentity(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return person.PartyID
}

// teamOf declares a team of these people and returns its party.
func teamOf(t *testing.T, r *httpapitest.Reach, members string) int64 {
	t.Helper()
	if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
		`{"name":"platform","display_name":"Platform","members":`+members+`}`); made.Code >= 300 {
		t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
	}
	var party int64
	if err := r.DB.DB.NewSelect().Table("team").Column("party_id").
		Where(`"name" = ?`, "platform").Scan(t.Context(), &party); err != nil {
		t.Fatal(err)
	}
	return party
}

func TestWithdrawingTheUndisclosedRoleHandsBackUndisclosedWork(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		holds := heldAt(t, r, access.Private, partyOf(t, r, "private-triage"))
		got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/private-triage/roles/mine/private-triage", "")
		if got.Code != http.StatusOK {
			t.Fatalf("withdrawing a role answered %d: %s", got.Code, got.Body.String())
		}
		if holds() {
			t.Error("somebody who may no longer read undisclosed work here still holds it")
		}
	})
}

func TestWithdrawingAnEstateRoleHandsBackWhatItLetThemRead(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.Scanned(t)
		holder, err := r.Rights.ByIdentity(ctx, "triager")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Rights.GrantEstateRole(ctx, holder.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		holds := heldAt(t, r, access.Private, holder.PartyID)
		got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/triager/roles/private-triage", "")
		if got.Code != http.StatusOK {
			t.Fatalf("withdrawing a role answered %d: %s", got.Code, got.Body.String())
		}
		if holds() {
			t.Error("somebody who keeps a role here and lost undisclosed reading still holds undisclosed work")
		}
	})
}

func TestTakingTheLastReaderOffATeamHandsBackItsQueue(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		holds := heldAt(t, r, access.Private, teamOf(t, r, `["private-triage","triager"]`))
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete,
			"/v1/teams/platform/members/private-triage", ""); got.Code != http.StatusNoContent {
			t.Fatalf("taking somebody off a team answered %d: %s", got.Code, got.Body.String())
		}
		if holds() {
			t.Error("a team nobody on reads undisclosed work still holds undisclosed work")
		}
	})
}

func TestRetiringATeamHandsBackItsQueue(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		holds := heldAt(t, r, access.Public, teamOf(t, r, `["triager"]`))
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete,
			"/v1/teams/platform", ""); got.Code != http.StatusNoContent {
			t.Fatalf("retiring a team answered %d: %s", got.Code, got.Body.String())
		}
		if holds() {
			t.Error("a retired team still holds work")
		}
	})
}

func TestDeactivatingATeamsLastReaderHandsBackItsQueue(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		holds := heldAt(t, r, access.Private, teamOf(t, r, `["private-triage","triager"]`))
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut,
			"/v1/people/private-triage/deactivation", ""); got.Code != http.StatusOK {
			t.Fatalf("deactivating answered %d: %s", got.Code, got.Body.String())
		}
		if holds() {
			t.Error("a team whose one reader of undisclosed work left still holds undisclosed work")
		}
	})
}
