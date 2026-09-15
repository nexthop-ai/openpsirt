package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestATeamIsManagedAndGrantsNothing(t *testing.T) {
	// A team holds work. Belonging to one says nothing about what somebody
	// may read, which is what lets one carry mixed clearance.
	eachReach(t, func(t *testing.T, r *reach) {
		made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"Kernel","display_name":"Kernel","members":["reader","private"]}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording a team answered %d: %s", made.Code, made.Body.String())
		}

		var listed struct {
			Items []struct {
				Name    string   `json:"name"`
				Members []string `json:"members"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/teams", &listed)
		if len(listed.Items) != 1 {
			t.Fatalf("the deployment lists %d teams, want the one recorded", len(listed.Items))
		}
		// Matched without regard to capitals and stored normalized.
		if listed.Items[0].Name != "kernel" {
			t.Errorf("a team named Kernel is matched as %q", listed.Items[0].Name)
		}
		if len(listed.Items[0].Members) != 2 {
			t.Errorf("the team holds %v, want the two named", listed.Items[0].Members)
		}

		// The mixed-clearance case: one of those two may read undisclosed work
		// and the other may not, and joining moved neither.
		var mine struct {
			Holds []struct {
				Role string `json:"role"`
			} `json:"holds"`
		}
		read(t, r, "reader", "/v1/session/me", &mine)
		for _, held := range mine.Holds {
			if held.Role == "private-read" {
				t.Error("joining a team granted reading of undisclosed work")
			}
		}

		// Names to anybody who may hand work around, membership to an
		// administrator: routing means naming a team, and who is on one is
		// the same question as who is here.
		var seen struct {
			Items []struct {
				Name    string   `json:"name"`
				Members []string `json:"members"`
			} `json:"items"`
		}
		read(t, r, "assigner", "/v1/teams", &seen)
		if len(seen.Items) != 1 || seen.Items[0].Name != "kernel" {
			t.Fatalf("somebody who hands work around cannot see the teams: %+v", seen.Items)
		}
		if len(seen.Items[0].Members) != 0 {
			t.Errorf("a non-administrator was told who is on the team: %v",
				seen.Items[0].Members)
		}

		// Somebody who is not an administrator does not manage teams.
		refused := asPerson(t, r, "triager", http.MethodPost, "/v1/teams", `{"name":"other"}`)
		if refused.Code != http.StatusForbidden && refused.Code != http.StatusNotFound {
			t.Errorf("a triager recording a team answered %d: %s",
				refused.Code, refused.Body.String())
		}

		// A team cannot bring somebody into the deployment.
		unknown := asPerson(t, r, "admin", http.MethodPut,
			"/v1/teams/kernel/members/nobody-here", "")
		if unknown.Code != http.StatusNotFound {
			t.Errorf("putting an unrecorded person on a team answered %d: %s",
				unknown.Code, unknown.Body.String())
		}

		off := asPerson(t, r, "admin", http.MethodDelete, "/v1/teams/kernel/members/reader", "")
		if off.Code != http.StatusNoContent {
			t.Fatalf("taking somebody off a team answered %d: %s", off.Code, off.Body.String())
		}
		read(t, r, "admin", "/v1/teams", &listed)
		if len(listed.Items[0].Members) != 1 {
			t.Errorf("after a removal the team holds %v", listed.Items[0].Members)
		}

		gone := asPerson(t, r, "admin", http.MethodDelete, "/v1/teams/kernel", "")
		if gone.Code != http.StatusNoContent {
			t.Fatalf("retiring a team answered %d: %s", gone.Code, gone.Body.String())
		}
		read(t, r, "admin", "/v1/teams", &listed)
		if len(listed.Items) != 0 {
			t.Errorf("a retired team is still listed: %+v", listed.Items)
		}
		if again := asPerson(t, r, "admin", http.MethodDelete, "/v1/teams/kernel", ""); again.Code != http.StatusNotFound {
			t.Errorf("retiring a retired team answered %d", again.Code)
		}
	})
}

func TestDeclaringTheSameTeamTwiceSaysItMadeNothing(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		// Created the first time, and the second says so rather than refusing:
		// a script that sets a deployment up stays runnable.
		for i, want := range []bool{true, false} {
			code := http.StatusOK
			if want {
				code = http.StatusCreated
			}
			got := asPerson(t, r, "admin", http.MethodPost, "/v1/teams", `{"name":"kernel"}`)
			if got.Code != code {
				t.Fatalf("call %d answered %d, want %d: %s", i, got.Code, code, got.Body.String())
			}
			var out struct {
				Created bool `json:"created"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.Created != want {
				t.Errorf("call %d reports created=%v, want %v", i, out.Created, want)
			}
		}
	})
}

func TestAnAssignmentNamesAPartyRatherThanAPerson(t *testing.T) {
	// The column holds a party, and a person's is not their person
	// identifier. The two coincide in a database that has only ever made
	// people, so this makes a team first: from then on the numbers differ,
	// and anything still comparing the wrong one answers about somebody
	// else.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"kernel"}`); made.Code != http.StatusCreated {
			t.Fatalf("recording a team answered %d: %s", made.Code, made.Body.String())
		}
		// Somebody recorded after the team, so their party and their person
		// identifier have certainly diverged.
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"later",`+
				`"holds":[{"product":"mine","role":"public-triage"}]}`); made.Code != http.StatusCreated {
			t.Fatalf("recording a person answered %d: %s", made.Code, made.Body.String())
		}

		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"person":"later"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		// Their own list finds it, which it can only do if what was written
		// and what is read are the same name.
		var theirs struct {
			Total int `json:"total"`
		}
		read(t, r, "later", "/v1/people/later/assignments", &theirs)
		if theirs.Total != 1 {
			t.Errorf("the person it was assigned to holds %d, want the one", theirs.Total)
		}
		// And the finding names them.
		var detail struct {
			AssignedTo string `json:"assigned_to"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
		if detail.AssignedTo != "later" {
			t.Errorf("the finding says %q is dealing with it", detail.AssignedTo)
		}
	})
}

func TestATeamQueueIsTakenFromWithTriageAndFilledWithDispatch(t *testing.T) {
	// Work routed to a team is unheld until somebody takes it, so taking
	// it is picking up what nobody owns — triage alone. Putting it there
	// is dispatching, which is the act the assigner right names.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"kernel","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatalf("recording a team answered %d: %s", made.Code, made.Body.String())
		}

		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"

		// Filling the queue is dispatching. Refused as an act rather than as
		// a name that is not there: the finding is one they are already
		// looking at, and the same condition on the component path has always
		// been answered this way.
		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"team":"kernel"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a triager routed work to a team, answering %d: %s",
				got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"team":"kernel"}`); got.Code != http.StatusNoContent {
			t.Fatalf("an assigner could not route work to a team: %d %s",
				got.Code, got.Body.String())
		}

		// It is the team's, and it is a queue rather than a holding.
		var holding struct {
			Items []struct {
				Person string `json:"person"`
				Team   bool   `json:"team"`
			} `json:"items"`
		}
		read(t, r, "assigner", "/v1/assignments", &holding)
		if len(holding.Items) != 1 || !holding.Items[0].Team ||
			holding.Items[0].Person != "kernel" {
			t.Fatalf("who is holding what says %+v, want the team's queue", holding.Items)
		}

		// A member sees it as theirs, because "assigned to me" means
		// mine or my team's.
		var mine struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/people/me/assignments", &mine)
		if mine.Total != 1 {
			t.Errorf("a member's own list holds %d, want the team's one piece", mine.Total)
		}
		// Somebody not on it does not.
		var theirs struct {
			Total int `json:"total"`
		}
		read(t, r, "assigner", "/v1/people/me/assignments", &theirs)
		if theirs.Total != 0 {
			t.Errorf("somebody not on the team holds %d of its queue", theirs.Total)
		}

		// And taking it out is triage alone: no dispatch right needed.
		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("a member could not take work out of their team's queue: %d %s",
				got.Code, got.Body.String())
		}
		// Decoded fresh. Reusing the target above would leave the team flag
		// standing, because an absent field does not clear what was there.
		var after struct {
			Items []struct {
				Person string `json:"person"`
				Team   bool   `json:"team"`
			} `json:"items"`
		}
		read(t, r, "assigner", "/v1/assignments", &after)
		if len(after.Items) != 1 || after.Items[0].Team || after.Items[0].Person != "triager" {
			t.Errorf("after somebody took it, it reads as %+v, want their own holding",
				after.Items)
		}
	})
}

func TestWorkIsNotRoutedWhereNobodyOnTheTeamCanSeeIt(t *testing.T) {
	// At least one member, not every member: requiring all of them turns
	// routing pressure into access pressure. Requiring none is the failure
	// in the other direction — a queue nobody can see, which shows as held
	// in every administrative view and sits in nobody's list.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		// A team of one person who holds nothing on this product.
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"outsiders","members":["approver"]}`); made.Code != http.StatusCreated {
			t.Fatalf("recording a team answered %d: %s", made.Code, made.Body.String())
		}
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		refused := asPerson(t, r, "assigner", http.MethodPut, at, `{"team":"outsiders"}`)
		if refused.Code != http.StatusUnprocessableEntity {
			t.Fatalf("routing work to a team that cannot read it answered %d: %s",
				refused.Code, refused.Body.String())
		}

		// One member who can read it is enough, however many cannot.
		if on := asPerson(t, r, "admin", http.MethodPut,
			"/v1/teams/outsiders/members/reader", ""); on.Code != http.StatusNoContent {
			t.Fatalf("adding a member answered %d: %s", on.Code, on.Body.String())
		}
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"team":"outsiders"}`); got.Code != http.StatusNoContent {
			t.Errorf("one member who may read it was not enough: %d %s",
				got.Code, got.Body.String())
		}
	})
}

func TestWorkIsHeldByOnePartyAtATime(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"kernel","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		got := asPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200/assignment",
			`{"person":"triager","team":"kernel"}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("naming a person and a team answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestATeamQueueAndItsCountsAreNarrowedPerMember(t *testing.T) {
	// The queue is narrowed per viewer like every other list, and so are
	// its counts: a badge reading "Kernel · 2" shown to a member who may
	// not read undisclosed work announces that an embargoed item exists,
	// which is the thing an embargo prevents, arriving as a number.
	// Asserted rather than assumed from the row query being right, because
	// the count is the half that gets missed.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		// One of the two undisclosed, and a team holding a member of
		// each clearance — the mixed team a team that grants no roles
		// exists to allow.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"kernel","members":["triager","private-triage"]}`); made.Code != http.StatusCreated {
			t.Fatalf("recording a team answered %d: %s", made.Code, made.Body.String())
		}

		for _, issue := range []string{"CVE-2026-9999", "CVE-2026-1000"} {
			at := "/v1/products/mine/streams/master/variants/broadcom/findings/" +
				issue + "/components/linux-image/assignment"
			if got := asPerson(t, r, "private-dispatcher", http.MethodPut, at,
				`{"team":"kernel"}`); got.Code != http.StatusNoContent {
				t.Fatalf("routing %s answered %d: %s", issue, got.Code, got.Body.String())
			}
		}

		// The rows, and the count beside them, for each clearance.
		for _, who := range []struct {
			identity string
			wants    int
		}{{"triager", 1}, {"private-triage", 2}} {
			var queue struct {
				Items []struct{} `json:"items"`
				Total int        `json:"total"`
			}
			read(t, r, who.identity, "/v1/people/me/assignments", &queue)
			if queue.Total != who.wants || len(queue.Items) != who.wants {
				t.Errorf("%s sees %d rows of %d in the team's queue, want %d",
					who.identity, len(queue.Items), queue.Total, who.wants)
			}

			var holding struct {
				Items []struct {
					Person string `json:"person"`
					Open   int    `json:"open"`
				} `json:"items"`
			}
			read(t, r, who.identity, "/v1/assignments", &holding)
			if len(holding.Items) != 1 {
				t.Fatalf("%s sees %d parties holding work", who.identity, len(holding.Items))
			}
			if holding.Items[0].Open != who.wants {
				t.Errorf("%s is told the team holds %d, want %d — a count is as much a "+
					"disclosure as a row", who.identity, holding.Items[0].Open, who.wants)
			}
		}
	})
}

func TestTakingSomebodyOffATeamTheyAreNotOnRecordsNothing(t *testing.T) {
	// The fifth write that takes access away, and it read what it matched the
	// way the other four now do. Membership is what routes an undisclosed
	// finding to somebody, so a trail row saying a membership ended is a
	// record of who stopped being able to receive them — and answered as
	// success, one was written for a membership that never existed.
	eachReach(t, func(t *testing.T, r *reach) {
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"kernel","members":["reader"]}`); made.Code != http.StatusCreated {
			t.Fatalf("recording a team answered %d: %s", made.Code, made.Body.String())
		}

		// Somebody who is here and is not on that team.
		got := asPerson(t, r, "admin", http.MethodDelete, "/v1/teams/kernel/members/private", "")
		if got.Code != http.StatusNotFound {
			t.Errorf("taking off somebody who was never on answered %d: %s",
				got.Code, got.Body.String())
		}

		var trail changed
		read(t, r, "admin", "/v1/administration/changes?kind=team&limit=200", &trail)
		for _, row := range trail.Items {
			if strings.Contains(row.About, "private") {
				t.Errorf("a removal that removed nothing recorded %+v", row)
			}
		}
	})
}
