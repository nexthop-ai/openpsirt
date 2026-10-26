// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/findingsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// flawLeadAs is the lead a flaw was recorded from, as one person reads it.
func flawLeadAs(t *testing.T, r *httpapitest.Reach, who, flaw string) findingsapi.FlawLeadBody {
	t.Helper()
	var body findingsapi.FlawLeadBody
	httpapitest.Read(t, r, who, "/v1/products/mine/issues/"+flaw+"/lead", &body)
	return body
}

// flawClosures is how the flaw's findings closed, open ones as the empty
// string.
func flawClosures(t *testing.T, r *httpapitest.Reach, flaw string) []string {
	t.Helper()
	var closed []string
	if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"`).
		ColumnExpr(`COALESCE("f"."closed_because", '')`).
		Where(`"vu"."identifier" = ?`, flaw).
		Where(`"f"."kind" = ?`, kind.Entered).
		Scan(t.Context(), &closed); err != nil {
		t.Fatal(err)
	}
	return closed
}

func TestAFlawRecordsTheLeadItWasRecordedFromWithItsOffer(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, false)
		got := flawLeadAs(t, r, "lead-handler", flaw)
		if got.Place != place || got.Rule == "" || got.Path != "src/a.c" || got.State != "handed-off" ||
			got.Stream != "master" || got.Variant != "broadcom" {
			t.Errorf("the flaw names its lead as %+v; want the handed-off lead at %s", got, place)
		}
		if got.Suggested.From == "" || got.HandedBy != "lead-handler" || got.HandedAt == "" || got.UndoneAt != "" {
			t.Errorf("the flaw records its offer as %+v; want the first suggestion and who handed it off", got)
		}
		if len(got.Proposed) != 1 || got.Proposed[0].Stream != "master" || !got.Proposed[0].Seen {
			t.Errorf("the flaw was proposed against %+v; want the one build the lead was seen in", got.Proposed)
		}
		if len(got.FixedIn) != 0 {
			t.Errorf("a lead still seen offers the flaw fixed in %+v; want nowhere", got.FixedIn)
		}
	})
}

func TestTheLeadOfAFlawIsReadOnlyByWhoeverReadsBoth(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		_, flaw := httpapitest.HandedOffLead(t, r, false)
		path := "/v1/products/mine/issues/" + flaw + "/lead"
		// Reads the flaw and not the internal lead it was kept as.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage", http.MethodGet, path, ""),
			http.StatusNotFound)
		// Reads the lead and not the undisclosed flaw.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet, path, ""),
			http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "lead-handler", http.MethodGet,
			"/v1/products/mine/issues/SONIC-2026-000000/lead", ""), http.StatusNotFound)
	})
}

func TestAFlawIsOfferedFixedWhereItsLeadIsNotReproduced(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, false)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.LeadRun(false))
		got := flawLeadAs(t, r, "lead-handler", flaw)
		evidence := evidenceAs(t, r, "lead-handler", place)
		if len(got.FixedIn) != 1 || got.FixedIn[0].Stream != "master" ||
			got.FixedIn[0].NotSeen.Run != evidence.NotSeenRun ||
			got.FixedIn[0].Fixed != nil {
			t.Fatalf("a flaw whose lead is not reproduced is offered fixed in %+v; want the build, at run %d",
				got.FixedIn, evidence.NotSeenRun)
		}
		// A person closes it, and the build is no longer offered.
		if w := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom/findings/"+flaw+"/resolve",
			`{"because":"not reproduced since the fix"}`); w.Code != http.StatusOK {
			t.Fatalf("closing the flaw answered %d: %s", w.Code, w.Body)
		}
		if got := flawLeadAs(t, r, "lead-handler", flaw); len(got.FixedIn) != 0 {
			t.Errorf("a flaw closed as fixed is offered fixed in %+v; want nowhere", got.FixedIn)
		}
	})
}

func TestAnUndoneHandOffConfirmsTheLeadAgainAndTakesTheFlawBack(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, true)
		undo := leadAt(place) + "/hand-off/withdrawal"
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPut,
			leadAt(place)+"/collaborators/outsider", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the lead answered %d: %s", got.Code, got.Body)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, undo,
			`{"because":"handed off by mistake"}`), http.StatusForbidden)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, undo,
			`{"because":"   "}`), http.StatusUnprocessableEntity)
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, undo,
			`{"because":"handed off against the wrong component"}`); got.Code != http.StatusNoContent {
			t.Fatalf("undoing the hand-off answered %d: %s", got.Code, got.Body)
		}

		if got := evidenceAs(t, r, "internal-reader", place); got.State != "confirmed" ||
			got.Handoff != nil || got.At.Message != "p is leaked" {
			t.Errorf("an internal reader reads the lead as %s %+v; want the whole lead, confirmed", got.State, got)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "outsider", http.MethodGet, leadAt(place), ""),
			http.StatusNotFound)
		if closed := flawClosures(t, r, flaw); len(closed) == 0 {
			t.Error("the flaw has no findings")
		} else {
			for _, why := range closed {
				if why != "invalid" {
					t.Errorf("the flaw's findings closed as %v; want every one invalid", closed)
					break
				}
			}
		}
		origin := flawLeadAs(t, r, "lead-handler", flaw)
		if origin.Place != place || origin.UndoneAt == "" || origin.UndoneBy != "lead-handler" ||
			origin.Because != "handed off against the wrong component" {
			t.Errorf("the flaw records its lead as %+v; want it marked undone, with why", origin)
		}

		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, undo,
			`{"because":"again"}`), http.StatusConflict)
		again := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(place)+"/hand-off",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks on the early return"}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("handing the lead off again answered %d: %s", again.Code, again.Body)
		}
	})
}

func TestAHandOffIsNotUndoneOnceItsFlawIsDisclosed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, false)
		disclosed(t, r, flaw)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost,
			leadAt(place)+"/hand-off/withdrawal", `{"because":"handed off by mistake"}`), http.StatusConflict)
		if got := evidenceAs(t, r, "lead-handler", place); got.State != "handed-off" {
			t.Errorf("a lead whose flaw is disclosed reads %s after a refused undo; want handed off", got.State)
		}
	})
}
