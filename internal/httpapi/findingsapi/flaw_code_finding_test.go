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

// flawCodeFindingAs is the code finding a flaw was recorded from, as one person reads it.
func flawCodeFindingAs(t *testing.T, r *httpapitest.Reach, who, flaw string) findingsapi.FlawCodeFindingBody {
	t.Helper()
	var body findingsapi.FlawCodeFindingBody
	httpapitest.Read(t, r, who, "/v1/products/mine/issues/"+flaw+"/code-finding", &body)
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

func TestAFlawRecordsTheCodeFindingItWasRecordedFromWithItsOffer(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		got := flawCodeFindingAs(t, r, "code-finding-handler", flaw)
		if got.Occurrence != occurrence || got.Rule == "" || got.Path != "src/a.c" || got.State != "recorded-as-flaw" ||
			got.BranchOrTag != "master" || got.Variant != "broadcom" {
			t.Errorf("the flaw names its code finding as %+v; want the code finding recorded as a flaw at %s", got, occurrence)
		}
		if got.Suggested.From == "" || got.RecordedBy != "code-finding-handler" || got.RecordedAt == "" || got.UndoneAt != "" {
			t.Errorf("the flaw records its offer as %+v; want the first suggestion and who recorded it", got)
		}
		if len(got.Proposed) != 1 || got.Proposed[0].BranchOrTag != "master" || !got.Proposed[0].Seen {
			t.Errorf("the flaw was proposed against %+v; want the one build the code finding was seen in", got.Proposed)
		}
		if len(got.FixedIn) != 0 {
			t.Errorf("a code finding still seen offers the flaw fixed in %+v; want nowhere", got.FixedIn)
		}
	})
}

func TestTheCodeFindingOfAFlawIsReadOnlyByWhoeverReadsBoth(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		_, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		path := "/v1/products/mine/issues/" + flaw + "/code-finding"
		// Reads the flaw and not the internal-only code finding it was recorded from.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage", http.MethodGet, path, ""),
			http.StatusNotFound)
		// Reads the code finding and not the undisclosed flaw.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet, path, ""),
			http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodGet,
			"/v1/products/mine/issues/SONIC-2026-000000/code-finding", ""), http.StatusNotFound)
	})
}

func TestAFlawIsOfferedFixedWhereItsCodeFindingIsNoLongerDetected(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRun(false))
		got := flawCodeFindingAs(t, r, "code-finding-handler", flaw)
		evidence := evidenceAs(t, r, "code-finding-handler", occurrence)
		if len(got.FixedIn) != 1 || got.FixedIn[0].BranchOrTag != "master" ||
			got.FixedIn[0].NotSeen.Run != evidence.NotSeenRun ||
			got.FixedIn[0].Fixed != nil {
			t.Fatalf("a flaw whose code finding is no longer detected is offered fixed in %+v; want the build, at run %d",
				got.FixedIn, evidence.NotSeenRun)
		}
		// A person closes it, and the build is no longer offered.
		if w := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/findings/"+flaw+"/resolve",
			`{"because":"no longer detected since the fix"}`); w.Code != http.StatusOK {
			t.Fatalf("closing the flaw answered %d: %s", w.Code, w.Body)
		}
		if got := flawCodeFindingAs(t, r, "code-finding-handler", flaw); len(got.FixedIn) != 0 {
			t.Errorf("a flaw closed as fixed is offered fixed in %+v; want nowhere", got.FixedIn)
		}
	})
}

func TestAnUndoneRecordAsFlawConfirmsTheCodeFindingAgainAndTakesTheFlawBack(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, true)
		undo := codeFindingAt(occurrence) + "/flaw/withdrawal"
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut,
			codeFindingAt(occurrence)+"/collaborators/outsider", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the code finding answered %d: %s", got.Code, got.Body)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, undo,
			`{"because":"recorded as a flaw by mistake"}`), http.StatusForbidden)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, undo,
			`{"because":"   "}`), http.StatusUnprocessableEntity)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, undo,
			`{"because":"recorded as a flaw against the wrong component"}`); got.Code != http.StatusNoContent {
			t.Fatalf("undoing the flaw record answered %d: %s", got.Code, got.Body)
		}

		if got := evidenceAs(t, r, "internal-reader", occurrence); got.State != "confirmed" ||
			got.RecordedAsFlaw != nil || got.At.Message != "p is leaked" {
			t.Errorf("an internal reader reads the code finding as %s %+v; want the whole code finding, confirmed", got.State, got)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "outsider", http.MethodGet, codeFindingAt(occurrence), ""),
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
		origin := flawCodeFindingAs(t, r, "code-finding-handler", flaw)
		if origin.Occurrence != occurrence || origin.UndoneAt == "" || origin.UndoneBy != "code-finding-handler" ||
			origin.Because != "recorded as a flaw against the wrong component" {
			t.Errorf("the flaw records its code finding as %+v; want it marked undone, with why", origin)
		}

		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, undo,
			`{"because":"again"}`), http.StatusConflict)
		again := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrence)+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks on the early return"}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("handing the code finding off again answered %d: %s", again.Code, again.Body)
		}
	})
}

func TestARecordAsFlawIsNotUndoneOnceItsFlawIsDisclosed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		disclosed(t, r, flaw)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost,
			codeFindingAt(occurrence)+"/flaw/withdrawal", `{"because":"recorded as a flaw by mistake"}`), http.StatusConflict)
		if got := evidenceAs(t, r, "code-finding-handler", occurrence); got.State != "recorded-as-flaw" {
			t.Errorf("a code finding whose flaw is disclosed reads %s after a refused undo; want recorded as a flaw", got.State)
		}
	})
}
