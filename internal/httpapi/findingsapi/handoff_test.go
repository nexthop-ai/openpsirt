// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/findingsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// leadAt is the seeded lead's address on the seeded build.
func leadAt(place string) string {
	return "/v1/products/mine/streams/master/variants/broadcom/leads/" + place
}

// evidenceAs is the seeded lead's evidence as one person reads it.
func evidenceAs(t *testing.T, r *httpapitest.Reach, who, place string) findingsapi.LeadEvidenceBody {
	t.Helper()
	var body findingsapi.LeadEvidenceBody
	httpapitest.Read(t, r, who, leadAt(place), &body)
	return body
}

// disclosed discloses a flaw found here, which always takes a second person.
func disclosed(t *testing.T, r *httpapitest.Reach, flaw string) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
		"/v1/products/mine/issues/"+flaw+"/disclosure", `{"reason":"fixed in every release"}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("the disclosure answered %d: %s", got.Code, got.Body)
	}
	var asked struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &asked); err != nil {
		t.Fatal(err)
	}
	if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
		fmt.Sprintf("/v1/disclosure-movements/%d/approval", asked.ID), ""); got.Code != http.StatusNoContent {
		t.Fatalf("agreeing to the disclosure answered %d: %s", got.Code, got.Body)
	}
}

func TestAConfirmedLeadIsHandedOffAsAFlawOnce(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, false)
		got := evidenceAs(t, r, "lead-handler", place)
		if got.State != "handed-off" || got.Handoff == nil || got.Handoff.Flaw != flaw || got.Handoff.Moved {
			t.Fatalf("the lead reads %s with %+v; want handed off, kept, as %s", got.State, got.Handoff, flaw)
		}
		again := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(place)+"/hand-off",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"again"}`)
		httpapitest.RefusedWith(t, again, http.StatusConflict)
		// The flaw is judged now, not the lead.
		decided := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadAt(place)+"/decision",
			`{"outcome":"confirmed","reasoning":"still real"}`)
		httpapitest.RefusedWith(t, decided, http.StatusConflict)
	})
}

func TestOnlyAConfirmedLeadIsHandedOffBySomebodyWorkingBothHalves(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		body := `{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks"}`
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost,
			leadAt(place)+"/hand-off", body), http.StatusConflict)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadAt(place)+"/decision",
			`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
		}
		// Internal triage alone does not record a private flaw.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			leadAt(place)+"/hand-off", body), http.StatusForbidden)
	})
}

func TestAMovedLeadIsAStubToSomebodyNotOnItsCase(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, true)
		stub := evidenceAs(t, r, "internal-reader", place)
		if !stub.Withheld || stub.At.Message != "" || stub.At.Snippet != "" || len(stub.Steps) != 0 ||
			stub.Handoff != nil || stub.Decision != nil {
			t.Fatalf("an internal reader read %+v; want the state, rule, location and sightings alone", stub)
		}
		if stub.State != "handed-off" || stub.Rule != "clang-tidy/leak" || stub.At.Path != "src/a.c" || stub.At.StartLine != 12 {
			t.Errorf("an internal reader read %s %s at %s:%d; want the lead's state, rule and place",
				stub.State, stub.Rule, stub.At.Path, stub.At.StartLine)
		}
		var listed struct {
			Items []struct {
				Message  string `json:"message"`
				Withheld bool   `json:"withheld"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/leads?state=handed-off", &listed)
		if len(listed.Items) != 1 || !listed.Items[0].Withheld || listed.Items[0].Message != "" {
			t.Errorf("an internal reader listed %+v; want the moved lead, withheld", listed.Items)
		}
		full := evidenceAs(t, r, "private", place)
		if full.Withheld || full.At.Message != "p is leaked" || full.Handoff == nil || !full.Handoff.Moved ||
			full.Handoff.Flaw != flaw {
			t.Errorf("a reader of undisclosed work read %+v; want the whole lead and its flaw", full)
		}
	})
}

func TestAKeptLeadNamesItsFlawOnlyToThePeopleOnTheCase(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, false)
		internal := evidenceAs(t, r, "internal-reader", place)
		if internal.Withheld || internal.At.Message != "p is leaked" || internal.Handoff != nil {
			t.Errorf("an internal reader read %+v; want the whole lead and nothing of the case", internal)
		}
		// A kept lead is internal, which reading undisclosed work does not
		// reach.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "embargo-reader", http.MethodGet, leadAt(place), ""),
			http.StatusNotFound)
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPut,
			leadAt(place)+"/collaborators/embargo-reader", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the lead answered %d: %s", got.Code, got.Body)
		}
		granted := evidenceAs(t, r, "embargo-reader", place)
		if granted.At.Message != "p is leaked" || granted.Handoff == nil || granted.Handoff.Flaw != flaw {
			t.Errorf("somebody granted the lead read %+v; want the lead and its flaw", granted)
		}
		// The grant is the lead and nothing else of the internal work.
		var listed struct {
			Items []json.RawMessage `json:"items"`
		}
		httpapitest.Read(t, r, "embargo-reader", "/v1/products/mine/leads?state=handed-off", &listed)
		if len(listed.Items) != 0 {
			t.Errorf("somebody granted one lead listed %d; want none, as the grant is not a list", len(listed.Items))
		}
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodDelete,
			leadAt(place)+"/collaborators/embargo-reader", ""); got.Code != http.StatusNoContent {
			t.Fatalf("withdrawing the grant answered %d: %s", got.Code, got.Body)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "embargo-reader", http.MethodGet, leadAt(place), ""),
			http.StatusNotFound)
	})
}

func TestAMovedLeadIsDisclosedWithItsFlawWithoutItsSnippets(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, true)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, leadAt(place), ""),
			http.StatusNotFound)
		disclosed(t, r, flaw)
		public := evidenceAs(t, r, "reader", place)
		if public.At.Message != "p is leaked" || public.At.Snippet != "" {
			t.Errorf("a reader of disclosed work read %q with snippet %q; want the lead without its source",
				public.At.Message, public.At.Snippet)
		}
		// Disclosure is one way.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "lead-handler", http.MethodDelete,
			leadAt(place)+"/move", ""), http.StatusConflict)
	})
}

func TestASnippetIsDisclosedWhereItsPathSaysSo(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, flaw := httpapitest.HandedOffLead(t, r, true)
		located, err := catalog.NewStore(r.DB.DB).Locate(t.Context(), "mine", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		yes := true
		if err := sourcelink.NewStore(r.DB.DB).Replace(t.Context(), located.ProductID, sourcelink.Config{
			Hosts: []sourcelink.Host{{Remote: "github.com", Web: "https://github.com", Style: sourcelink.GitHub}},
			Paths: []sourcelink.Path{{Prefix: "", Snippets: &yes}, {Prefix: "src", DisclosedSnippets: &yes}},
		}); err != nil {
			t.Fatal(err)
		}
		disclosed(t, r, flaw)
		if got := evidenceAs(t, r, "reader", place); got.At.Snippet != "return;" {
			t.Errorf("a reader of disclosed work read snippet %q; want the source the path discloses", got.At.Snippet)
		}
	})
}

func TestAnUndoneMoveMakesTheLeadInternalAgain(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, _ := httpapitest.HandedOffLead(t, r, true)
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodDelete, leadAt(place)+"/move", ""); got.Code != http.StatusNoContent {
			t.Fatalf("undoing the move answered %d: %s", got.Code, got.Body)
		}
		if got := evidenceAs(t, r, "internal-reader", place); got.Withheld || got.At.Message != "p is leaked" {
			t.Errorf("an internal reader read %+v; want the whole lead again", got)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "embargo-reader", http.MethodGet, leadAt(place), ""),
			http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "lead-handler", http.MethodDelete,
			leadAt(place)+"/move", ""), http.StatusConflict)
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPut, leadAt(place)+"/move", ""); got.Code != http.StatusNoContent {
			t.Fatalf("moving it again answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestALaterSightingOfAMovedLeadOpensInItsCase(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, _ := httpapitest.HandedOffLead(t, r, true)
		now := time.Now().UTC()
		httpapitest.ApplyRun(t, r, now.Add(-time.Hour), httpapitest.LeadRun(false))
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(place)+"/fixed",
			`{"because":"the early return frees p"}`); got.Code != http.StatusOK {
			t.Fatalf("closing the lead answered %d: %s", got.Code, got.Body)
		}
		httpapitest.ApplyRun(t, r, now.Add(-30*time.Minute), httpapitest.LeadRun(true))
		var held []string
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."visibility"`).
			Where(`"f"."kind" = ?`, kind.Analysis).Where(`"f"."place_identity" = ?`, place).
			Scan(t.Context(), &held); err != nil {
			t.Fatal(err)
		}
		if len(held) != 2 || held[0] != "private" || held[1] != "private" {
			t.Errorf("the lead's findings are %v; want the reopened one in the case beside the closed one", held)
		}
	})
}

func TestAHandOffOffersTheComponentItsPrefixWasConfirmedAs(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadAt(place)+"/decision",
			`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
		}
		var offer findingsapi.HandoffOfferBody
		httpapitest.Read(t, r, "lead-handler", leadAt(place)+"/hand-off", &offer)
		last := offer.Suggestions[len(offer.Suggestions)-1]
		if offer.Prefix != "src" || len(offer.Seen) != 1 || last.From != "build" || last.Component != "" {
			t.Fatalf("offered %+v; want the build last, for the prefix src", offer)
		}
		if len(offer.Discloses.Authors) != 1 || offer.Discloses.Authors[0].Identity != "internal-triager" ||
			offer.Discloses.Messages == 0 || offer.Discloses.Stripped != 1 {
			t.Errorf("a move discloses %+v; want the one author, the messages and the stripped snippet", offer.Discloses)
		}
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(place)+"/hand-off",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"component":"zlib","summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the hand-off answered %d: %s", got.Code, got.Body)
		}

		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.OtherToolRun("cppcheck", "overflow", "120", "src/c.c", 4))
		var other string
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."place_identity"`).
			Where(`"f"."kind" = ?`, kind.Analysis).Where(`"f"."place_identity" <> ?`, place).
			Scan(t.Context(), &other); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadAt(other)+"/decision",
			`{"outcome":"confirmed","reasoning":"n overflows"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming the second lead answered %d: %s", got.Code, got.Body)
		}
		httpapitest.Read(t, r, "lead-handler", leadAt(other)+"/hand-off", &offer)
		if first := offer.Suggestions[0]; first.From != "confirmed" || first.Component != "zlib" || len(first.Lacking) != 0 {
			t.Errorf("the second lead under src was offered %+v first; want zlib, as src was confirmed", first)
		}
	})
}
