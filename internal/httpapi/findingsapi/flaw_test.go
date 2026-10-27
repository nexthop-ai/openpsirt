// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/findingsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// codeFindingAt is the seeded code finding's address on the seeded build.
func codeFindingAt(occurrence string) string {
	return "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
}

// evidenceAs is the seeded code finding's evidence as one person reads it.
func evidenceAs(t *testing.T, r *httpapitest.Reach, who, occurrence string) findingsapi.CodeFindingEvidenceBody {
	t.Helper()
	var body findingsapi.CodeFindingEvidenceBody
	httpapitest.Read(t, r, who, codeFindingAt(occurrence), &body)
	return body
}

// disclosed discloses a flaw found here, which always takes a second person.
func disclosed(t *testing.T, r *httpapitest.Reach, flaw string) {
	t.Helper()
	if err := agreeToDisclose(t, r, askToDisclose(t, r, flaw)); err != nil {
		t.Fatal(err)
	}
}

// askToDisclose asks to disclose a flaw found here, and is the movement
// waiting for a second person.
func askToDisclose(t *testing.T, r *httpapitest.Reach, flaw string) int64 {
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
	return asked.ID
}

// agreeToDisclose is the second person agreeing to a disclosure asked for. It
// answers rather than failing the test, so a rival goroutine may call it.
func agreeToDisclose(t *testing.T, r *httpapitest.Reach, movement int64) error {
	got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
		fmt.Sprintf("/v1/disclosure-movements/%d/approval", movement), "")
	if got.Code != http.StatusNoContent {
		return fmt.Errorf("agreeing to the disclosure answered %d: %s", got.Code, got.Body)
	}
	return nil
}

func TestAConfirmedCodeFindingIsRecordedAsFlawAsAFlawOnce(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		got := evidenceAs(t, r, "code-finding-handler", occurrence)
		if got.State != "recorded-as-flaw" || got.RecordedAsFlaw == nil || got.RecordedAsFlaw.Flaw != flaw || got.RecordedAsFlaw.IncludedInDisclosure {
			t.Fatalf("the code finding reads %s with %+v; want recorded as a flaw, internal only, as %s", got.State, got.RecordedAsFlaw, flaw)
		}
		again := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrence)+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"again"}`)
		httpapitest.RefusedWith(t, again, http.StatusConflict)
		// The flaw is judged now, not the code finding.
		decided := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFindingAt(occurrence)+"/decision",
			`{"outcome":"confirmed","reasoning":"still real"}`)
		httpapitest.RefusedWith(t, decided, http.StatusConflict)
	})
}

func TestOnlyAConfirmedCodeFindingIsRecordedAsFlawBySomebodyWorkingBothHalves(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		body := `{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks"}`
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost,
			codeFindingAt(occurrence)+"/flaw", body), http.StatusConflict)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFindingAt(occurrence)+"/decision",
			`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
		}
		// Internal triage alone does not record a private flaw.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			codeFindingAt(occurrence)+"/flaw", body), http.StatusForbidden)
	})
}

// recordedAsFlawItems is the code findings recorded as a flaw one person lists, with what the
// analyzer said of each.
func recordedAsFlawItems(t *testing.T, r *httpapitest.Reach, who string) []string {
	t.Helper()
	var listed struct {
		Items []struct {
			Message string `json:"message"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, who, "/v1/products/mine/code-findings?state=recorded-as-flaw", &listed)
	said := make([]string, 0, len(listed.Items))
	for _, item := range listed.Items {
		said = append(said, item.Message)
	}
	return said
}

// decisionAt is the decision made at a code finding's occurrence.
func decisionAt(t *testing.T, r *httpapitest.Reach, occurrence string) string {
	t.Helper()
	var decision int64
	if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."decision_id"`).
		Where(`"de"."occurrence_identity" = ?`, occurrence).Limit(1).Scan(t.Context(), &decision); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("/v1/decisions/%d", decision)
}

func TestAnIncludedCodeFindingStaysWholeToEverybodyWhoReadIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, true)
		got := evidenceAs(t, r, "internal-reader", occurrence)
		if got.At.Message != "p is leaked" || got.At.Snippet == "" || got.DecisionOccurrence == nil || got.RecordedAsFlaw != nil {
			t.Errorf("an internal reader read %+v; want the whole code finding and its decision, and nothing of the flaw", got)
		}
		if said := recordedAsFlawItems(t, r, "internal-reader"); len(said) != 1 || said[0] != "p is leaked" {
			t.Errorf("an internal reader listed %q; want the included code finding, whole", said)
		}
		if decision := httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet, decisionAt(t, r, occurrence), ""); decision.Code != http.StatusOK {
			t.Errorf("an internal reader reading the decision at the included code finding answered %d: %s", decision.Code, decision.Body)
		}
	})
}

func TestTheFlawsReadersReadACodeFindingOnlyOnceItIsIncluded(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private", http.MethodGet, codeFindingAt(occurrence), ""),
			http.StatusNotFound)
		if said := recordedAsFlawItems(t, r, "private"); len(said) != 0 {
			t.Errorf("a reader of undisclosed work listed %q before the code finding was included; want nothing", said)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, codeFindingAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Fatalf("including the code finding answered %d: %s", got.Code, got.Body)
		}
		full := evidenceAs(t, r, "private", occurrence)
		if full.At.Message != "p is leaked" || full.RecordedAsFlaw == nil || !full.RecordedAsFlaw.IncludedInDisclosure || full.RecordedAsFlaw.Flaw != flaw {
			t.Errorf("a reader of undisclosed work read %+v; want the whole code finding and its flaw", full)
		}
		if said := recordedAsFlawItems(t, r, "private"); len(said) != 1 || said[0] != "p is leaked" {
			t.Errorf("a reader of undisclosed work listed %q; want the included code finding, whole", said)
		}
		// Reading undisclosed work is not reading internal work: the code finding
		// reaches them, and no other internal code finding does.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private", http.MethodGet, "/v1/products/mine/code-finding-series", ""),
			http.StatusForbidden)
	})
}

func TestAnInternalOnlyCodeFindingNamesItsFlawOnlyToThePeopleOnTheCase(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		internal := evidenceAs(t, r, "internal-reader", occurrence)
		if internal.At.Message != "p is leaked" || internal.RecordedAsFlaw != nil {
			t.Errorf("an internal reader read %+v; want the whole code finding and nothing of the case", internal)
		}
		// An internal-only code finding is internal, which reading undisclosed work does not
		// reach.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "embargo-reader", http.MethodGet, codeFindingAt(occurrence), ""),
			http.StatusNotFound)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut,
			codeFindingAt(occurrence)+"/collaborators/embargo-reader", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the code finding answered %d: %s", got.Code, got.Body)
		}
		granted := evidenceAs(t, r, "embargo-reader", occurrence)
		if granted.At.Message != "p is leaked" || granted.RecordedAsFlaw == nil || granted.RecordedAsFlaw.Flaw != flaw {
			t.Errorf("somebody granted the code finding read %+v; want the code finding and its flaw", granted)
		}
		// The grant is the code finding and nothing else of the internal work.
		var listed struct {
			Items []json.RawMessage `json:"items"`
		}
		httpapitest.Read(t, r, "embargo-reader", "/v1/products/mine/code-findings?state=recorded-as-flaw", &listed)
		if len(listed.Items) != 0 {
			t.Errorf("somebody granted one code finding listed %d; want none, as the grant is not a list", len(listed.Items))
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete,
			codeFindingAt(occurrence)+"/collaborators/embargo-reader", ""); got.Code != http.StatusNoContent {
			t.Fatalf("withdrawing the grant answered %d: %s", got.Code, got.Body)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "embargo-reader", http.MethodGet, codeFindingAt(occurrence), ""),
			http.StatusNotFound)
	})
}

func TestAnIncludedCodeFindingIsDisclosedWithItsFlawWithoutItsSnippets(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, true)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, codeFindingAt(occurrence), ""),
			http.StatusNotFound)
		disclosed(t, r, flaw)
		public := evidenceAs(t, r, "reader", occurrence)
		if public.At.Message != "p is leaked" || public.At.Snippet != "" {
			t.Errorf("a reader of disclosed work read %q with snippet %q; want the code finding without its source",
				public.At.Message, public.At.Snippet)
		}
		// Disclosure is one way.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete,
			codeFindingAt(occurrence)+"/flaw/disclosure", ""), http.StatusConflict)
	})
}

func TestASnippetIsDisclosedWhereItsPathSaysSo(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, true)
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
		if got := evidenceAs(t, r, "reader", occurrence); got.At.Snippet != "return;" {
			t.Errorf("a reader of disclosed work read snippet %q; want the source the path discloses", got.At.Snippet)
		}
	})
}

func TestTakingACodeFindingOutOfDisclosureTakesBackOnlyTheFlawsReaders(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, true)
		if got := evidenceAs(t, r, "embargo-reader", occurrence); got.At.Message != "p is leaked" {
			t.Fatalf("a reader of undisclosed work read %+v while the code finding was included; want the whole code finding", got)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete, codeFindingAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Fatalf("taking it out of disclosure answered %d: %s", got.Code, got.Body)
		}
		if got := evidenceAs(t, r, "internal-reader", occurrence); got.At.Message != "p is leaked" {
			t.Errorf("an internal reader read %+v; want the whole code finding still", got)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "embargo-reader", http.MethodGet, codeFindingAt(occurrence), ""),
			http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete,
			codeFindingAt(occurrence)+"/flaw/disclosure", ""), http.StatusConflict)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, codeFindingAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Fatalf("moving it again answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestALaterSightingOfAnIncludedCodeFindingOpensReadableByBothAudiences(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, true)
		now := time.Now().UTC()
		httpapitest.ApplyRun(t, r, now.Add(-time.Hour), httpapitest.CodeFindingRun(false))
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrence)+"/fixed",
			httpapitest.FixedBody(t, r, codeFindingAt(occurrence), "the early return frees p")); got.Code != http.StatusOK {
			t.Fatalf("closing the code finding answered %d: %s", got.Code, got.Body)
		}
		httpapitest.ApplyRun(t, r, now.Add(-30*time.Minute), httpapitest.CodeFindingRun(true))
		var held []string
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."visibility"`).
			Where(`"f"."kind" = ?`, kind.Analysis).Where(`"f"."occurrence_identity" = ?`, occurrence).
			Scan(t.Context(), &held); err != nil {
			t.Fatal(err)
		}
		if len(held) != 2 || held[0] != "internal" || held[1] != "internal" {
			t.Errorf("the code finding's findings are %v; want the reopened one internal beside the closed one", held)
		}
		for _, who := range []string{"internal-reader", "private"} {
			if got := evidenceAs(t, r, who, occurrence); !got.Open || got.At.Message != "p is leaked" {
				t.Errorf("%s read the reopened code finding as %+v; want it open and whole", who, got)
			}
		}
	})
}

func TestARecordAsFlawOffersTheComponentItsPrefixWasConfirmedAs(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFindingAt(occurrence)+"/decision",
			`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
		}
		var offer findingsapi.FlawOfferBody
		httpapitest.Read(t, r, "code-finding-handler", codeFindingAt(occurrence)+"/flaw", &offer)
		last := offer.Suggestions[len(offer.Suggestions)-1]
		if offer.Prefix != "src" || len(offer.Seen) != 1 || last.From != "build" || last.Component != "" {
			t.Fatalf("offered %+v; want the build last, for the prefix src", offer)
		}
		if d := offer.Discloses; len(d.Authors) != 1 || d.Authors[0].Identity != "internal-triager" ||
			len(d.Authors[0].Notes) != 1 || d.Authors[0].Notes[0].Body != "p leaks on the early return" ||
			d.Stripped != 1 || d.Snippets != 0 {
			t.Errorf("an inclusion discloses %+v; want the one author's reasoning and the stripped snippet", d)
		}
		if said := offer.Discloses.Said; !slices.Contains(said, findingsapi.AnalyzerSaidBody{Path: "src/a.c", Message: "p is leaked"}) {
			t.Errorf("an inclusion discloses the messages %+v; want the analyzer's message at src/a.c", said)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrence)+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"component":"zlib","summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the flaw record answered %d: %s", got.Code, got.Body)
		}

		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.OtherToolRun("cppcheck", "overflow", "120", "src/c.c", 4))
		var other string
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."occurrence_identity"`).
			Where(`"f"."kind" = ?`, kind.Analysis).Where(`"f"."occurrence_identity" <> ?`, occurrence).
			Scan(t.Context(), &other); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFindingAt(other)+"/decision",
			`{"outcome":"confirmed","reasoning":"n overflows"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming the second code finding answered %d: %s", got.Code, got.Body)
		}
		httpapitest.Read(t, r, "code-finding-handler", codeFindingAt(other)+"/flaw", &offer)
		if first := offer.Suggestions[0]; first.From != "confirmed" || first.Component != "zlib" || len(first.Lacking) != 0 {
			t.Errorf("the second code finding under src was offered %+v first; want zlib, as src was confirmed", first)
		}
		// The build itself replaces what src was confirmed as.
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(other)+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"n overflows"}`); got.Code != http.StatusCreated {
			t.Fatalf("the second flaw record answered %d: %s", got.Code, got.Body)
		}
		remembered, err := r.DB.DB.NewSelect().TableExpr(`"code_finding_component" AS "lco"`).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if remembered != 0 {
			t.Errorf("%d prefixes are remembered after the build itself was chosen; want src confirmed as nothing", remembered)
		}
	})
}

func TestADisclosedCodeFindingSeenAgainKeepsItsSourceStripped(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, true)
		disclosed(t, r, flaw)
		// The next run describes the code finding again, with its snippet.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRun(true))
		if got := evidenceAs(t, r, "reader", occurrence); got.At.Message != "p is leaked" || got.At.Snippet != "" {
			t.Errorf("a reader of disclosed work read %q with snippet %q after the next run; want the code finding without its source",
				got.At.Message, got.At.Snippet)
		}
	})
}

func TestSomebodyGrantedOnlyACodeFindingReadsItAndIsToldSo(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut,
			codeFindingAt(occurrence)+"/collaborators/outsider", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the code finding answered %d: %s", got.Code, got.Body)
		}
		// The outsider holds nothing on the product.
		got := evidenceAs(t, r, "outsider", occurrence)
		if got.At.Message != "p is leaked" || got.RecordedAsFlaw == nil || got.RecordedAsFlaw.Flaw != flaw {
			t.Errorf("somebody granted only the code finding read %+v; want the code finding and its flaw", got)
		}
		if told := r.Told(t, "outsider", "brought-in"); len(told) != 1 {
			t.Errorf("somebody granted only the code finding was told %q; want the one line granting it", told)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete,
			codeFindingAt(occurrence)+"/collaborators/outsider", ""); got.Code != http.StatusNoContent {
			t.Fatalf("withdrawing the grant answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestAnInternalOnlyCodeFindingStaysInternalOnceItsFlawIsDisclosed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut,
			codeFindingAt(occurrence)+"/collaborators/embargo-reader", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the code finding answered %d: %s", got.Code, got.Body)
		}
		disclosed(t, r, flaw)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut,
			codeFindingAt(occurrence)+"/flaw/disclosure", ""), http.StatusConflict)
		if got := evidenceAs(t, r, "internal-reader", occurrence); got.At.Message != "p is leaked" {
			t.Errorf("an internal reader read %+v; want the internal-only code finding, internal still", got)
		}
		if got := evidenceAs(t, r, "code-finding-handler", occurrence); got.RecordedAsFlaw == nil || !got.RecordedAsFlaw.Disclosed || got.RecordedAsFlaw.IncludedInDisclosure {
			t.Errorf("the flaw record reads %+v; want it internal only, and its flaw disclosed", got.RecordedAsFlaw)
		}
		// The grant ends with the disclosure.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "embargo-reader", http.MethodGet, codeFindingAt(occurrence), ""),
			http.StatusNotFound)
	})
}

func TestARecordedCodeFindingsDecisionIsNeitherRevisedNorWithdrawn(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, false)
		var decision int64
		if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."decision_id"`).
			Where(`"de"."occurrence_identity" = ?`, occurrence).Limit(1).Scan(t.Context(), &decision); err != nil {
			t.Fatal(err)
		}
		at := fmt.Sprintf("/v1/decisions/%d", decision)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at+"/reasoning",
			`{"reasoning":"p leaks, and more besides"}`), http.StatusConflict)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, at, ""),
			http.StatusConflict)
	})
}

func TestADisclosureLandingWhileARunAppliesStripsWhatTheRunWrote(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, true)
		movement := askToDisclose(t, r, flaw)
		// The disclosure is agreed to after the run has described the code finding
		// again and read its flaw record, and before the run commits.
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "code_finding_flaw", "sighting", 3*time.Second,
			func() error { return agreeToDisclose(t, r, movement) })
		watched := *r.DB
		watched.DB = hooked
		// The run keeps source at the code finding's step too, which it writes as a
		// row of its own.
		doc := strings.Replace(httpapitest.CodeFindingRun(true), `"region":{"startLine":3}`,
			`"region":{"startLine":3,"snippet":{"text":"p = malloc(1);"}}`, 1)
		httpapitest.ApplyRunOn(t, r, &watched, "clang-tidy/default", time.Now().UTC().Add(-time.Hour), doc)
		if err := rival(); err != nil {
			t.Fatal(err)
		}
		got := evidenceAs(t, r, "reader", occurrence)
		if got.At.Message != "p is leaked" || got.At.Snippet != "" || len(got.Steps) != 1 || got.Steps[0].Snippet != "" {
			t.Errorf("a reader of disclosed work read %q with snippet %q and steps %+v; want the code finding without the source the run wrote",
				got.At.Message, got.At.Snippet, got.Steps)
		}
	})
}

func TestAnUndoneBatchLeavesTheConfirmationARecordAsFlawRestsOn(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFindingAt(occurrence)+"/decision",
			`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
		}
		var decided struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{"batch":"tuesday"}`); got.Code != http.StatusOK {
			t.Fatalf("agreeing to the confirmation answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrence)+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the flaw record answered %d: %s", got.Code, got.Body)
		}
		got = httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodDelete, "/v1/approval-batches/tuesday", "")
		if got.Code != http.StatusOK {
			t.Fatalf("undoing the batch answered %d: %s", got.Code, got.Body)
		}
		var undone struct {
			Undone int64 `json:"undone"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &undone); err != nil {
			t.Fatal(err)
		}
		var state string
		if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."state"`).
			Where(`"de"."decision_id" = ?`, decided.DecisionID).Scan(t.Context(), &state); err != nil {
			t.Fatal(err)
		}
		if undone.Undone != 0 || state != "approved" {
			t.Errorf("undoing the batch undid %d and left the confirmation %s; want it approved still",
				undone.Undone, state)
		}
	})
}

func TestAnInclusionLandingWhileARunAppliesReachesTheSightingTheRunOpened(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, false)
		now := time.Now().UTC()
		httpapitest.ApplyRun(t, r, now.Add(-time.Hour), httpapitest.CodeFindingRun(false))
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrence)+"/fixed",
			httpapitest.FixedBody(t, r, codeFindingAt(occurrence), "the early return frees p")); got.Code != http.StatusOK {
			t.Fatalf("closing the code finding answered %d: %s", got.Code, got.Body)
		}
		// The code finding is included in disclosure after the run has read its flaw record, and before
		// the run opens the sighting at it.
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "code_finding_flaw", "finding", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, codeFindingAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
				return fmt.Errorf("the inclusion answered %d: %s", got.Code, got.Body)
			}
			return nil
		})
		watched := *r.DB
		watched.DB = hooked
		httpapitest.ApplyRunOn(t, r, &watched, "clang-tidy/default", now.Add(-30*time.Minute), httpapitest.CodeFindingRun(true))
		if err := rival(); err != nil {
			t.Fatal(err)
		}
		var held []string
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."visibility"`).
			Where(`"f"."kind" = ?`, kind.Analysis).Where(`"f"."occurrence_identity" = ?`, occurrence).
			Scan(t.Context(), &held); err != nil {
			t.Fatal(err)
		}
		if len(held) != 2 || held[0] != "internal" || held[1] != "internal" {
			t.Errorf("the code finding's findings are %v; want the one the run opened internal with the other", held)
		}
		if got := evidenceAs(t, r, "private", occurrence); !got.Open || got.RecordedAsFlaw == nil || !got.RecordedAsFlaw.IncludedInDisclosure {
			t.Errorf("a reader of undisclosed work read %+v; want the sighting the run opened, in its flaw's disclosure", got)
		}
	})
}

// toldOf is the bodies of one kind a person holds.
func toldOf(t *testing.T, r *httpapitest.Reach, who, kind string) []string {
	t.Helper()
	var theirs struct {
		Items []struct {
			Kind string `json:"kind"`
			Body string `json:"body"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, who, "/v1/notifications", &theirs)
	var out []string
	for _, item := range theirs.Items {
		if item.Kind == kind {
			out = append(out, item.Body)
		}
	}
	return out
}

func TestARecordAsFlawAndAnInclusionAreToldToTheProductsInternalTriagersWithoutTheFlawAndNotToTheirAuthor(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		if got := toldOf(t, r, "internal-triager", "code-finding-recorded-as-flaw"); len(got) != 1 ||
			!strings.Contains(got[0], "recorded as a flaw") || strings.Contains(got[0], flaw) {
			t.Errorf("the internal triager was told %q; want the flaw record without its flaw", got)
		}
		for _, who := range []string{"code-finding-handler", "internal-reader", "private-triage"} {
			if got := toldOf(t, r, who, "code-finding-recorded-as-flaw"); len(got) != 0 {
				t.Errorf("%s was told %q; want nothing", who, got)
			}
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, codeFindingAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Fatalf("the inclusion answered %d: %s", got.Code, got.Body)
		}
		if got := toldOf(t, r, "internal-triager", "code-finding-included-in-disclosure"); len(got) != 1 ||
			!strings.Contains(got[0], "included in its flaw's disclosure") || strings.Contains(got[0], flaw) {
			t.Errorf("the internal triager was told %q; want the inclusion without its flaw", got)
		}
	})
}

// decisionReads is what one person reads of the decision at a code finding's
// occurrence, by the status each read of it answers, and whether their list of
// decision occurrences holds it.
func decisionReads(t *testing.T, r *httpapitest.Reach, who, decision, occurrence string) (string, bool) {
	t.Helper()
	var codes []string
	for _, path := range []string{decision, decision + "/comments", decision + "/revisions", decision + "/approvals", occurrence} {
		codes = append(codes, fmt.Sprint(httpapitest.AsPerson(t, r, who, http.MethodGet, path, "").Code))
	}
	var listed struct {
		Items []struct {
			DecisionOccurrence struct {
				DecisionID int64 `json:"decision_id"`
			} `json:"decision_occurrence"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, who, "/v1/decision-occurrences?limit=200", &listed)
	listedIt := false
	for _, item := range listed.Items {
		if fmt.Sprintf("/v1/decisions/%d", item.DecisionOccurrence.DecisionID) == decision {
			listedIt = true
		}
	}
	exported := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/audit.csv", "")
	if exported.Code != http.StatusOK {
		t.Fatalf("%s exporting the audit answered %d: %s", who, exported.Code, exported.Body)
	}
	if strings.Contains(exported.Body.String(), "clang-tidy/leak") != listedIt {
		t.Errorf("%s exported %q, where their list held the decision: %v", who, exported.Body, listedIt)
	}
	return strings.Join(codes, " "), listedIt
}

func TestTheDecisionsAtACodeFindingAreReadByTheFlawsReadersOnlyWhileItIsIncluded(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPut,
			"/v1/products/mine/issues/"+flaw+"/collaborators/outsider", ""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing somebody onto the flaw's case answered %d: %s", got.Code, got.Body)
		}
		decision := decisionAt(t, r, occurrence)
		var row int64
		if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."id"`).
			Where(`"de"."occurrence_identity" = ?`, occurrence).Limit(1).Scan(t.Context(), &row); err != nil {
			t.Fatal(err)
		}
		occurrenceAt := fmt.Sprintf("/v1/decision-occurrences/%d", row)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, decision+"/comments",
			`{"body":"the early return is the only path"}`); got.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", got.Code, got.Body)
		}
		const whole, none = "200 200 200 200 200", "404 404 404 404 404"
		expect := func(when string, flawsReaders string) {
			t.Helper()
			for who, want := range map[string]string{
				"internal-reader": whole, "private": flawsReaders, "outsider": flawsReaders,
			} {
				got, listed := decisionReads(t, r, who, decision, occurrenceAt)
				if got != want || listed != (want == whole) {
					t.Errorf("%s %s read the decision as %s, listed %v; want %s", who, when, got, listed, want)
				}
			}
		}
		expect("while the code finding was internal only", none)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, codeFindingAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Fatalf("including the code finding answered %d: %s", got.Code, got.Body)
		}
		expect("while the code finding was included", whole)
		for _, who := range []string{"internal-reader", "private", "outsider"} {
			if got := evidenceAs(t, r, who, occurrence); got.DecisionOccurrence == nil {
				t.Errorf("%s read the included code finding without its decision", who)
			}
		}
		// Reading the decisions is not arguing them.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private", http.MethodPost, decision+"/comments",
			`{"body":"me too"}`), http.StatusNotFound)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete, codeFindingAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Fatalf("taking it out of disclosure answered %d: %s", got.Code, got.Body)
		}
		expect("once it was taken out of disclosure", none)
	})
}

// dismissedCodeFinding is the seeded code finding dismissed by one decision, and the decision.
func dismissedCodeFinding(t *testing.T, r *httpapitest.Reach) (string, string) {
	t.Helper()
	occurrence := httpapitest.SeededCodeFinding(t, r)
	if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFindingAt(occurrence)+"/decision",
		`{"outcome":"dismissed","reason":"false_positive","reasoning":"freed by the caller"}`); got.Code != http.StatusCreated {
		t.Fatalf("dismissing answered %d: %s", got.Code, got.Body)
	}
	return occurrence, decisionAt(t, r, occurrence)
}

func TestAWithdrawnDismissalOfACodeFindingIsToldToTheInternalTriagersAndAnApprovalIsNot(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		_, decision := dismissedCodeFinding(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost, decision+"/approval", `{}`); got.Code != http.StatusOK {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body)
		}
		if got := toldOf(t, r, "code-finding-handler", "code-finding-reopened"); len(got) != 0 {
			t.Errorf("an internal triager was told %q of an approval; want nothing", got)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, decision, ""); got.Code != http.StatusNoContent {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body)
		}
		if got := toldOf(t, r, "code-finding-handler", "code-finding-reopened"); len(got) != 1 || !strings.Contains(got[0], "back in the queue") {
			t.Errorf("an internal triager was told %q; want the code finding back in the queue", got)
		}
		if got := toldOf(t, r, "internal-triager", "code-finding-reopened"); len(got) != 0 {
			t.Errorf("whoever withdrew it was told %q; want nothing", got)
		}
		if got := toldOf(t, r, "private-triage", "code-finding-reopened"); len(got) != 0 {
			t.Errorf("a triager of undisclosed work was told %q; want nothing", got)
		}
	})
}

func TestAWithdrawnDismissalNobodyAgreedToTellsNobody(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		_, decision := dismissedCodeFinding(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, decision, ""); got.Code != http.StatusNoContent {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body)
		}
		if got := toldOf(t, r, "code-finding-handler", "code-finding-reopened"); len(got) != 0 {
			t.Errorf("an internal triager was told %q of a dismissal that never held the code finding out; want nothing", got)
		}
	})
}
