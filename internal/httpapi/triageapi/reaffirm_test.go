// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestOneRowEscalatingSendsTheWholeReAffirmationBack(t *testing.T) {
	// The agreement was that this did not matter much, and that is not an
	// agreement about what it has become. The single form already asks this
	// per row; asked per row here, an act covering forty-five places could
	// have written forty-four standing decisions and one waiting — an approver
	// agreeing to part of an argument they were shown whole.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		claimed := r.AgreedThenLapsed(t)

		// Agreed to as a medium, and the world re-rates it critical after the
		// agreement: a higher band, which a rescoring within one is not.
		if _, err := r.DB.DB.NewUpdate().Table("decision").
			Set("severity_centi = ?", 550).
			Where("claim_id = ?", claimed).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.DB.DB.NewUpdate().Table("vulnerability").
			Set("score_centi = ?", 980).Set("severity = ?", "critical").
			Where("identifier = ?", "CVE-2026-CURL1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		again := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("re-affirming answered %d: %s", again.Code, again.Body.String())
		}
		var restored struct {
			ClaimID   int64   `json:"claim_id"`
			Decisions []int64 `json:"decisions"`
			Waiting   bool    `json:"waiting"`
		}
		if err := json.Unmarshal(again.Body.Bytes(), &restored); err != nil {
			t.Fatal(err)
		}
		if !restored.Waiting {
			t.Error("a re-affirmation of something rated worse since stood on its own")
		}
		// And every row of it waits, rather than the one that escalated.
		waiting, err := r.DB.DB.NewSelect().Table("decision").
			Where("claim_id = ?", restored.ClaimID).Where("state = ?", "proposed").
			Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if waiting != len(restored.Decisions) {
			t.Errorf("%d of %d rows wait, want all of them",
				waiting, len(restored.Decisions))
		}
		// So it is in the review queue, which is where the second person is.
		var queue struct {
			Items []struct {
				Claim struct {
					ID int64 `json:"id"`
				} `json:"claim"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reviewer", "/v1/review-queue", &queue)
		found := false
		for _, item := range queue.Items {
			if item.Claim.ID == restored.ClaimID {
				found = true
			}
		}
		if !found {
			t.Error("a re-affirmation needing a second person is not in the review queue")
		}
	})
}

// Re-affirming a whole claim is its proposer's right. Anybody else holding
// triage is told so in the store's words, as a refusal they can act on by
// proposing afresh.
func TestReAffirmingAWholeClaimSomebodyElseMadeIsRefusedInWords(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		claimed := r.AgreedThenLapsed(t)

		refused := httpapitest.AsPerson(t, r, "wide-triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`)
		if refused.Code != http.StatusUnprocessableEntity {
			t.Fatalf("somebody else re-affirming the claim answered %d: %s",
				refused.Code, refused.Body.String())
		}
		if !strings.Contains(refused.Body.String(), "only the person who made a decision") {
			t.Errorf("the refusal does not say whose it is: %s", refused.Body.String())
		}
	})
}

func TestReAffirmingADismissalIsBoundedAndAPromiseIsNot(t *testing.T) {
	// The outcome comes from the claim being re-made, so a lapsed bulk
	// dismissal comes back through this path — and nothing re-checks a
	// dismissal, which is the reason the cap exists. Unbounded it would write
	// as many rows as it liked, and with the earlier agreement carried on,
	// nobody would stand between the request and the rows.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		claimed := r.AgreedThenLapsed(t)

		// One, so the two places of the fold are already past it.
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.write-ceiling",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}
		refused := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`)
		if refused.Code != http.StatusUnprocessableEntity {
			t.Fatalf("re-affirming a dismissal past the cap answered %d: %s",
				refused.Code, refused.Body.String())
		}
		if !strings.Contains(refused.Body.String(), "writes at most") {
			t.Errorf("the refusal does not name the bound: %s", refused.Body.String())
		}

		// And raising it deliberately is the way through, which is what the
		// refusal offers.
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.write-ceiling",
			`{"value":"50"}`); got.Code != http.StatusNoContent {
			t.Fatalf("raising the cap answered %d: %s", got.Code, got.Body.String())
		}
		if again := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`,
		); again.Code != http.StatusCreated {
			t.Fatalf("re-affirming inside the cap answered %d: %s",
				again.Code, again.Body.String())
		}
	})
}

func TestTwoLapsedRowsAtOnePlaceAreOneReAffirmation(t *testing.T) {
	// A place identity is names alone while a decision is keyed on the
	// versions too, so one component at two versions under one consumer is two
	// lapsed rows sharing a place. Walked twice, the act resolved the same
	// current place twice, wrote the same live key twice, and refused the
	// whole of itself with "a decision already stands here" — which is false
	// and leaves the caller nowhere to go.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.ScannedSiblings(t)
		claimed := r.AgreedThenLapsed(t)

		// A second lapsed row of the same claim at a place it already covers,
		// written directly: how one place comes to hold two versions is the
		// applying side's subject and has its own tests. What is pinned here
		// is that the act reads one place out of two rows.
		var rows []triage.Decision
		if err := r.DB.DB.NewSelect().Model(&rows).
			Where("de.claim_id = ?", claimed).Order("de.id ASC").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("the claim covers nothing, so this checks nothing")
		}
		twin := rows[0]
		twin.ID = 0
		twin.LiveKey = nil
		was := "0.0.1"
		twin.ComponentUpstreamVersion = &was
		if _, err := r.DB.DB.NewInsert().Model(&twin).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		again := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; still not reached."}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("re-affirming a claim with two rows at one place answered %d: %s",
				again.Code, again.Body.String())
		}
		var restored struct {
			Decisions []int64 `json:"decisions"`
			Places    int     `json:"places"`
		}
		if err := json.Unmarshal(again.Body.Bytes(), &restored); err != nil {
			t.Fatal(err)
		}
		// Two places, not three: the twin shares one of them.
		if restored.Places != 2 || len(restored.Decisions) != 2 {
			t.Errorf("re-affirming wrote %d decisions over %d places, want two of each",
				len(restored.Decisions), restored.Places)
		}
	})
}
