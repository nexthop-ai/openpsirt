// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// agreedThenLapsed claims one issue across the whole curl fold, has it agreed
// to, then moves the code under it — which is what makes a decision lapse. It
// answers with the claim whose rows are now lapsed.
func (r *reach) agreedThenLapsed(t *testing.T) int64 {
	t.Helper()
	ctx := t.Context()
	// One judgment over the fold: two packages, two places, one claim.
	decided := asPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libcurl4t64/decisions",
		`{"vulnerabilities":["CVE-2026-CURL1"],"outcome":"not-applicable",`+
			`"justification":"vulnerable_code_cannot_be_controlled_by_adversary",`+
			`"selected_by":"the transfer path",`+
			`"reasoning":"Nothing an attacker sends reaches the transfer path."}`)
	if decided.Code != http.StatusCreated {
		t.Fatalf("deciding together answered %d: %s", decided.Code, decided.Body.String())
	}
	var made struct {
		ClaimID int64   `json:"claim_id"`
		IDs     []int64 `json:"ids"`
	}
	if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	if len(made.IDs) != 2 {
		t.Fatalf("the claim covers %d places, want the two of the fold", len(made.IDs))
	}
	r.agreed(t, made.ClaimID)

	// The code moves under them, which is what a lapse is.
	if _, err := r.db.DB.NewUpdate().Table("component").
		Set("version = ?", "8.6.0-1").Set("upstream_version = ?", "8.6.0").
		Where("name LIKE ?", "%curl%").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var targets []int64
	if err := r.db.DB.NewSelect().TableExpr(`"target" AS "t"`).
		ColumnExpr("t.id").Scan(ctx, &targets); err != nil {
		t.Fatal(err)
	}
	store := triage.NewStore(r.db.DB)
	for _, target := range targets {
		if _, err := store.Lapse(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
	var lapsed int
	lapsed, err := r.db.DB.NewSelect().Table("decision").
		Where("claim_id = ?", made.ClaimID).Where("state = ?", "lapsed").Count(ctx)
	if err != nil || lapsed != 2 {
		t.Fatalf("%d rows of the claim lapsed (err %v), want both", lapsed, err)
	}

	return made.ClaimID
}

func TestOneRowEscalatingSendsTheWholeReAffirmationBack(t *testing.T) {
	// The agreement was that this did not matter much, and that is not an
	// agreement about what it has become. The single form already asks this
	// per row; asked per row here, an act covering forty-five places could
	// have written forty-four standing decisions and one waiting — an approver
	// agreeing to part of an argument they were shown whole.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		claimed := r.agreedThenLapsed(t)

		// Agreed to as a medium, and the world re-rates it critical after the
		// agreement: a higher band, which a rescoring within one is not.
		if _, err := r.db.DB.NewUpdate().Table("decision").
			Set("severity_centi = ?", 550).
			Where("claim_id = ?", claimed).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewUpdate().Table("vulnerability").
			Set("score_centi = ?", 980).Set("severity = ?", "critical").
			Where("identifier = ?", "CVE-2026-CURL1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		again := asPerson(t, r, "triager", http.MethodPost,
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
		waiting, err := r.db.DB.NewSelect().Table("decision").
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
		read(t, r, "reviewer", "/v1/review-queue", &queue)
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

func TestReAffirmingADismissalIsBoundedAndAPromiseIsNot(t *testing.T) {
	// The outcome comes from the claim being re-made, so a lapsed bulk
	// dismissal comes back through this path — and nothing re-checks a
	// dismissal, which is the reason the cap exists. Unbounded it would write
	// as many rows as it liked, and with the earlier agreement carried on,
	// nobody would stand between the request and the rows.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		claimed := r.agreedThenLapsed(t)

		// One, so the two places of the fold are already past it.
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.write-ceiling",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}
		refused := asPerson(t, r, "triager", http.MethodPost,
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
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.write-ceiling",
			`{"value":"50"}`); got.Code != http.StatusNoContent {
			t.Fatalf("raising the cap answered %d: %s", got.Code, got.Body.String())
		}
		if again := asPerson(t, r, "triager", http.MethodPost,
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
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scannedSiblings(t)
		claimed := r.agreedThenLapsed(t)

		// A second lapsed row of the same claim at a place it already covers,
		// written directly: how one place comes to hold two versions is the
		// applying side's subject and has its own tests. What is pinned here
		// is that the act reads one place out of two rows.
		var rows []triage.Decision
		if err := r.db.DB.NewSelect().Model(&rows).
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
		if _, err := r.db.DB.NewInsert().Model(&twin).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		again := asPerson(t, r, "triager", http.MethodPost,
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
