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

// agreedAcrossTheFold claims one issue over the curl fold with the reason
// given, has it agreed to, and answers with the claim.
func (r *reach) agreedAcrossTheFold(t *testing.T, issue, justification string) int64 {
	t.Helper()
	decided := asPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/streams/master/variants/broadcom/components/libcurl4t64/decisions",
		fmt.Sprintf(`{"vulnerabilities":[%q],"outcome":"not-applicable",`+
			`"justification":%q,"selected_by":"the transfer path",`+
			`"reasoning":"Judged at 8.4.0."}`, issue, justification))
	if decided.Code != http.StatusCreated {
		t.Fatalf("deciding answered %d: %s", decided.Code, decided.Body.String())
	}
	var made struct {
		ClaimID int64 `json:"claim_id"`
	}
	if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	r.agreed(t, made.ClaimID)
	return made.ClaimID
}

// agreed has the reviewer agree to a claim.
func (r *reach) agreed(t *testing.T, claim int64) {
	t.Helper()
	if ok := asPerson(t, r, "reviewer", http.MethodPost,
		fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
		t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
	}
}

// curlMovedTo moves curl to a new upstream version and sweeps every build, which
// is what lapses the decisions made about the old one.
func (r *reach) curlMovedTo(t *testing.T, upstream string) {
	t.Helper()
	ctx := t.Context()
	if _, err := r.db.DB.NewUpdate().Table("component").
		Set("version = ?", upstream+"-1").Set("upstream_version = ?", upstream).
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
}

// reaffirmedMany is the answer to one act over many claims.
type reaffirmedMany struct {
	Claims []struct {
		PreviousClaimID int64   `json:"previous_claim_id"`
		ClaimID         int64   `json:"claim_id"`
		Decisions       []int64 `json:"decisions"`
		Waiting         bool    `json:"waiting"`
	} `json:"claims"`
}

// bothCurlRows is a selection of the two curl issues' rows on the findings list.
const bothCurlRows = `"findings":[` +
	`{"stream":"master","variant":"broadcom","vulnerability":"CVE-2026-CURL1","component":"libcurl4t64"},` +
	`{"stream":"master","variant":"broadcom","vulnerability":"CVE-2026-CURL2","component":"libcurl3t64"}]`

func reaffirmingMany(t *testing.T, r *reach, who string) (int, string, reaffirmedMany) {
	t.Helper()
	got := asPerson(t, r, who, http.MethodPost, "/v1/products/mine/reaffirmations",
		`{"reasoning":"Checked the changelog; none of these subsystems moved.",`+bothCurlRows+`}`)
	var out reaffirmedMany
	if got.Code == http.StatusCreated {
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return got.Code, got.Body.String(), out
}

func TestOneActReAffirmsEveryLapsedClaimInASelection(t *testing.T) {
	// A version bump on a large component lapses many claims at once, and each
	// is a separate claim with its own outcome and justification. One act
	// re-makes all of them under one reason, each keeping what it said.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		absent := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		unreachable := r.agreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		r.curlMovedTo(t, "8.6.0")

		code, body, out := reaffirmingMany(t, r, "triager")
		if code != http.StatusCreated {
			t.Fatalf("re-affirming the selection answered %d: %s", code, body)
		}
		if len(out.Claims) != 2 {
			t.Fatalf("the act re-made %d claims, want the two behind the selection: %s",
				len(out.Claims), body)
		}
		for _, one := range out.Claims {
			if one.PreviousClaimID != absent && one.PreviousClaimID != unreachable {
				t.Errorf("the act re-made claim %d, which nothing selected covers",
					one.PreviousClaimID)
			}
			if len(one.Decisions) != 2 {
				t.Errorf("claim %d was re-made at %d places, want both of the fold",
					one.PreviousClaimID, len(one.Decisions))
			}
			if one.Waiting {
				t.Errorf("claim %d waits for a second person with nothing changed",
					one.PreviousClaimID)
			}
			// Each keeps its own justification: the reason is shared and the
			// argument is not.
			var was, now string
			if err := r.db.DB.NewSelect().Table("claim").Column("justification").
				Where("id = ?", one.PreviousClaimID).Scan(t.Context(), &was); err != nil {
				t.Fatal(err)
			}
			if err := r.db.DB.NewSelect().Table("claim").Column("justification").
				Where("id = ?", one.ClaimID).Scan(t.Context(), &now); err != nil {
				t.Fatal(err)
			}
			if now != was {
				t.Errorf("claim %d was re-made as %q, want its own %q",
					one.PreviousClaimID, now, was)
			}
		}
	})
}

func TestASeverityRiseSendsBackOnlyTheClaimItBearsOn(t *testing.T) {
	// Each claim carries its own earlier agreement, so one that needs a second
	// look says nothing about the others. A rise bears on a claim that nothing
	// an attacker controls reaches the code, and not on one that the code is
	// absent.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		absent := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		unreachable := r.agreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		for _, issue := range []string{"CVE-2026-CURL1", "CVE-2026-CURL2"} {
			if _, err := r.db.DB.NewUpdate().Table("vulnerability").
				Set("score_centi = ?", 990).Set("severity = ?", "critical").
				Where("identifier = ?", issue).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		r.curlMovedTo(t, "8.6.0")

		code, body, out := reaffirmingMany(t, r, "triager")
		if code != http.StatusCreated {
			t.Fatalf("re-affirming the selection answered %d: %s", code, body)
		}
		for _, one := range out.Claims {
			switch one.PreviousClaimID {
			case absent:
				if one.Waiting {
					t.Error("a claim that the code is absent waits after a severity rise")
				}
			case unreachable:
				if !one.Waiting {
					t.Error("a claim that the code is unreachable stood after a severity rise")
				}
			}
		}
	})
}

func TestReAffirmingManyRefusesAClaimSomebodyElseMade(t *testing.T) {
	// Re-affirming is the claimant's right. The refusal names the issues, so
	// they can be taken out of the selection.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		r.agreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.curlMovedTo(t, "8.6.0")

		code, body, _ := reaffirmingMany(t, r, "wide-triager")
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("somebody else re-affirming answered %d: %s", code, body)
		}
		if !strings.Contains(body, "CVE-2026-CURL1") || !strings.Contains(body, "CVE-2026-CURL2") {
			t.Errorf("the refusal does not name the issues: %s", body)
		}
		written, err := r.db.DB.NewSelect().Table("decision").
			Where("state <> ?", "lapsed").Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if written != 0 {
			t.Errorf("a refused act left %d decisions written", written)
		}
	})
}

func TestReAffirmingManyReachesOnlyWhatNothingReplaced(t *testing.T) {
	// A claim re-made after one bump lapses at the next, beside the claim it
	// re-made. The later one is what the place last said; re-making the
	// earlier as well would write two claims at one place.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		r.agreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.curlMovedTo(t, "8.6.0")
		code, body, first := reaffirmingMany(t, r, "triager")
		if code != http.StatusCreated {
			t.Fatalf("the first re-affirmation answered %d: %s", code, body)
		}

		r.curlMovedTo(t, "8.7.0")
		code, body, second := reaffirmingMany(t, r, "triager")
		if code != http.StatusCreated {
			t.Fatalf("the second re-affirmation answered %d: %s", code, body)
		}
		made := map[int64]bool{}
		for _, one := range first.Claims {
			made[one.ClaimID] = true
		}
		if len(second.Claims) != 2 {
			t.Fatalf("the second act re-made %d claims, want the two latest: %s",
				len(second.Claims), body)
		}
		for _, one := range second.Claims {
			if !made[one.PreviousClaimID] {
				t.Errorf("the second act re-made claim %d, which a later claim replaced",
					one.PreviousClaimID)
			}
		}
	})
}

func TestReAffirmingManyIsBoundedOverTheWholeAct(t *testing.T) {
	// Bound what is written. Each claim here is two places, inside a cap of
	// three; the act is four.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		r.agreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.curlMovedTo(t, "8.6.0")
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.together-cap",
			`{"value":"3"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}

		code, body, _ := reaffirmingMany(t, r, "triager")
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("an act past the cap answered %d: %s", code, body)
		}
		if !strings.Contains(body, "that is 4 findings") {
			t.Errorf("the refusal does not count the whole act: %s", body)
		}
	})
}
