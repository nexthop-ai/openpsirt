// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestABulkClaimSkippingDecidedPlacesSaysWhichItLeftOut(t *testing.T) {
	// The response is where the claimant learns the claim is smaller than the
	// selection, so each skipped place comes back by the issue's name with
	// the decision standing there.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/linux-image/decisions"
		claim := func(issues, extra string) *struct {
			code int
			body string
		} {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
				`{"vulnerabilities":[`+issues+`],"outcome":"wont-fix",`+
					`"selected_by":"the drivers","reasoning":"Not built for this image."`+
					extra+`}`)
			return &struct {
				code int
				body string
			}{got.Code, got.Body.String()}
		}
		if got := claim(`"CVE-2026-1000"`, ""); got.code != http.StatusCreated {
			t.Fatalf("the first claim answered %d: %s", got.code, got.body)
		}
		if got := claim(`"CVE-2026-9999","CVE-2026-1000"`, ""); got.code !=
			http.StatusUnprocessableEntity {
			t.Fatalf("a selection covering a decided place answered %d: %s", got.code, got.body)
		}

		got := claim(`"CVE-2026-9999","CVE-2026-1000"`, `,"skip_decided":true`)
		if got.code != http.StatusCreated {
			t.Fatalf("skipping answered %d: %s", got.code, got.body)
		}
		var made struct {
			Recorded int `json:"recorded"`
			Skipped  []struct {
				Vulnerability string `json:"vulnerability"`
				Decision      int64  `json:"decision"`
				State         string `json:"state"`
			} `json:"skipped"`
		}
		if err := json.Unmarshal([]byte(got.body), &made); err != nil {
			t.Fatal(err)
		}
		if made.Recorded != 1 || len(made.Skipped) != 1 ||
			made.Skipped[0].Vulnerability != "CVE-2026-1000" ||
			made.Skipped[0].Decision == 0 || made.Skipped[0].State != "proposed" {
			t.Errorf("the claim reads %+v, want one recorded and CVE-2026-1000 skipped", made)
		}

		if got := claim(`"CVE-2026-9999","CVE-2026-1000"`, `,"skip_decided":true`); got.code !=
			http.StatusUnprocessableEntity {
			t.Errorf("a selection with nothing left to claim answered %d: %s", got.code, got.body)
		}
	})
}

func TestABulkAnswerIsBoundedByTheIssuesItAsksAReviewerToRead(t *testing.T) {
	// A reviewer reads issues, so a new answer about many of them is counted
	// in issues. Two issues against a limit of one is refused whatever the
	// place ceiling, and passes once the limit is two.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/linux-image/decisions"
		const body = `{"vulnerabilities":["CVE-2026-9999","CVE-2026-1000"],` +
			`"outcome":"wont-fix","selected_by":"the drivers",` +
			`"reasoning":"Not built for this image."}`
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.review-issues",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the limit answered %d: %s", got.Code, got.Body.String())
		}
		refused := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at, body)
		if refused.Code != http.StatusUnprocessableEntity ||
			!strings.Contains(refused.Body.String(), "that is 2 issues") {
			t.Fatalf("two issues under a limit of one answered %d: %s",
				refused.Code, refused.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.review-issues",
			`{"value":"2"}`); got.Code != http.StatusNoContent {
			t.Fatalf("raising the limit answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at, body); got.Code !=
			http.StatusCreated {
			t.Errorf("two issues under a limit of two answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestABulkDeferralRecordsTheDateItRunsTo(t *testing.T) {
	// A date is read only for a deferral, and refused beside any other
	// outcome or where it is not a date.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/linux-image/decisions"
		decide := func(outcome, until string) (int, string) {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
				`{"vulnerabilities":["CVE-2026-9999","CVE-2026-1000"],"outcome":"`+outcome+`",`+
					`"selected_by":"the drivers","reasoning":"Waiting on the vendor."`+
					`,"deferred_until":"`+until+`"}`)
			return got.Code, got.Body.String()
		}

		if code, body := decide("wont-fix", httpapitest.AheadOfUs); code != http.StatusUnprocessableEntity ||
			!strings.Contains(body, "only means something when the outcome is deferred") {
			t.Errorf("a date beside another outcome answered %d: %s", code, body)
		}
		if code, body := decide("deferred", "31/12/2026"); code != http.StatusUnprocessableEntity ||
			!strings.Contains(body, "that is not a date") {
			t.Errorf("a date in another layout answered %d: %s", code, body)
		}

		code, body := decide("deferred", httpapitest.AheadOfUs)
		if code != http.StatusCreated {
			t.Fatalf("a bulk deferral answered %d: %s", code, body)
		}
		var made struct {
			ClaimID  int64 `json:"claim_id"`
			Recorded int   `json:"recorded"`
		}
		if err := json.Unmarshal([]byte(body), &made); err != nil {
			t.Fatal(err)
		}
		if made.Recorded != 2 {
			t.Errorf("a deferral of two issues recorded %d", made.Recorded)
		}
		var claim struct {
			Argument struct {
				Outcome       string `json:"outcome"`
				DeferredUntil string `json:"deferred_until"`
			} `json:"argument"`
		}
		httpapitest.Read(t, r, "triager", "/v1/claims/"+httpapitest.Itoa(made.ClaimID), &claim)
		if claim.Argument.Outcome != "deferred" || claim.Argument.DeferredUntil != httpapitest.AheadOfUs {
			t.Errorf("the claim reads %+v, want deferred until %s", claim.Argument, httpapitest.AheadOfUs)
		}
	})
}
