// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestABulkClaimSkippingDecidedPlacesSaysWhichItLeftOut(t *testing.T) {
	// The response is where the claimant learns the claim is smaller than the
	// selection, so each skipped place comes back by the issue's name with
	// the decision standing there.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/linux-image/decisions"
		claim := func(issues, extra string) *struct {
			code int
			body string
		} {
			got := asPerson(t, r, "triager", http.MethodPost, at,
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
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/linux-image/decisions"
		const body = `{"vulnerabilities":["CVE-2026-9999","CVE-2026-1000"],` +
			`"outcome":"wont-fix","selected_by":"the drivers",` +
			`"reasoning":"Not built for this image."}`
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.review-issues",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the limit answered %d: %s", got.Code, got.Body.String())
		}
		refused := asPerson(t, r, "triager", http.MethodPost, at, body)
		if refused.Code != http.StatusUnprocessableEntity ||
			!strings.Contains(refused.Body.String(), "that is 2 issues") {
			t.Fatalf("two issues under a limit of one answered %d: %s",
				refused.Code, refused.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.review-issues",
			`{"value":"2"}`); got.Code != http.StatusNoContent {
			t.Fatalf("raising the limit answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "triager", http.MethodPost, at, body); got.Code !=
			http.StatusCreated {
			t.Errorf("two issues under a limit of two answered %d: %s", got.Code, got.Body.String())
		}
	})
}
