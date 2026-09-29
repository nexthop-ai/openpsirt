// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestTheRecordNarrowsToOneBuildAndCarriesEveryAgreement is two of what a
// release sign-off and an audit each asked for and could not get.
//
// A decision names no build — it is keyed on the product, the issue and the
// place, so that it carries across releases sharing the code — so "what was
// decided about what this release ships" could not be asked at all. And the
// file dropped every approval date and every agreement taken back, which is
// what an audit is looking for.
func TestTheRecordNarrowsToOneBuildAndCarriesEveryAgreement(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		claim, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{"batch":"a-batch"}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
		// Taken back, which is the half the file dropped.
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodDelete,
			"/v1/approval-batches/a-batch", ""); got.Code >= 300 {
			t.Fatalf("taking the agreement back answered %d: %s", got.Code, got.Body.String())
		}

		// The build the judgment is about.
		var about struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "private-triage",
			"/v1/audit?product=mine&stream=master&variant=broadcom", &about)
		if about.Total != 1 {
			t.Errorf("the record narrowed to the build it was decided in holds %d", about.Total)
		}

		// A second build of the same product, holding nothing: the judgment
		// is about a place that build does not have, and a decision names no
		// build, so without the match through the findings it would answer
		// here too.
		r.AlsoIn(t, "mellanox")
		var elsewhere struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "private-triage",
			"/v1/audit?product=mine&stream=master&variant=mellanox", &elsewhere)
		if elsewhere.Total != 0 {
			t.Errorf("a build holding none of it answers with %d judgments", elsewhere.Total)
		}

		// A build of the same product that holds none of it.
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/audit?product=mine&stream=master&variant=nothing-is-built-this-way", ""); got.Code != http.StatusNotFound {
			t.Errorf("a variant nobody declared answered %d", got.Code)
		}
		// Half a build is refused rather than narrowing to a stream of
		// whichever product happens to share the name.
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/audit?product=mine&stream=master", ""); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a stream with no variant answered %d", got.Code)
		}

		// And the file carries the whole of the agreement record.
		file := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet, "/v1/audit.csv", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d", file.Code)
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := httpapitest.RowsUnder(lines)
		at := httpapitest.IndexOf(body[0], "agreements")
		if at < 0 {
			t.Fatalf("the file has no agreements column: %v", body[0])
		}
		if len(body) < 2 {
			t.Fatal("the file holds no judgment")
		}
		said := body[1][at]
		if !strings.Contains(said, "reviewer") || !strings.Contains(said, "withdrawn") {
			t.Errorf("the file does not carry the agreement that was taken back: %q", said)
		}
		// With a date, which is the other half: an agreement with no date is
		// not evidence of when the control held.
		if !strings.Contains(said, "20") {
			t.Errorf("the file carries no date for the agreement: %q", said)
		}
		// And who agrees now stays who agrees now.
		if standing := body[1][httpapitest.IndexOf(body[0], "approved by")]; standing != "" {
			t.Errorf("a withdrawn agreement reads as somebody who agrees: %q", standing)
		}
	})
}
