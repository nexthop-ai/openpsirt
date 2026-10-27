// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// agreedThenWithdrawn is an agreement cell naming who agreed, when, and when
// it was taken back, in that order.
var agreedThenWithdrawn = regexp.MustCompile(`^reviewer \d{4}-\d{2}-\d{2}T\S+ withdrawn \d{4}-\d{2}-\d{2}T`)

// TestTheRecordNarrowsToOneBuildAndCarriesEveryAgreement is two of what a
// release sign-off and an audit each asked for and could not get.
//
// A decision names no build — it is keyed on the product, the issue and the
// occurrence, so that it carries across releases sharing the code — so "what was
// decided about what this release ships" could not be asked at all. And the
// file dropped every approval date and every agreement taken back, which is
// what an audit is looking for.
func TestTheRecordNarrowsToOneBuildAndCarriesEveryAgreement(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decision), `{"batch":"a-batch"}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
		// Taken back, which is the half the file dropped.
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodDelete,
			"/v1/approval-batches/a-batch", ""); got.Code >= 300 {
			t.Fatalf("taking the agreement back answered %d: %s", got.Code, got.Body.String())
		}

		// The build the decision is about.
		var about struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "private-triage",
			"/v1/audit?product=mine&stream=master&variant=broadcom", &about)
		if about.Total != 1 {
			t.Errorf("the record narrowed to the build it was decided in holds %d", about.Total)
		}

		// A second build of the same product, holding nothing: the decision
		// is about an occurrence that build does not have, and a decision names no
		// build, so without the match through the findings it would answer
		// here too.
		r.AlsoIn(t, "mellanox")
		var elsewhere struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "private-triage",
			"/v1/audit?product=mine&stream=master&variant=mellanox", &elsewhere)
		if elsewhere.Total != 0 {
			t.Errorf("a build holding none of it answers with %d decisions", elsewhere.Total)
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
			t.Fatal("the file holds no decision")
		}
		said := body[1][at]
		if !strings.Contains(said, "reviewer") || !strings.Contains(said, "withdrawn") {
			t.Errorf("the file does not carry the agreement that was taken back: %q", said)
		}
		// With a date, which is the other half: an agreement with no date is
		// not evidence of when the control held. The withdrawal carries a
		// date of its own, so the agreement's is the one before it.
		if !agreedThenWithdrawn.MatchString(said) {
			t.Errorf("the file carries no date for the agreement: %q", said)
		}
		// And who agrees now stays who agrees now.
		if standing := body[1][httpapitest.IndexOf(body[0], "approved by")]; standing != "" {
			t.Errorf("a withdrawn agreement reads as somebody who agrees: %q", standing)
		}
	})
}

func TestTheRecordListsOneEntryPerDecisionAndTheFileOneRowPerOccurrence(t *testing.T) {
	// One act across a fold covers several occurrences. The screen's list is
	// the act, once, saying how much it covers; the file is every occurrence,
	// each carrying the decision it belongs to so a spreadsheet can group them.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		decision := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")

		var occurrences struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "reviewer", "/v1/audit", &occurrences)
		if occurrences.Total < 2 {
			t.Fatalf("the act covered %d occurrences, want one per occurrence across the fold", occurrences.Total)
		}

		var decisions struct {
			Items []struct {
				Decision    int64  `json:"decision"`
				Rows        int    `json:"rows"`
				Occurrences int    `json:"occurrences"`
				State       string `json:"state"`
				Standing    int    `json:"standing"`
				TwoPeople   bool   `json:"two_people"`
				States      struct {
					Approved int `json:"approved"`
				} `json:"states"`
			} `json:"items"`
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "reviewer", "/v1/audit/decisions", &decisions)
		if decisions.Total != 1 || len(decisions.Items) != 1 || decisions.Items[0].Decision != decision {
			t.Fatalf("the record by decision lists %+v, want decision %d once", decisions, decision)
		}
		got := decisions.Items[0]
		if got.Rows != occurrences.Total || got.Occurrences != occurrences.Total ||
			got.States.Approved != occurrences.Total || got.Standing != occurrences.Total {
			t.Errorf("the decision reads %+v, want all %d occurrences, approved and standing",
				got, occurrences.Total)
		}
		if got.State != "approved" || !got.TwoPeople {
			t.Errorf("an agreed decision reads %q, two people %v", got.State, got.TwoPeople)
		}

		// Narrowed to a state none of its occurrences is in, the decision is absent
		// and the total says so.
		var lapsed struct {
			Items []struct{} `json:"items"`
			Total int        `json:"total"`
		}
		httpapitest.Read(t, r, "reviewer", "/v1/audit/decisions?state=lapsed", &lapsed)
		if lapsed.Total != 0 || len(lapsed.Items) != 0 {
			t.Errorf("asked for what lapsed, the record lists %d decisions", lapsed.Total)
		}

		file := httpapitest.AsPerson(t, r, "reviewer", http.MethodGet, "/v1/audit.csv", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d", file.Code)
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := httpapitest.RowsUnder(lines)
		at := httpapitest.IndexOf(body[0], "decision")
		if at < 0 {
			t.Fatalf("the file has no decision column: %v", body[0])
		}
		if len(body)-1 != occurrences.Total {
			t.Fatalf("the file holds %d rows, want one per occurrence: %d", len(body)-1, occurrences.Total)
		}
		for _, row := range body[1:] {
			if row[at] != fmt.Sprint(decision) {
				t.Errorf("an occurrence of decision %d is filed under decision %q", decision, row[at])
			}
		}
	})
}
