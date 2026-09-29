// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// rulingRead is what the ruling routes answer, as a test reads it.
type rulingRead struct {
	ID          int64    `json:"id"`
	Disposition string   `json:"disposition"`
	DuplicateOf string   `json:"duplicate_of"`
	Reports     []string `json:"reports"`
	State       string   `json:"state"`
	Yours       bool     `json:"yours"`
	ApprovedBy  string   `json:"approved_by"`
}

// rulingOf reads a report's disposition fields, which ReportRead leaves out.
type rulingOf struct {
	Disposition string `json:"disposition"`
	Waiting     string `json:"waiting"`
	Ruling      int64  `json:"ruling"`
	DuplicateOf string `json:"duplicate_of"`
}

func TestSlopIsRejectedInOneActThatASecondPersonApproves(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		first := r.Claim(t, "Generated text about a function this does not have.")
		second := r.Claim(t, "More generated text about the same missing function.")

		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/report-rulings",
			fmt.Sprintf(`{"reports":[%q,%q,%q],"disposition":"rejected","reasoning":"Slop."}`,
				first, second, strings.ToLower(first)))
		if got.Code != http.StatusCreated {
			t.Fatalf("proposing answered %d: %s", got.Code, got.Body.String())
		}
		var proposed rulingRead
		if err := json.Unmarshal(got.Body.Bytes(), &proposed); err != nil {
			t.Fatal(err)
		}
		if proposed.State != "waiting" || !proposed.Yours || len(proposed.Reports) != 2 {
			t.Errorf("proposed, it reads %+v", proposed)
		}
		var report rulingOf
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/reports/"+first, &report)
		if report.Disposition != "" || report.Waiting != "rejected" || report.Ruling != proposed.ID {
			t.Errorf("a report under a waiting rejection reads %+v", report)
		}

		// The approver sees it waiting, and that it is not theirs.
		var waiting struct {
			Items []rulingRead `json:"items"`
			Total int          `json:"total"`
		}
		httpapitest.Read(t, r, "private-dispatcher", "/v1/products/mine/report-rulings?waiting=true", &waiting)
		if waiting.Total != 1 || waiting.Items[0].Yours {
			t.Errorf("the approver's waiting list reads %+v", waiting)
		}

		at := fmt.Sprintf("/v1/products/mine/report-rulings/%d", proposed.ID)
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at+"/approval", ""); got.Code !=
			http.StatusConflict {
			t.Errorf("the proposer approving answered %d: %s", got.Code, got.Body.String())
		}
		// Somebody who may read undisclosed work and neither approve nor work
		// reports. They can read the ruling, so they are refused in words
		// rather than told it is not there.
		if code := r.As(t, "private", http.MethodPost, at+"/approval"); code != http.StatusForbidden {
			t.Errorf("a private reader approving answered %d", code)
		}
		// Somebody who may not read reports at all is told it is not there.
		if code := r.As(t, "triager", http.MethodPost, at+"/approval"); code != http.StatusNotFound &&
			code != http.StatusForbidden {
			t.Errorf("a public triager approving answered %d", code)
		}
		got = httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, at+"/approval", "")
		if got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		var approved rulingRead
		if err := json.Unmarshal(got.Body.Bytes(), &approved); err != nil {
			t.Fatal(err)
		}
		if approved.State != "in-force" || approved.ApprovedBy == "" {
			t.Errorf("approved, it reads %+v", approved)
		}
		report = rulingOf{}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/reports/"+second, &report)
		if report.Disposition != "rejected" || report.Waiting != "" {
			t.Errorf("an approved rejection reads %+v on its report", report)
		}

		// Undone, the reports are back in the inbox.
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at+"/withdrawal", ""); got.Code !=
			http.StatusOK {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
		}
		report = rulingOf{}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/reports/"+second, &report)
		if report.Disposition != "" || report.Ruling != 0 {
			t.Errorf("a withdrawn rejection still reads %+v on its report", report)
		}
	})
}

func TestADuplicateIsListedOnTheIssueItDuplicates(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		minted := r.Embargoed(t)
		claimed := r.Claim(t, "The management socket lets anybody in, with a screenshot.")

		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/report-rulings",
			fmt.Sprintf(`{"reports":[%q],"disposition":"duplicate","duplicate_of":%q}`,
				claimed, minted))
		if got.Code != http.StatusCreated {
			t.Fatalf("a duplicate answered %d: %s", got.Code, got.Body.String())
		}
		var report rulingOf
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/reports/"+claimed, &report)
		if report.Disposition != "duplicate" || report.DuplicateOf != minted {
			t.Errorf("the duplicate reads %+v", report)
		}

		duplicates := "/v1/products/mine/issues/" + minted + "/duplicates"
		var listed struct {
			Items []httpapitest.ReportRead `json:"items"`
		}
		httpapitest.Read(t, r, "private-triage", duplicates, &listed)
		if len(listed.Items) != 1 || listed.Items[0].Reference != claimed {
			t.Errorf("the issue lists duplicates %+v", listed.Items)
		}
		// Somebody who reads undisclosed work reads them; somebody who
		// triages announced work only reads the issue and none of them.
		if code := r.As(t, "private", http.MethodGet, duplicates); code != http.StatusOK {
			t.Errorf("a private reader reading duplicates answered %d", code)
		}
		if code := r.As(t, "triager", http.MethodGet, duplicates); code != http.StatusForbidden {
			t.Errorf("a public triager reading duplicates answered %d", code)
		}

		// Somebody who may not work reports is refused alike whether the
		// issue named is here or not, so the route is not a way to ask.
		for _, name := range []string{"CVE-2026-9999", "CVE-1999-0001"} {
			for _, path := range []string{
				"/v1/products/mine/issues/" + name + "/duplicates",
			} {
				got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, path, "")
				if got.Code != http.StatusForbidden {
					t.Errorf("GET %s as a public triager answered %d: %s",
						path, got.Code, got.Body.String())
				}
			}
			got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, "/v1/products/mine/report-rulings",
				fmt.Sprintf(`{"reports":[%q],"disposition":"duplicate","duplicate_of":%q}`,
					claimed, name))
			if got.Code != http.StatusForbidden {
				t.Errorf("a public triager naming %s answered %d: %s", name, got.Code,
					got.Body.String())
			}
			got = httpapitest.AsPerson(t, r, "triager", http.MethodPut,
				"/v1/products/mine/reports/"+claimed+"/issue",
				fmt.Sprintf(`{"vulnerability":%q}`, name))
			if got.Code != http.StatusNotFound ||
				!strings.Contains(got.Body.String(), "no report here goes by that name") {
				t.Errorf("a public triager accepting as %s answered %d: %s", name, got.Code,
					got.Body.String())
			}
		}

		// An issue that is not here answers as one nobody may be told of.
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/report-rulings",
			fmt.Sprintf(`{"reports":[%q],"disposition":"duplicate","duplicate_of":"CVE-1999-0001"}`,
				r.Claim(t, "Another."))); got.Code != http.StatusNotFound {
			t.Errorf("a duplicate of an issue not here answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestRulingsAcrossProductsAreThoseInProductsTheReaderWorksReportsIn(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		claimed := r.Claim(t, "Generated text about a function this does not have.")
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/report-rulings",
			fmt.Sprintf(`{"reports":[%q],"disposition":"rejected","reasoning":"Slop."}`,
				claimed)); got.Code != http.StatusCreated {
			t.Fatalf("proposing answered %d: %s", got.Code, got.Body.String())
		}

		type across struct {
			Items []rulingRead `json:"items"`
			Total int          `json:"total"`
		}
		var seen across
		httpapitest.Read(t, r, "private-dispatcher", "/v1/report-rulings?waiting=true", &seen)
		if seen.Total != 1 || len(seen.Items) != 1 {
			t.Fatalf("somebody who works reports reads %+v", seen)
		}
		var named struct {
			Items []struct {
				Product string `json:"product"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "private-dispatcher", "/v1/report-rulings", &named)
		if len(named.Items) != 1 || named.Items[0].Product != "mine" {
			t.Errorf("a ruling across products names its product as %+v", named.Items)
		}

		// A reader of undisclosed work reads them.
		var private across
		httpapitest.Read(t, r, "private", "/v1/report-rulings", &private)
		if private.Total != 1 {
			t.Errorf("a private reader reads %+v", private)
		}

		// Nothing from a product the reader may not read reports in, not
		// even the count: a public triager, and a reader of the whole estate
		// who may read nothing undisclosed.
		for _, who := range []string{"triager", "estate-reader"} {
			var none across
			httpapitest.Read(t, r, who, "/v1/report-rulings", &none)
			if none.Total != 0 || len(none.Items) != 0 {
				t.Errorf("%s reads %+v", who, none)
			}
		}

		// The period is the day it was proposed, the end exclusive.
		today := time.Now().UTC().Format(time.DateOnly)
		tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
		var within, before across
		httpapitest.Read(t, r, "private-triage", "/v1/report-rulings?from="+today+"&to="+tomorrow, &within)
		httpapitest.Read(t, r, "private-triage", "/v1/report-rulings?to="+today, &before)
		if within.Total != 1 || before.Total != 0 {
			t.Errorf("proposed today, it is %d in today and %d before it",
				within.Total, before.Total)
		}

		// Approved, it is no longer waiting.
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
			fmt.Sprintf("/v1/products/mine/report-rulings/%d/approval", seen.Items[0].ID),
			""); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		var still across
		httpapitest.Read(t, r, "private-dispatcher", "/v1/report-rulings?waiting=true", &still)
		if still.Total != 0 {
			t.Errorf("an approved ruling is still listed as waiting: %+v", still)
		}

		// Somebody holding private triage across the whole estate reaches it
		// too, through the products that exist rather than a list of grants.
		holder, err := r.Rights.Ensure(t.Context(), "estate-triager", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Rights.Claim(t.Context(), holder.ID, "estate-triager"); err != nil {
			t.Fatal(err)
		}
		if err := r.Rights.GrantEstateRole(t.Context(), holder.ID,
			access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		var estate across
		httpapitest.Read(t, r, "estate-triager", "/v1/report-rulings", &estate)
		if estate.Total != 1 {
			t.Errorf("private triage across the estate reads %+v", estate)
		}

		// A product the reader holds nothing on answers as one never declared.
		if code := r.As(t, "private-triage", http.MethodGet,
			"/v1/report-rulings?product=theirs"); code != http.StatusNotFound {
			t.Errorf("naming a product the reader cannot see answered %d", code)
		}
	})
}
