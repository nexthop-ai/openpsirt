// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAFlawCarriesWhoToldUsAndWhenItArrived(t *testing.T) {
	// Without the reporter the coordinated-disclosure timeline cannot be
	// evidenced at all, and the advisory's acknowledgments section — the
	// part a researcher reads first — is empty.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		// Received a fortnight before it was typed in, which is the case the
		// clock rule exists for.
		arrived := time.Now().UTC().AddDate(0, 0, -14).Format(time.DateOnly)
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"summary":"The management socket answers before anyone has authenticated.",`+
				`"severity":"high","component":"libnl-3-200",`+
				`"reported_by":"A. Researcher","contact":"a@example.org",`+
				`"credit":"anonymous","received":"`+arrived+`"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}

		at := "/v1/products/mine/issues/" + recorded.Identifier + "/report"
		var told struct {
			ReportedBy   string `json:"reported_by"`
			Contact      string `json:"contact"`
			Credit       string `json:"credit"`
			Received     string `json:"received"`
			Acknowledged string `json:"acknowledged"`
		}
		httpapitest.Read(t, r, "private-triage", at, &told)
		if told.ReportedBy != "A. Researcher" || told.Contact != "a@example.org" {
			t.Errorf("who told us reads as %+v", told)
		}
		if told.Credit != "anonymous" {
			t.Errorf("how they wish to be credited reads as %q", told.Credit)
		}
		if told.Received != arrived {
			t.Errorf("the day it arrived reads as %q, want %q", told.Received, arrived)
		}
		if told.Acknowledged != "" {
			t.Error("a report nobody answered reads as answered")
		}

		// The embargo runs from when it arrived, not from when it was typed
		// in: they are counting from the day they sent it, and they are the
		// party who will publish regardless.
		var detail struct {
			DiscloseAt string `json:"disclose_at"`
		}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/"+recorded.Identifier+"/components/libnl-3-200", &detail)
		want := time.Now().UTC().AddDate(0, 0, -14).AddDate(0, 0, 90).Format(time.DateOnly)
		if detail.DiscloseAt != want {
			t.Errorf("the embargo ends %q, want %q — it should run from receipt",
				detail.DiscloseAt, want)
		}

		// Nobody has answered them, which is a condition rather than an event:
		// what is wrong is that nothing has happened.
		waiting := r.Alerts(t, "private-triage", "unanswered-report")
		if len(waiting) != 1 {
			t.Fatalf("an unanswered report raised %d notices: %v", len(waiting), waiting)
		}
		if !httpapitest.Contains(waiting[0], "A. Researcher") {
			t.Errorf("the notice does not say who is waiting: %q", waiting[0])
		}
		// And not to somebody who may not read undisclosed work here.
		if told := r.Alerts(t, "triager", "unanswered-report"); len(told) != 0 {
			t.Errorf("somebody who may not read the flaw was told about it: %v", told)
		}

		// Answering clears it, and is dated.
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			at+"/acknowledgement", ""); got.Code != http.StatusNoContent {
			t.Fatalf("acknowledging answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.Read(t, r, "private-triage", at, &told)
		if told.Acknowledged == "" {
			t.Error("acknowledging recorded no date")
		}
		if still := r.Alerts(t, "private-triage", "unanswered-report"); len(still) != 0 {
			t.Errorf("an answered report is still reported as unanswered: %v", still)
		}
	})
}

func TestACVEAssignedLaterBecomesAnotherNameForTheSameIssue(t *testing.T) {
	// The code anticipated this in a comment and nothing implemented it,
	// so a published advisory shipped an internal identifier and no CVE —
	// and nobody searching by the CVE found the advisory, which is the one
	// lookup a published advisory exists to serve.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		minted := r.Embargoed(t)

		alias := func(who, name string) int {
			return httpapitest.AsPerson(t, r, who, http.MethodPut,
				fmt.Sprintf("/v1/products/mine/issues/%s/aliases/%s", minted, name), "").Code
		}
		if code := alias("private-triage", "CVE-2027-0001"); code != http.StatusNoContent {
			t.Fatalf("recording another name answered %d", code)
		}

		// It is now filed under the name a reader will look for, and the name
		// it was minted under still resolves — nothing keyed on the issue
		// moved, because none of it was keyed on what it is called.
		var detail struct {
			Vulnerability string   `json:"vulnerability"`
			Aliases       []string `json:"aliases"`
		}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/"+minted+"/components/libnl-3-200", &detail)
		if detail.Vulnerability != "CVE-2027-0001" {
			t.Errorf("the issue is filed under %q, want the CVE", detail.Vulnerability)
		}
		var byNewName struct {
			Vulnerability string `json:"vulnerability"`
		}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2027-0001/components/libnl-3-200", &byNewName)
		if byNewName.Vulnerability != "CVE-2027-0001" {
			t.Errorf("the new name does not resolve: %+v", byNewName)
		}

		// Recording it again changes nothing.
		if code := alias("private-triage", "CVE-2027-0001"); code != http.StatusNoContent {
			t.Errorf("recording a name it already goes by answered %d", code)
		}

		// A name another issue already answers to is refused rather than
		// silently merging two records.
		if code := alias("private-triage", "CVE-2026-9999"); code != http.StatusConflict {
			t.Errorf("a name another issue holds answered %d, want 409", code)
		}
	})
}

func TestWhoToldUsNeedsTheRightItSaysItNeeds(t *testing.T) {
	// The route declares the rights it enforces, because the declaration is
	// what the generated reference tells an operator the rule is.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"summary":"The management socket answers before anyone has authenticated.",`+
				`"severity":"high","component":"libnl-3-200",`+
				`"reported_by":"A. Researcher","contact":"a@example.org"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}

		at := "/v1/products/mine/issues/" + recorded.Identifier + "/report"
		// Who reported it is read with the right that reads the report itself:
		// undisclosed work in the product, whether or not the reader may act.
		for _, who := range []string{"private", "private-triage"} {
			if ok := httpapitest.AsPerson(t, r, who, http.MethodGet, at, ""); ok.Code != http.StatusOK {
				t.Errorf("%s was refused the reporter's details: %d %s",
					who, ok.Code, ok.Body.String())
			}
		}
		// Somebody who argues about public findings and reads nothing
		// undisclosed is told nobody is recorded.
		if refused := httpapitest.AsPerson(t, r, "triager", http.MethodGet, at, ""); refused.Code != http.StatusNotFound {
			t.Errorf("a triager who reads no undisclosed work was answered %d: %s",
				refused.Code, refused.Body.String())
		}
		// Answering the reporter is working the report, which reading it does
		// not grant.
		if refused := httpapitest.AsPerson(t, r, "private", http.MethodPost, at+"/acknowledgement", ""); refused.Code != http.StatusForbidden {
			t.Errorf("a reader answered the reporter: %d", refused.Code)
		}
	})
}
