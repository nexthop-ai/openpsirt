// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// recordReport records a claim in the product "mine" and answers the path it
// is reached by.
func recordReport(t *testing.T, r *httpapitest.Reach) string {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/reports",
		`{"summary":"The management socket answers before anyone has authenticated.",`+
			`"reported_by":"A. Researcher"}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording a claim answered %d: %s", got.Code, got.Body.String())
	}
	var recorded httpapitest.ReportRead
	if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	return "/v1/products/mine/reports/" + recorded.Reference
}

// told counts the notices of one kind written for one person.
func told(t *testing.T, r *httpapitest.Reach, who string, kind notify.Kind) int {
	t.Helper()
	n, err := r.DB.DB.NewSelect().TableExpr(`"notification" AS "n"`).
		Join(`JOIN "person" AS "p" ON "p"."id" = "n"."person_id"`).
		Where(`"p"."identity" = ?`, who).
		Where(`"n"."kind" = ?`, kind).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

type heldReports struct {
	Items []struct {
		Reference  string `json:"reference"`
		AssignedTo string `json:"assigned_to"`
	} `json:"items"`
	Total int `json:"total"`
}

func TestAReportIsGivenOnlyToSomebodyWhoReadsReportsAndTheyAreTold(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		at := recordReport(t, r)

		var waiting heldReports
		httpapitest.Read(t, r, "private-triage", "/v1/unassigned/reports", &waiting)
		if waiting.Total != 1 {
			t.Fatalf("%d reports wait for somebody, want 1", waiting.Total)
		}

		// A reader of disclosed work alone cannot open a report, so it is not
		// given to them, and nothing tells them it exists.
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, at+"/assignment",
			`{"person":"triager"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("giving a report to somebody who cannot read it answered %d: %s", got.Code, got.Body)
		}
		if n := told(t, r, "triager", notify.Assigned); n != 0 {
			t.Errorf("somebody who cannot read reports was told about one %d times", n)
		}

		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, at+"/assignment",
			`{"person":"private"}`); got.Code != http.StatusNoContent {
			t.Fatalf("giving a report to a reader of reports answered %d: %s", got.Code, got.Body)
		}
		if n := told(t, r, "private", notify.Assigned); n != 1 {
			t.Errorf("the person given the report was told %d times, want once", n)
		}

		var theirs heldReports
		httpapitest.Read(t, r, "private-triage", "/v1/people/private/assignments/reports", &theirs)
		if theirs.Total != 1 || len(theirs.Items) != 1 || theirs.Items[0].AssignedTo != "private" {
			t.Errorf("what they hold reads as %+v", theirs)
		}
		// A fresh value, because a total of zero is left out of the answer.
		waiting = heldReports{}
		httpapitest.Read(t, r, "private-triage", "/v1/unassigned/reports", &waiting)
		if waiting.Total != 0 || len(waiting.Items) != 0 {
			t.Errorf("%d reports still wait for somebody after one was given out", waiting.Total)
		}
		// The same list asked by somebody who reads no reports is empty.
		var hidden heldReports
		httpapitest.Read(t, r, "triager", "/v1/people/private/assignments/reports", &hidden)
		if hidden.Total != 0 || len(hidden.Items) != 0 {
			t.Errorf("somebody who reads no reports was shown %+v", hidden)
		}

		// Taking a report a colleague holds is the assigner's to do.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage", http.MethodPut,
			at+"/assignment", `{"person":"private-triage"}`), http.StatusForbidden)
	})
}

func TestAMessageFromTheReporterIsToldToWhoeverHoldsTheReport(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		at := recordReport(t, r)
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, at+"/assignment",
			`{"person":"private-triage"}`); got.Code != http.StatusNoContent {
			t.Fatalf("giving the report out answered %d: %s", got.Code, got.Body)
		}

		// A message sent is the holder's own act and tells nobody.
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, at+"/messages",
			`{"direction":"sent","body":"Thank you; we are looking."}`); got.Code != http.StatusCreated {
			t.Fatalf("recording a message sent answered %d: %s", got.Code, got.Body)
		}
		if n := told(t, r, "private-triage", notify.ReportMessage); n != 0 {
			t.Errorf("a message sent was told to the holder %d times", n)
		}

		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, at+"/messages",
			`{"direction":"received","body":"Any news?"}`); got.Code != http.StatusCreated {
			t.Fatalf("recording a message received answered %d: %s", got.Code, got.Body)
		}
		if n := told(t, r, "private-triage", notify.ReportMessage); n != 1 {
			t.Errorf("the holder was told of the reporter's message %d times, want once", n)
		}

		var one httpapitest.ReportRead
		httpapitest.Read(t, r, "private-triage", at, &one)
		if one.Acknowledged == "" {
			t.Error("a report with a message sent reads as unacknowledged")
		}
	})
}

func TestANoteOnAReportTellsOnlyThoseWhoReadReports(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		at := recordReport(t, r)

		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at+"/notes",
			`{"body":"@private and @triager, have a look."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("noting on a report answered %d: %s", got.Code, got.Body)
		}
		var written struct {
			NotNotified []string `json:"not_notified"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &written); err != nil {
			t.Fatal(err)
		}
		if len(written.NotNotified) != 1 || written.NotNotified[0] != "triager" {
			t.Errorf("the names nobody was told about read as %v, want only triager", written.NotNotified)
		}
		if n := told(t, r, "private", notify.Mentioned); n != 1 {
			t.Errorf("a reader of reports named in a note was told %d times, want once", n)
		}
		if n := told(t, r, "triager", notify.Mentioned); n != 0 {
			t.Errorf("somebody who reads no reports was told of a note %d times", n)
		}

		// Reading the notes is the report's rule; writing one is working it.
		if got := httpapitest.AsPerson(t, r, "private", http.MethodGet, at+"/notes", ""); got.Code != http.StatusOK {
			t.Errorf("a reader of reports reading its notes answered %d", got.Code)
		}
		if got := httpapitest.AsPerson(t, r, "private", http.MethodPost, at+"/notes",
			`{"body":"Me too."}`); got.Code != http.StatusForbidden {
			t.Errorf("a reader of reports writing a note answered %d, want 403", got.Code)
		}
		// Somebody who reads no reports is told the report is not there.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "triager", http.MethodGet, at+"/notes", ""),
			http.StatusNotFound)
	})
}
