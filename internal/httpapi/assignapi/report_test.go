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

// recordReport records a vulnerability report in the product "mine" and answers the path it
// is reached by.
func recordReport(t *testing.T, r *httpapitest.Reach) string {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/reports",
		`{"reported_problem":"The management socket answers before anyone has authenticated.",`+
			`"reported_by":"A. Researcher"}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording a report answered %d: %s", got.Code, got.Body.String())
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

		// A message sent is told to whoever watches the report, apart from
		// whoever recorded it.
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, at+"/messages",
			`{"direction":"sent","body":"Thank you; we are looking."}`); got.Code != http.StatusCreated {
			t.Fatalf("recording a message sent answered %d: %s", got.Code, got.Body)
		}
		if n := told(t, r, "private-triage", notify.ReportMessage); n != 0 {
			t.Errorf("a message sent was told to the holder as the reporter writing %d times", n)
		}
		if n := told(t, r, "private-triage", notify.ReportSent); n != 1 {
			t.Errorf("the holder was told of a message sent %d times, want once", n)
		}
		if n := told(t, r, "private-dispatcher", notify.ReportSent); n != 0 {
			t.Errorf("whoever recorded a message sent was told of it %d times", n)
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

func TestANoteOnAReportIsToldToItsHolderAndNotToItsAuthor(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		at := recordReport(t, r)
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, at+"/assignment",
			`{"person":"private-triage"}`); got.Code != http.StatusNoContent {
			t.Fatalf("giving the report out answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, at+"/notes",
			`{"body":"The reporter's address bounces."}`); got.Code != http.StatusCreated {
			t.Fatalf("noting on a report answered %d: %s", got.Code, got.Body)
		}
		if n := told(t, r, "private-triage", notify.ReportNoted); n != 1 {
			t.Errorf("the holder was told of a colleague's note %d times, want once", n)
		}
		if n := told(t, r, "private-dispatcher", notify.ReportNoted); n != 0 {
			t.Errorf("the note's author was told of it %d times", n)
		}
		// Named in a note, the holder hears of the mention alone.
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, at+"/notes",
			`{"body":"@private-triage, can you reply?"}`); got.Code != http.StatusCreated {
			t.Fatalf("noting on a report answered %d: %s", got.Code, got.Body)
		}
		if n := told(t, r, "private-triage", notify.ReportNoted); n != 1 {
			t.Errorf("the holder named in a note was told of it as a note too: %d notes, want 1", n)
		}
		if n := told(t, r, "private-triage", notify.Mentioned); n != 1 {
			t.Errorf("the holder named in a note was told of the mention %d times, want once", n)
		}
	})
}

// A report goes to a team only where one member reads reports in the
// product. The team's queue lists it for somebody who reads reports and for
// nobody else, a team nobody declared holds nothing, and the totals list the
// team for the report it holds though it holds no finding.
func TestAReportGoesToATeamOnlyWhereAMemberReadsReports(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		at := recordReport(t, r)
		for _, team := range []string{
			`{"name":"intake","members":["private-triage"]}`,
			`{"name":"readers","members":["triager"]}`,
		} {
			if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams", team); made.Code != http.StatusCreated {
				t.Fatalf("declaring %s answered %d: %s", team, made.Code, made.Body)
			}
		}

		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, at+"/assignment",
			`{"team":"readers"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("giving a report to a team nobody on which reads reports answered %d: %s",
				got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, at+"/assignment",
			`{"team":"intake"}`); got.Code != http.StatusNoContent {
			t.Fatalf("giving a report to a team that reads reports answered %d: %s", got.Code, got.Body)
		}

		queue := func(who, team string) heldReports {
			var out heldReports
			httpapitest.Read(t, r, who, "/v1/teams/"+team+"/assignments/reports", &out)
			return out
		}
		if held := queue("private-triage", "intake"); held.Total != 1 || len(held.Items) != 1 ||
			"/v1/products/mine/reports/"+held.Items[0].Reference != at {
			t.Errorf("the team's queue reads as %+v, want the one report at %s", held, at)
		}
		if held := queue("triager", "intake"); held.Total != 0 || len(held.Items) != 0 {
			t.Errorf("somebody who reads no reports was shown the team's queue: %+v", held)
		}
		if held := queue("private-triage", "readers"); held.Total != 0 || len(held.Items) != 0 {
			t.Errorf("a team that was refused the report holds %+v", held)
		}
		if held := queue("private-triage", "no-such-team"); held.Total != 0 || len(held.Items) != 0 {
			t.Errorf("a team nobody declared holds %+v", held)
		}

		var holding struct {
			Items []struct {
				Person  string `json:"person"`
				Team    bool   `json:"team"`
				Open    int    `json:"open"`
				Reports int    `json:"reports"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "private-dispatcher", "/v1/assignments", &holding)
		if len(holding.Items) != 1 || !holding.Items[0].Team || holding.Items[0].Open != 0 ||
			holding.Items[0].Reports != 1 {
			t.Errorf("the totals read as %+v, want the team alone holding one report and no finding",
				holding.Items)
		}
	})
}
