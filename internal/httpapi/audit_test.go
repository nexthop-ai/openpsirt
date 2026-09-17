package httpapi_test

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"testing"
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
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{"batch":"a-batch"}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
		// Taken back, which is the half the file dropped.
		if got := asPerson(t, r, "reviewer", http.MethodDelete,
			"/v1/approval-batches/a-batch", ""); got.Code >= 300 {
			t.Fatalf("taking the agreement back answered %d: %s", got.Code, got.Body.String())
		}

		// The build the judgment is about.
		var about struct {
			Total int `json:"total"`
		}
		read(t, r, "private-triage",
			"/v1/audit?product=mine&stream=master&variant=broadcom", &about)
		if about.Total != 1 {
			t.Errorf("the record narrowed to the build it was decided in holds %d", about.Total)
		}

		// A second build of the same product, holding nothing: the judgment
		// is about a place that build does not have, and a decision names no
		// build, so without the match through the findings it would answer
		// here too.
		r.alsoIn(t, "mellanox")
		var elsewhere struct {
			Total int `json:"total"`
		}
		read(t, r, "private-triage",
			"/v1/audit?product=mine&stream=master&variant=mellanox", &elsewhere)
		if elsewhere.Total != 0 {
			t.Errorf("a build holding none of it answers with %d judgments", elsewhere.Total)
		}

		// A build of the same product that holds none of it.
		if got := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/audit?product=mine&stream=master&variant=nothing-is-built-this-way", ""); got.Code != http.StatusNotFound {
			t.Errorf("a variant nobody declared answered %d", got.Code)
		}
		// Half a build is refused rather than narrowing to a stream of
		// whichever product happens to share the name.
		if got := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/audit?product=mine&stream=master", ""); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a stream with no variant answered %d", got.Code)
		}

		// And the file carries the whole of the agreement record.
		file := asPerson(t, r, "private-triage", http.MethodGet, "/v1/audit.csv", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d", file.Code)
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := rowsUnder(lines)
		at := indexOf(body[0], "agreements")
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
		if standing := body[1][indexOf(body[0], "approved by")]; standing != "" {
			t.Errorf("a withdrawn agreement reads as somebody who agrees: %q", standing)
		}
	})
}
