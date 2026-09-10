package httpapi_test

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi"
)

func TestWhatIsOutOfSupportIsListedBecauseNothingElseCountsIt(t *testing.T) {
	// Past end-of-life the deadline comes off every open finding, so none of
	// this is overdue, none is due soon, and none of it reaches a figure built
	// on either. That is right — nothing will be fixed there — and it means
	// asking for it is the only way to see it.
	// On every engine: what it pins is a query, and a date comparison joined
	// across two tables is exactly the shape that agrees on one of them.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		listed := func(t *testing.T, who string) struct {
			Items []httpapi.RetiredBody `json:"items"`
			Total int                   `json:"total"`
			Open  int                   `json:"open"`
		} {
			t.Helper()
			got := asPerson(t, r, who, http.MethodGet, "/v1/releases/out-of-support", "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s asking what is out of support answered %d: %s",
					who, got.Code, got.Body.String())
			}
			var out struct {
				Items []httpapi.RetiredBody `json:"items"`
				Total int                   `json:"total"`
				Open  int                   `json:"open"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
				t.Fatalf("what is out of support is not JSON: %v", err)
			}
			return out
		}

		// A supported release is not in it, which is the half that makes the
		// other half mean anything: a report answering the same thing before
		// and after would pass every assertion below.
		if before := listed(t, "private-triage"); before.Total != 0 {
			t.Fatalf("something is out of support before anything went out of support: %+v",
				before.Items)
		}

		ended := asPerson(t, r, "admin", http.MethodPut,
			"/v1/products/mine/streams/master/end-of-life", `{"on":"2020-01-01"}`)
		if ended.Code != http.StatusNoContent {
			t.Fatalf("putting a release out of support answered %d: %s",
				ended.Code, ended.Body.String())
		}

		after := listed(t, "private-triage")
		if after.Total != 1 {
			t.Fatalf("%d releases are out of support, want the one that went: %+v",
				after.Total, after.Items)
		}
		row := after.Items[0]
		if row.Product != "mine" || row.Stream != "master" {
			t.Errorf("the wrong release is out of support: %+v", row)
		}
		if row.EndedOn != "2020-01-01" {
			t.Errorf("it says support ended on %q", row.EndedOn)
		}
		if row.Inherited {
			t.Error("a date the release stated itself is reported as the product's")
		}
		if row.EndedDays <= 0 {
			t.Errorf("support ended %d days ago", row.EndedDays)
		}
		// The whole point: what is still shipped and no longer maintained.
		if row.Open == 0 || after.Open != row.Open {
			t.Errorf("nothing is open on a release with two findings on it: %+v", after)
		}
	})
}

func TestOutOfSupportSaysWhenTheFileWasTaken(t *testing.T) {
	// How long ago a release ended is only readable against a date, and a
	// spreadsheet has nowhere else to carry the day it was taken.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		ended := asPerson(t, r, "admin", http.MethodPut,
			"/v1/products/mine/streams/master/end-of-life", `{"on":"2020-01-01"}`)
		if ended.Code != http.StatusNoContent {
			t.Fatalf("putting a release out of support answered %d", ended.Code)
		}

		got := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/releases/out-of-support.csv", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", got.Code, got.Body.String())
		}
		reader := csv.NewReader(strings.NewReader(got.Body.String()))
		reader.FieldsPerRecord = -1
		lines, err := reader.ReadAll()
		if err != nil {
			t.Fatalf("it came back as something that is not a spreadsheet: %v", err)
		}
		if len(lines) < 3 {
			t.Fatalf("%d lines, want the statement, the header and a release", len(lines))
		}
		if lines[0][0] != "# taken on" || lines[0][1] == "" {
			t.Errorf("the file does not say when it was taken: %v", lines[0])
		}
		if lines[2][0] != "mine" || lines[2][1] != "master" {
			t.Errorf("the release is not in the file: %v", lines[2])
		}
	})
}
