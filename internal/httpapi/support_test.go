package httpapi_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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
		if states(lines)["taken on"] == "" {
			t.Errorf("the file does not say when it was taken: %v", states(lines))
		}
		// And what it is, which is the half that tells one file from another
		// once both are in somebody's downloads.
		if states(lines)["export"] == "" {
			t.Errorf("the file does not say what it is: %v", states(lines))
		}
		release := rowsUnder(lines)[1]
		if release[0] != "mine" || release[1] != "master" {
			t.Errorf("the release is not in the file: %v", release)
		}
	})
}

// TestNothingWarnedBeforeAReleaseCrossed is the warning half.
//
// The day a release goes out of support the deadline comes off every open
// finding on it, so a pile of work leaves every overdue count at once with
// nobody having decided anything. The report was past-only, so the first sight
// of it was the figures moving.
func TestNothingWarnedBeforeAReleaseCrossed(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		soon := time.Now().UTC().AddDate(0, 0, 20).Format(time.DateOnly)
		ending := asPerson(t, r, "admin", http.MethodPut,
			"/v1/products/mine/streams/master/end-of-life",
			fmt.Sprintf(`{"on":%q}`, soon))
		if ending.Code != http.StatusNoContent {
			t.Fatalf("giving a release an end date answered %d: %s",
				ending.Code, ending.Body.String())
		}

		asked := func(t *testing.T, query string) struct {
			Items []struct {
				Stream string `json:"stream"`
			} `json:"items"`
			Ending []struct {
				Stream    string `json:"stream"`
				EndedDays int    `json:"ended_days"`
				Ended     bool   `json:"ended"`
			} `json:"ending"`
			EndingOpen int `json:"ending_open"`
		} {
			t.Helper()
			var out struct {
				Items []struct {
					Stream string `json:"stream"`
				} `json:"items"`
				Ending []struct {
					Stream    string `json:"stream"`
					EndedDays int    `json:"ended_days"`
					Ended     bool   `json:"ended"`
				} `json:"ending"`
				EndingOpen int `json:"ending_open"`
			}
			read(t, r, "private-triage", "/v1/releases/out-of-support"+query, &out)
			return out
		}

		// Asked for nothing, this is the past-only report it has always been.
		// A second population appearing unasked would change what every figure
		// on the screen counts.
		if now := asked(t, ""); len(now.Items) != 0 || len(now.Ending) != 0 {
			t.Fatalf("a release that has not ended is already in the report: %+v", now)
		}

		// Asked ahead, it is a warning with a date on it.
		ahead := asked(t, "?within=30")
		if len(ahead.Items) != 0 {
			t.Errorf("a release that has not ended is listed as out of support: %+v", ahead.Items)
		}
		if len(ahead.Ending) != 1 || ahead.Ending[0].Stream != "master" {
			t.Fatalf("the release about to go is not in the warning: %+v", ahead.Ending)
		}
		if ahead.Ending[0].Ended {
			t.Error("a release whose date has not arrived is reported as ended")
		}
		// Negative, which is the same figure read the other way: how long is
		// left rather than how long ago.
		if ahead.Ending[0].EndedDays >= 0 {
			t.Errorf("a date twenty days ahead reads as %d days ago",
				ahead.Ending[0].EndedDays)
		}
		// And what leaves every overdue count on the day it crosses, which is
		// the number the warning is for.
		if ahead.EndingOpen == 0 {
			t.Error("the warning does not say what is open on what is about to go")
		}

		// A horizon short of the date says nothing, which is what makes the
		// parameter a question rather than a switch.
		if near := asked(t, "?within=5"); len(near.Ending) != 0 {
			t.Errorf("a release ending in twenty days is warned about five days out: %+v",
				near.Ending)
		}

		// The file says which of the two a row is, in a word: a spreadsheet
		// sorted on the days column puts them either side of zero, and a
		// reader has to notice a minus sign to tell them apart.
		file := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/releases/out-of-support.csv?within=30", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d", file.Code)
		}
		reader := csv.NewReader(strings.NewReader(file.Body.String()))
		reader.FieldsPerRecord = -1
		lines, err := reader.ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := rowsUnder(lines)
		at := indexOf(body[0], "state")
		if at < 0 {
			t.Fatalf("the file has no state column: %v", body[0])
		}
		if len(body) < 2 || body[1][at] != "ending" {
			t.Errorf("the file does not say which population the row is: %v", body)
		}
	})
}
