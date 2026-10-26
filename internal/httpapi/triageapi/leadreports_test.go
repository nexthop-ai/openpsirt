// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// leadSeries is a product's lead counts by analyzer series as somebody reads
// them.
type leadSeries struct {
	Items []struct {
		Series  string         `json:"series"`
		States  map[string]int `json:"states"`
		Waiting int            `json:"waiting"`
		Ruled   int            `json:"ruled"`
	} `json:"items"`
}

const leadSeriesAt = "/v1/products/mine/lead-series"

// The counts by series are internal however they are narrowed. An internal
// reader reads them; anybody else is refused, and the refusal names neither a
// series nor a number.
func TestLeadCountsBySeriesAreReadOnlyUnderInternalRead(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		for _, who := range []string{"internal-reader", "internal-triager", "internal-reviewer"} {
			var got leadSeries
			httpapitest.Read(t, r, who, leadSeriesAt, &got)
			if len(got.Items) != 1 || got.Items[0].Series != "clang-tidy/default" || got.Items[0].States["baseline"] != 1 {
				t.Errorf("%s read %+v; want the seeded series and its one baseline lead", who, got.Items)
			}
		}
		// Reading the product at every other visibility, triaging it or
		// administering the deployment is not reading internal material, and
		// is refused as such. Somebody who reads nothing in the product is not
		// told it exists.
		for who, want := range map[string]int{
			"reader": http.StatusForbidden, "private": http.StatusForbidden,
			"embargo-reader": http.StatusForbidden, "private-triage": http.StatusForbidden,
			"admin-reader": http.StatusForbidden, "admin": http.StatusForbidden,
			"approver": http.StatusNotFound, "outsider": http.StatusNotFound,
		} {
			got := httpapitest.AsPerson(t, r, who, http.MethodGet, leadSeriesAt, "")
			httpapitest.RefusedWith(t, got, want)
			if body := got.Body.String(); strings.Contains(body, "clang-tidy") || strings.Contains(body, "baseline") {
				t.Errorf("%s was refused with what the counts hold: %s", who, body)
			}
		}
	})
}

// Every figure opens the list it counts: for each series and each state, the
// count is the total the lead list answers asked for that series and state.
func TestEachSeriesCountIsTheTotalOfTheListItNames(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		httpapitest.ApplyRunIn(t, r, "semgrep/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.OtherToolRun("semgrep", "sqli", "89", "src/c.c", 3, 7))

		// One lead of each series moved out of the baseline: the seeded one
		// dismissed with a second person's agreement, one of the other
		// series' pulled into the queue.
		decided := decideLead(t, r, place,
			`{"outcome":"dismissed","reason":"used_in_tests","reasoning":"only the test harness calls it"}`)
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", decided.ClaimID), `{}`); got.Code != http.StatusOK {
			t.Fatalf("the approval answered %d: %s", got.Code, got.Body)
		}
		other := leadsOf(t, r, "internal-reader", "?series=SEMGREP/default&state=baseline")
		if len(other.Items) != 2 {
			t.Fatalf("the other series' baseline is %+v; want its two leads", other.Items)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/products/mine/leads/"+other.Items[0].Place+"/escalation", `{}`); got.Code >= 300 {
			t.Fatalf("pulling a lead in answered %d: %s", got.Code, got.Body)
		}

		var counted leadSeries
		httpapitest.Read(t, r, "internal-reader", leadSeriesAt, &counted)
		want := map[string]map[string]int{
			"clang-tidy/default": {"dismissed": 1},
			"semgrep/default":    {"baseline": 1, "open": 1},
		}
		if len(counted.Items) != len(want) {
			t.Fatalf("the counts are %+v; want one entry per series", counted.Items)
		}
		for _, each := range counted.Items {
			for state, n := range each.States {
				if n != want[each.Series][state] {
					t.Errorf("%s holds %d %s; want %d", each.Series, n, state, want[each.Series][state])
				}
				listed := leadsOf(t, r, "internal-reader",
					"?"+url.Values{"series": {each.Series}, "state": {state}}.Encode())
				if listed.Total != n {
					t.Errorf("%s counts %d %s and its list holds %d", each.Series, n, state, listed.Total)
				}
			}
		}
		// A name no series holds lists nothing, where the product's leads
		// stand in the state asked for.
		if got := leadsOf(t, r, "internal-reader", "?series=nobody&state=baseline"); got.Total != 0 || len(got.Items) != 0 {
			t.Errorf("a series nobody holds lists %+v", got)
		}
	})
}

// leadFile is the lead queue's file as somebody downloads it, its rows read
// with the strict field count a conformant reader applies.
func leadFile(t *testing.T, r *httpapitest.Reach, who, query string) (int, [][]string, string) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/products/mine/leads.csv"+query, "")
	if got.Code != http.StatusOK {
		return got.Code, nil, got.Body.String()
	}
	body := got.Body.String()
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("the file is not CSV a strict reader reads: %v\n%s", err, body)
	}
	var rows [][]string
	header := false
	for _, record := range records {
		if !header {
			header = record[0] == "rule"
			continue
		}
		if !strings.HasPrefix(record[0], "#") {
			rows = append(rows, record)
		}
	}
	if !header {
		t.Fatalf("the file names no columns:\n%s", body)
	}
	return got.Code, rows, body
}

// The lead queue's file holds what the list holds for the same reader and
// nothing the list withholds: a moved lead is a row with no message to an
// internal reader not on its case, and no row carries source text.
func TestTheLeadFileHoldsWhatTheListHoldsAndWithholdsWhatItWithholds(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, _ := httpapitest.HandedOffLead(t, r, true)
		const message, snippet = "p is leaked", "return;"

		_, rows, body := leadFile(t, r, "internal-reader", "?state=handed-off")
		if len(rows) != 1 || rows[0][0] != "clang-tidy/leak" || rows[0][4] != "" || rows[0][5] != "true" ||
			rows[0][11] != place {
			t.Fatalf("an internal reader's file holds %q; want the moved lead, withheld", rows)
		}
		if strings.Contains(body, message) || strings.Contains(body, snippet) {
			t.Errorf("an internal reader's file carries what the lead page withholds:\n%s", body)
		}

		// A reader of undisclosed work is on the flaw's side of the move and
		// reads the lead whole, as the list answers them; the snippet is the
		// evidence's alone.
		_, rows, body = leadFile(t, r, "private", "?state=handed-off")
		if len(rows) != 1 || rows[0][4] != message || rows[0][5] != "false" {
			t.Errorf("a reader of undisclosed work's file holds %q; want the moved lead whole", rows)
		}
		if strings.Contains(body, snippet) {
			t.Errorf("the file carries source text:\n%s", body)
		}

		// Somebody reading disclosed work alone is listed nothing, and the
		// file says the same.
		if got := leadsOf(t, r, "reader", "?state=handed-off"); len(got.Items) != 0 {
			t.Errorf("a reader of disclosed work lists %+v", got.Items)
		}
		if _, rows, body := leadFile(t, r, "reader", "?state=handed-off"); len(rows) != 0 ||
			strings.Contains(body, "clang-tidy/leak") {
			t.Errorf("a reader of disclosed work's file holds %q:\n%s", rows, body)
		}
		// Somebody who may not read the product is refused before a byte of
		// the file is written.
		if code, _, body := leadFile(t, r, "outsider", ""); code != http.StatusNotFound || strings.Contains(body, "clang-tidy") {
			t.Errorf("an outsider was answered %d: %s", code, body)
		}
	})
}

// The file with no state named is the queue, and says so above its rows.
func TestTheLeadFileWithNoStateIsTheQueueAndSaysSo(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		_, rows, body := leadFile(t, r, "internal-reader", "")
		if len(rows) != 0 || !strings.Contains(body, "the queue") {
			t.Fatalf("the file of a queue holding only the baseline holds %q:\n%s", rows, body)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/products/mine/leads/"+place+"/escalation", `{}`); got.Code >= 300 {
			t.Fatalf("pulling the lead in answered %d: %s", got.Code, got.Body)
		}
		if _, rows, _ := leadFile(t, r, "internal-reader", ""); len(rows) != 1 || rows[0][11] != place ||
			rows[0][6] != "open" || rows[0][2] != "12" {
			t.Errorf("the queue's file holds %q; want the lead pulled in, open at line 12", rows)
		}
	})
}

// exceptionReport is the record asked what the exception report asks it:
// every outcome that always needs a second person, standing on one.
const exceptionReport = "/v1/audit/claims?alone=true&outcome=not-applicable&outcome=mismatched" +
	"&outcome=wont-fix&outcome=already-fixed&outcome=dismissed&outcome=not-security"

// The exception report covers every kind. A lead dismissed with no second
// person agreeing is in it for a reader of internal material, and in it for
// nobody else, the count included.
func TestTheExceptionReportListsALeadDismissalNobodyAgreedToOnlyToInternalReaders(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		decided := decideLead(t, r, place,
			`{"outcome":"not-security","reasoning":"a crash in a tool that exits"}`)
		type record struct {
			Items []struct {
				Claim   int64  `json:"claim"`
				Outcome string `json:"outcome"`
			} `json:"items"`
			Total int `json:"total"`
		}
		var got record
		httpapitest.Read(t, r, "internal-reader", exceptionReport, &got)
		if got.Total != 1 || len(got.Items) != 1 || got.Items[0].Claim != decided.ClaimID {
			t.Fatalf("an internal reader's exception report is %+v; want the lead's claim alone", got)
		}
		for _, who := range []string{"private", "reader", "embargo-reader"} {
			var other record
			httpapitest.Read(t, r, who, exceptionReport, &other)
			if other.Total != 0 || len(other.Items) != 0 {
				t.Errorf("%s's exception report is %+v; want nothing of a lead", who, other)
			}
		}
		// Agreed to by a second person, it leaves.
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", decided.ClaimID), `{}`); got.Code != http.StatusOK {
			t.Fatalf("the approval answered %d: %s", got.Code, got.Body)
		}
		httpapitest.Read(t, r, "internal-reader", exceptionReport, &got)
		if got.Total != 0 {
			t.Errorf("a lead's dismissal two people made is still in the exception report: %+v", got)
		}
	})
}
