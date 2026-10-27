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
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// codeFindingSeries is a product's code finding counts by analyzer series as somebody reads
// them.
type codeFindingSeries struct {
	Items []struct {
		Series  string         `json:"series"`
		States  map[string]int `json:"states"`
		Waiting int            `json:"waiting"`
		Ruled   int            `json:"ruled"`
	} `json:"items"`
}

const codeFindingSeriesAt = "/v1/products/mine/code-finding-series"

// The counts by series are internal however they are narrowed. An internal
// reader reads them; anybody else is refused, and the refusal names neither a
// series nor a number.
func TestCodeFindingCountsBySeriesAreReadOnlyUnderInternalRead(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		for _, who := range []string{"internal-reader", "internal-triager", "internal-reviewer"} {
			var got codeFindingSeries
			httpapitest.Read(t, r, who, codeFindingSeriesAt, &got)
			if len(got.Items) != 1 || got.Items[0].Series != "clang-tidy/default" || got.Items[0].States["open"] != 1 {
				t.Errorf("%s read %+v; want the seeded series and its one open code finding", who, got.Items)
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
			got := httpapitest.AsPerson(t, r, who, http.MethodGet, codeFindingSeriesAt, "")
			httpapitest.RefusedWith(t, got, want)
			if body := got.Body.String(); strings.Contains(body, "clang-tidy") || strings.Contains(body, "no-longer-detected") {
				t.Errorf("%s was refused with what the counts hold: %s", who, body)
			}
		}
	})
}

// Every figure opens the list it counts: for each series and each state, the
// count is the total the code finding list answers asked for that series and state.
func TestEachSeriesCountIsTheTotalOfTheListItNames(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		httpapitest.ApplyRunIn(t, r, "semgrep/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.OtherToolRun("semgrep", "sqli", "89", "src/c.c", 3, 7))

		// The seeded code finding is dismissed with a second person's agreement, and
		// the other series' two stay open.
		decided := decideCodeFinding(t, r, occurrence,
			`{"outcome":"dismissed","reason":"used_in_tests","reasoning":"only the test harness calls it"}`)
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`); got.Code != http.StatusOK {
			t.Fatalf("the approval answered %d: %s", got.Code, got.Body)
		}
		if other := codeFindingsOf(t, r, "internal-reader", "?series=SEMGREP/default"); len(other.Items) != 2 {
			t.Fatalf("the other series' queue is %+v; want its two code findings", other.Items)
		}

		var counted codeFindingSeries
		httpapitest.Read(t, r, "internal-reader", codeFindingSeriesAt, &counted)
		want := map[string]map[string]int{
			"clang-tidy/default": {"dismissed": 1},
			"semgrep/default":    {"open": 2},
		}
		if len(counted.Items) != len(want) {
			t.Fatalf("the counts are %+v; want one entry per series", counted.Items)
		}
		for _, each := range counted.Items {
			for state, n := range each.States {
				if n != want[each.Series][state] {
					t.Errorf("%s holds %d %s; want %d", each.Series, n, state, want[each.Series][state])
				}
				listed := codeFindingsOf(t, r, "internal-reader",
					"?"+url.Values{"series": {each.Series}, "state": {state}}.Encode())
				if listed.Total != n {
					t.Errorf("%s counts %d %s and its list holds %d", each.Series, n, state, listed.Total)
				}
			}
		}
		// A name no series holds lists nothing, where the product's code findings
		// stand in the state asked for.
		if got := codeFindingsOf(t, r, "internal-reader", "?series=nobody&state=open"); got.Total != 0 || len(got.Items) != 0 {
			t.Errorf("a series nobody holds lists %+v", got)
		}
	})
}

// codeFindingFile is the code finding queue's file as somebody downloads it, its rows read
// with the strict field count a conformant reader applies.
func codeFindingFile(t *testing.T, r *httpapitest.Reach, who, query string) (int, [][]string, string) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/products/mine/code-findings.csv"+query, "")
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

// The code finding queue's file holds what the list holds for the same reader: a code finding
// included in its flaw's case is whole to its internal readers and to the
// flaw's readers, and no row carries source text.
func TestTheCodeFindingFileHoldsWhatTheListHolds(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, true)
		const message, snippet = "p is leaked", "return;"

		_, rows, body := codeFindingFile(t, r, "internal-reader", "?state=recorded-as-flaw")
		if len(rows) != 1 || rows[0][0] != "clang-tidy/leak" || rows[0][4] != message || rows[0][13] != occurrence {
			t.Fatalf("an internal reader's file holds %q; want the included code finding whole", rows)
		}
		if strings.Contains(body, snippet) {
			t.Errorf("the file carries source text:\n%s", body)
		}

		// A reader of undisclosed work reads the code finding whole once it is
		// included, as the list answers them; the snippet is the evidence's
		// alone.
		_, rows, body = codeFindingFile(t, r, "private", "?state=recorded-as-flaw")
		if len(rows) != 1 || rows[0][4] != message {
			t.Errorf("a reader of undisclosed work's file holds %q; want the included code finding whole", rows)
		}
		if strings.Contains(body, snippet) {
			t.Errorf("the file carries source text:\n%s", body)
		}

		// Somebody reading disclosed work alone is listed nothing, and the
		// file says the same.
		if got := codeFindingsOf(t, r, "reader", "?state=recorded-as-flaw"); len(got.Items) != 0 {
			t.Errorf("a reader of disclosed work lists %+v", got.Items)
		}
		if _, rows, body := codeFindingFile(t, r, "reader", "?state=recorded-as-flaw"); len(rows) != 0 ||
			strings.Contains(body, "clang-tidy/leak") {
			t.Errorf("a reader of disclosed work's file holds %q:\n%s", rows, body)
		}
		// Somebody who may not read the product is refused before a byte of
		// the file is written.
		if code, _, body := codeFindingFile(t, r, "outsider", ""); code != http.StatusNotFound || strings.Contains(body, "clang-tidy") {
			t.Errorf("an outsider was answered %d: %s", code, body)
		}
	})
}

// The file with no state named is the queue, and says so above its rows.
func TestTheCodeFindingFileWithNoStateIsTheQueueAndSaysSo(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		_, rows, body := codeFindingFile(t, r, "internal-reader", "")
		if !strings.Contains(body, "the queue") {
			t.Errorf("the file with no state does not say it is the queue:\n%s", body)
		}
		if len(rows) != 1 || rows[0][13] != occurrence || rows[0][5] != "open" || rows[0][2] != "12" {
			t.Errorf("the queue's file holds %q; want the seeded code finding, open at line 12", rows)
		}
		// Whoever holds a code finding is a column of the file, as the list names them.
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence+"/assignment",
			`{"person":"internal-triager"}`); got.Code >= 300 {
			t.Fatalf("taking the code finding answered %d: %s", got.Code, got.Body)
		}
		if _, rows, _ := codeFindingFile(t, r, "internal-reader", ""); len(rows) != 1 || rows[0][10] != "internal-triager" {
			t.Errorf("the queue's file holds %q; want the code finding held by the internal triager", rows)
		}
	})
}

// exceptionReport is the record asked what the exception report asks it:
// every outcome that always needs a second person, standing on one.
const exceptionReport = "/v1/audit/decisions?alone=true&outcome=not-applicable&outcome=mismatched" +
	"&outcome=wont-fix&outcome=already-fixed&outcome=dismissed&outcome=not-security"

// The exception report covers every kind. A code finding dismissed with no second
// person agreeing is in it for a reader of internal material, and in it for
// nobody else, the count included.
func TestTheExceptionReportListsACodeFindingDismissalNobodyAgreedToOnlyToInternalReaders(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decided := decideCodeFinding(t, r, occurrence,
			`{"outcome":"not-security","reasoning":"a crash in a tool that exits"}`)
		type record struct {
			Items []struct {
				Decision int64  `json:"decision"`
				Outcome  string `json:"outcome"`
			} `json:"items"`
			Total int `json:"total"`
		}
		var got record
		httpapitest.Read(t, r, "internal-reader", exceptionReport, &got)
		if got.Total != 1 || len(got.Items) != 1 || got.Items[0].Decision != decided.DecisionID {
			t.Fatalf("an internal reader's exception report is %+v; want the code finding's decision alone", got)
		}
		for _, who := range []string{"private", "reader", "embargo-reader"} {
			var other record
			httpapitest.Read(t, r, who, exceptionReport, &other)
			if other.Total != 0 || len(other.Items) != 0 {
				t.Errorf("%s's exception report is %+v; want nothing of a code finding", who, other)
			}
		}
		// Agreed to by a second person, it leaves.
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`); got.Code != http.StatusOK {
			t.Fatalf("the approval answered %d: %s", got.Code, got.Body)
		}
		httpapitest.Read(t, r, "internal-reader", exceptionReport, &got)
		if got.Total != 0 {
			t.Errorf("a code finding's dismissal two people made is still in the exception report: %+v", got)
		}
	})
}

func TestACodeFindingDismissalStandingWithNobodyAgreeingIsCountedWhateverItsFlagSays(t *testing.T) {
	for name, outcome := range map[string]string{
		"dismissed":    `{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`,
		"not security": `{"outcome":"not-security","reasoning":"a crash in a tool that exits"}`,
	} {
		t.Run(name, func(t *testing.T) {
			httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
				decided := decideCodeFinding(t, r, httpapitest.SeededCodeFinding(t, r), outcome)
				// Standing, and cleared of the gate's flag, which is the write
				// path got around.
				if _, err := r.DB.DB.NewUpdate().Table("decision_occurrence").
					Set(`"state" = ?`, triage.Approved).Set(`"needs_approval" = ?`, false).
					Where(`"decision_id" = ?`, decided.DecisionID).Exec(t.Context()); err != nil {
					t.Fatal(err)
				}
				decisions, rows, err := triage.NewStore(r.DB.DB).HiddenWithNobodyAgreeing(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if decisions != 1 || rows != 1 {
					t.Errorf("%s standing alone with no flag counts %d decisions over %d rows; want one of each",
						name, decisions, rows)
				}
			})
		})
	}
}
