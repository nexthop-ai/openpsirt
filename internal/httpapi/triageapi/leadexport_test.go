// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/csv"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// findingsFile is a findings export as somebody downloads it: its stated
// facts by label, its columns, and its rows, read with the strict field count
// a conformant reader applies.
func findingsFile(t *testing.T, r *httpapitest.Reach, who, path string) (int, map[string]string, []string, [][]string) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, path, "")
	if got.Code != http.StatusOK {
		return got.Code, nil, nil, nil
	}
	records, err := csv.NewReader(strings.NewReader(got.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("the file is not CSV a strict reader reads: %v\n%s", err, got.Body)
	}
	said := map[string]string{}
	var header []string
	var rows [][]string
	for _, record := range records {
		switch {
		case strings.HasPrefix(record[0], "# "):
			said[strings.TrimPrefix(record[0], "# ")] = record[1]
		case header == nil:
			header = record
		default:
			rows = append(rows, record)
		}
	}
	if header == nil {
		t.Fatalf("the file names no columns:\n%s", got.Body)
	}
	return got.Code, said, header, rows
}

// leadRowsIn is the rows of a findings file that are leads, each as its
// columns by name.
func leadRowsIn(t *testing.T, header []string, rows [][]string) []map[string]string {
	t.Helper()
	lead := slices.Index(header, "lead")
	if lead < 0 {
		t.Fatalf("the file has no lead column: %q", header)
	}
	var out []map[string]string
	for _, row := range rows {
		if row[lead] != "true" {
			continue
		}
		named := map[string]string{}
		for i, column := range header {
			named[column] = row[i]
		}
		out = append(out, named)
	}
	return out
}

// The findings lists' files carry the open leads of the selection, under the
// queue's visibility, to the readers who read them: an internal reader gets the lead,
// a reader of disclosed or undisclosed work alone gets none, and somebody who
// may not read the product is refused before a byte is written. Across
// products the lead is written under its product.
func TestTheFindingsFileCarriesTheOpenLeadsToInternalReadersAlone(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		const message, snippet = "p is leaked", "return;"
		for _, path := range []string{
			"/v1/products/mine/findings.csv",
			"/v1/products/mine/findings.csv?stream=master&variant=broadcom",
			"/v1/findings.csv",
		} {
			for _, who := range []string{"internal-reader", "internal-triager", "lead-handler"} {
				_, said, header, rows := findingsFile(t, r, who, path)
				leads := leadRowsIn(t, header, rows)
				if len(leads) != 1 {
					t.Fatalf("%s: %s's file holds the leads %v; want the seeded lead", path, who, leads)
				}
				l := leads[0]
				if l["issue"] != "clang-tidy/leak" || l["path"] != "src/a.c" || l["line"] != "12" ||
					l["message"] != message || l["stream"] != "master" ||
					l["variant"] != "broadcom" || l["severity"] != "" || l["component"] != "" {
					t.Errorf("%s: %s's file holds the lead as %v", path, who, l)
				}
				if strings.HasPrefix(path, "/v1/findings") && l["product"] != "mine" {
					t.Errorf("%s: the lead is written under the product %q", path, l["product"])
				}
				if !strings.HasPrefix(said["leads"], "every open lead") {
					t.Errorf("%s: the file says its leads are %q", path, said["leads"])
				}
				for _, row := range rows {
					if slices.Contains(row, snippet) {
						t.Errorf("%s: %s's file carries source text: %q", path, who, row)
					}
				}
			}
			for _, who := range []string{"reader", "private", "triager", "private-triage"} {
				code, _, header, rows := findingsFile(t, r, who, path)
				if code != http.StatusOK {
					t.Fatalf("%s: %s exporting answered %d", path, who, code)
				}
				if leads := leadRowsIn(t, header, rows); len(leads) != 0 {
					t.Errorf("%s: %s, who reads no internal work, exports the leads %v", path, who, leads)
				}
			}
		}
		if code, _, _, _ := findingsFile(t, r, "outsider", "/v1/products/mine/findings.csv"); code != http.StatusNotFound {
			t.Errorf("an outsider exporting the product's findings was answered %d", code)
		}
	})
}

// A lead carries no rating, component or decision, so a findings file
// narrowed by anything but its order holds none, and says so.
func TestAFindingsFileNarrowedByAFilterHoldsNoLeadAndSaysSo(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		for _, asked := range []string{
			"sort=age&asc=true",
			// The address the Findings screen exports, with the defaults it
			// writes in: every lead answers these the same way.
			"on=branch&support=in-support&planned=unplanned&sort=age",
			"below_minimum_severity=true",
		} {
			_, said, header, rows := findingsFile(t, r, "internal-reader", "/v1/products/mine/findings.csv?"+asked)
			if leads := leadRowsIn(t, header, rows); len(leads) != 1 {
				t.Fatalf("%s: the file holds the leads %v; want the seeded lead", asked, leads)
			}
			if !strings.HasPrefix(said["leads"], "every open lead") {
				t.Errorf("%s: the file says its leads are %q", asked, said["leads"])
			}
		}
		for _, asked := range []string{"severity=high", "q=leak", "exploited=true", "beneath=zlib", "on=tag", "planned=planned"} {
			code, said, header, rows := findingsFile(t, r, "internal-reader",
				"/v1/products/mine/findings.csv?stream=master&variant=broadcom&"+asked)
			if code != http.StatusOK {
				t.Fatalf("%s: exporting answered %d", asked, code)
			}
			if leads := leadRowsIn(t, header, rows); len(leads) != 0 {
				t.Errorf("%s: the narrowed file holds the leads %v", asked, leads)
			}
			if !strings.HasPrefix(said["leads"], "none") {
				t.Errorf("%s: the narrowed file says its leads are %q", asked, said["leads"])
			}
		}
	})
}

// A lead whose dismissal waits for a second person is open, and a findings
// file holds it, as it holds a finding a decision waits on, though the queue
// leaves it out.
func TestAFindingsFileHoldsAnOpenLeadADecisionWaitsOn(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededLead(t, r)
		decideLead(t, r, occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"checked a line above"}`)
		if queue := leadsOf(t, r, "internal-reader", ""); queue.Total != 0 || queue.Waiting != 1 {
			t.Fatalf("the queue is %+v; want the lead left out as waiting, or this checks nothing", queue)
		}
		_, _, header, rows := findingsFile(t, r, "internal-reader", "/v1/products/mine/findings.csv")
		if leads := leadRowsIn(t, header, rows); len(leads) != 1 || leads[0]["issue"] != "clang-tidy/leak" {
			t.Errorf("the findings file holds the leads %v; want the lead a decision waits on", leads)
		}
	})
}

// A lead in the queue reaches none of the vulnerability figures: a product's
// overview counts nothing open for a reader of internal work alone. The VEX
// document's exclusion is pinned beside the other vulnerability consumers,
// because no outcome a lead takes is one the document states.
func TestALeadInTheQueueReachesNoFigure(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		if got := leadsOf(t, r, "internal-reader", ""); got.Total != 1 {
			t.Fatalf("the queue holds %d leads; want the seeded lead, or this checks nothing", got.Total)
		}
		var overview struct {
			Open      int `json:"open"`
			Undecided int `json:"undecided"`
			Builds    []struct {
				Open int `json:"open"`
			} `json:"builds"`
		}
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/overview", &overview)
		if overview.Open != 0 || overview.Undecided != 0 {
			t.Errorf("the overview counts %d open and %d undecided for a reader of internal work alone",
				overview.Open, overview.Undecided)
		}
		for _, b := range overview.Builds {
			if b.Open != 0 {
				t.Errorf("a build counts %d open for a reader of internal work alone", b.Open)
			}
		}
	})
}
