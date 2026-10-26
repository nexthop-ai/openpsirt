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

// The findings lists' files carry the leads of the selection, as the queue
// lists them, to the readers who read them: an internal reader gets the lead,
// a reader of disclosed or undisclosed work alone gets none, and somebody who
// may not read the product is refused before a byte is written. Across
// products the lead is written under its product.
func TestTheFindingsFileCarriesTheQueueToInternalReadersAlone(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/products/mine/leads/"+place+"/escalation", `{}`); got.Code >= 300 {
			t.Fatalf("pulling the lead in answered %d: %s", got.Code, got.Body)
		}
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
					t.Fatalf("%s: %s's file holds the leads %v; want the one in the queue", path, who, leads)
				}
				l := leads[0]
				if l["issue"] != "clang-tidy/leak" || l["path"] != "src/a.c" || l["line"] != "12" ||
					l["message"] != message || l["withheld"] != "false" || l["stream"] != "master" ||
					l["variant"] != "broadcom" || l["severity"] != "" || l["component"] != "" {
					t.Errorf("%s: %s's file holds the lead as %v", path, who, l)
				}
				if strings.HasPrefix(path, "/v1/findings") && l["product"] != "mine" {
					t.Errorf("%s: the lead is written under the product %q", path, l["product"])
				}
				if !strings.Contains(said["leads"], "the lead queue") {
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
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/products/mine/leads/"+place+"/escalation", `{}`); got.Code >= 300 {
			t.Fatalf("pulling the lead in answered %d: %s", got.Code, got.Body)
		}
		_, _, header, rows := findingsFile(t, r, "internal-reader", "/v1/products/mine/findings.csv?sort=age&asc=true")
		if leads := leadRowsIn(t, header, rows); len(leads) != 1 {
			t.Fatalf("a file asking only an order holds the leads %v; want the one in the queue", leads)
		}
		for _, asked := range []string{"severity=high", "q=leak", "exploited=true", "beneath=zlib"} {
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

// A lead in the queue reaches none of the vulnerability figures: a product's
// overview counts nothing open for a reader of internal work alone. The VEX
// document's exclusion is pinned beside the other vulnerability consumers,
// because no outcome a lead takes is one the document states.
func TestALeadInTheQueueReachesNoFigure(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/products/mine/leads/"+place+"/escalation", `{}`); got.Code >= 300 {
			t.Fatalf("pulling the lead in answered %d: %s", got.Code, got.Body)
		}
		if got := leadsOf(t, r, "internal-reader", ""); got.Total != 1 {
			t.Fatalf("the queue holds %d leads; want the one pulled in, or this checks nothing", got.Total)
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
