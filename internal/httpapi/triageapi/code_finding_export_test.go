// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/csv"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
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

// codeFindingRowsIn is the rows of a findings file that are code findings, each as its
// columns by name.
func codeFindingRowsIn(t *testing.T, header []string, rows [][]string) []map[string]string {
	t.Helper()
	codeFinding := slices.Index(header, "code finding")
	if codeFinding < 0 {
		t.Fatalf("the file has no code finding column: %q", header)
	}
	var out []map[string]string
	for _, row := range rows {
		if row[codeFinding] != "true" {
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

// The findings lists' files carry the open code findings of the selection, under the
// queue's visibility, to the readers who read them: a security testing reader gets the code finding,
// a reader of disclosed or undisclosed work alone gets none, and somebody who
// may not read the product is refused before a byte is written. Across
// products the code finding is written under its product.
func TestTheFindingsFileCarriesTheOpenCodeFindingsToSecurityTestingReadersAlone(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		const message, snippet = "p is leaked", "return;"
		for _, path := range []string{
			"/v1/products/mine/findings.csv",
			"/v1/products/mine/findings.csv?branch_or_tag=master&variant=broadcom",
			"/v1/findings.csv",
		} {
			for _, who := range []string{"security-testing-reader", "security-testing-triager", "code-finding-handler"} {
				_, said, header, rows := findingsFile(t, r, who, path)
				codeFindings := codeFindingRowsIn(t, header, rows)
				if len(codeFindings) != 1 {
					t.Fatalf("%s: %s's file holds the code findings %v; want the seeded code finding", path, who, codeFindings)
				}
				l := codeFindings[0]
				if l["issue"] != "clang-tidy/leak" || l["path"] != "src/a.c" || l["line"] != "12" ||
					l["message"] != message || l["branch_or_tag"] != "master" ||
					l["variant"] != "broadcom" || l["severity"] != "" || l["component"] != "" {
					t.Errorf("%s: %s's file holds the code finding as %v", path, who, l)
				}
				if strings.HasPrefix(path, "/v1/findings") && l["product"] != "mine" {
					t.Errorf("%s: the code finding is written under the product %q", path, l["product"])
				}
				if !strings.HasPrefix(said["code findings"], "every open code finding") {
					t.Errorf("%s: the file says its code findings are %q", path, said["code findings"])
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
				if codeFindings := codeFindingRowsIn(t, header, rows); len(codeFindings) != 0 {
					t.Errorf("%s: %s, who reads no security testing work, exports the code findings %v", path, who, codeFindings)
				}
			}
		}
		if code, _, _, _ := findingsFile(t, r, "outsider", "/v1/products/mine/findings.csv"); code != http.StatusNotFound {
			t.Errorf("an outsider exporting the product's findings was answered %d", code)
		}
	})
}

// A code finding carries no rating, upstream or decision, so a findings file
// narrowed by anything but its order holds none, and says so.
func TestAFindingsFileNarrowedByAFilterHoldsNoCodeFindingAndSaysSo(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		for _, asked := range []string{
			"sort=age&asc=true",
			// The address the Findings screen exports, with the defaults it
			// writes in: every code finding answers these the same way.
			"on=branch&support=in-support&planned=unplanned&sort=age",
			"below_minimum_severity=true",
		} {
			_, said, header, rows := findingsFile(t, r, "security-testing-reader", "/v1/products/mine/findings.csv?"+asked)
			if codeFindings := codeFindingRowsIn(t, header, rows); len(codeFindings) != 1 {
				t.Fatalf("%s: the file holds the code findings %v; want the seeded code finding", asked, codeFindings)
			}
			if !strings.HasPrefix(said["code findings"], "every open code finding") {
				t.Errorf("%s: the file says its code findings are %q", asked, said["code findings"])
			}
		}
		for _, asked := range []string{"severity=high", "q=leak", "exploited=true", "beneath=zlib", "on=tag", "planned=planned"} {
			code, said, header, rows := findingsFile(t, r, "security-testing-reader",
				"/v1/products/mine/findings.csv?branch_or_tag=master&variant=broadcom&"+asked)
			if code != http.StatusOK {
				t.Fatalf("%s: exporting answered %d", asked, code)
			}
			if codeFindings := codeFindingRowsIn(t, header, rows); len(codeFindings) != 0 {
				t.Errorf("%s: the narrowed file holds the code findings %v", asked, codeFindings)
			}
			if !strings.HasPrefix(said["code findings"], "none") {
				t.Errorf("%s: the narrowed file says its code findings are %q", asked, said["code findings"])
			}
		}
	})
}

// A findings file names the component a code finding is placed on and its version,
// as the code finding list does, and leaves both empty for one on the build itself.
func TestAFindingsFileNamesTheComponentACodeFindingIsPlacedOn(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		_, _, header, rows := findingsFile(t, r, "security-testing-reader", "/v1/products/mine/findings.csv")
		if codeFindings := codeFindingRowsIn(t, header, rows); len(codeFindings) != 1 ||
			codeFindings[0]["component"] != "" || codeFindings[0]["version"] != "" {
			t.Fatalf("the code finding on the build is written as %v; want no component", codeFindings)
		}
		// The seeded run names no repository, so it is moved onto zlib by hand.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"component_id" = (SELECT "id" FROM "component" WHERE "name" = ?)`, "zlib").
			Where(`"kind" = ?`, kind.Analysis).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, _, header, rows = findingsFile(t, r, "security-testing-reader", "/v1/products/mine/findings.csv")
		if codeFindings := codeFindingRowsIn(t, header, rows); len(codeFindings) != 1 ||
			codeFindings[0]["component"] != "zlib" || codeFindings[0]["version"] != "1.3" {
			t.Errorf("the code finding on zlib is written as %v; want zlib 1.3", codeFindings)
		}
	})
}

// A code finding whose dismissal waits for a second person is open, and a findings
// file holds it, as it holds a finding a decision waits on, though the queue
// leaves it out.
func TestAFindingsFileHoldsAnOpenCodeFindingADecisionWaitsOn(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decideCodeFinding(t, r, occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"checked a line above"}`)
		if queue := codeFindingsOf(t, r, "security-testing-reader", ""); queue.Total != 0 || queue.Waiting != 1 {
			t.Fatalf("the queue is %+v; want the code finding left out as waiting, or this checks nothing", queue)
		}
		_, _, header, rows := findingsFile(t, r, "security-testing-reader", "/v1/products/mine/findings.csv")
		if codeFindings := codeFindingRowsIn(t, header, rows); len(codeFindings) != 1 || codeFindings[0]["issue"] != "clang-tidy/leak" {
			t.Errorf("the findings file holds the code findings %v; want the code finding a decision waits on", codeFindings)
		}
	})
}

// A code finding in the queue reaches none of the vulnerability figures: a product's
// overview counts nothing open for a reader of security testing work alone. The VEX
// document's exclusion is pinned beside the other vulnerability consumers,
// because no outcome a code finding takes is one the document states.
func TestACodeFindingInTheQueueReachesNoFigure(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		if got := codeFindingsOf(t, r, "security-testing-reader", ""); got.Total != 1 {
			t.Fatalf("the queue holds %d code findings; want the seeded code finding, or this checks nothing", got.Total)
		}
		var overview struct {
			Open      int `json:"open"`
			Undecided int `json:"undecided"`
			Builds    []struct {
				Open int `json:"open"`
			} `json:"builds"`
		}
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/overview", &overview)
		if overview.Open != 0 || overview.Undecided != 0 {
			t.Errorf("the overview counts %d open and %d undecided for a reader of security testing work alone",
				overview.Open, overview.Undecided)
		}
		for _, b := range overview.Builds {
			if b.Open != 0 {
				t.Errorf("a build counts %d open for a reader of security testing work alone", b.Open)
			}
		}
	})
}
