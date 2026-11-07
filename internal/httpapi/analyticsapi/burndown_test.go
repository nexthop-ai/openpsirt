// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// burndownRoutes are the chart and its file: one count read twice, refused
// alike.
var burndownRoutes = []string{"/v1/burndown", "/v1/burndown.csv"}

// leftNow is what a burndown says is left today, read as somebody.
func leftNow(t *testing.T, r *httpapitest.Reach, who, query string) (int, int) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/burndown?"+query, "")
	if got.Code != http.StatusOK {
		return got.Code, -1
	}
	var body struct {
		Points []struct {
			Left int `json:"left"`
		} `json:"points"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Points) == 0 {
		return got.Code, 0
	}
	return got.Code, body.Points[len(body.Points)-1].Left
}

// leftInFile is the same read from the file's last row.
func leftInFile(t *testing.T, r *httpapitest.Reach, who, query string) (int, int) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/burndown.csv?"+query, "")
	if got.Code != http.StatusOK {
		return got.Code, -1
	}
	lines := strings.Split(strings.TrimSpace(got.Body.String()), "\n")
	var header []string
	var last []string
	for _, line := range lines {
		cells := strings.Split(line, ",")
		if len(cells) > 1 && cells[0] == "day" {
			header = cells
			continue
		}
		if header != nil && len(cells) == len(header) {
			last = cells
		}
	}
	if header == nil {
		t.Fatalf("the file has no header row: %s", got.Body.String())
	}
	if last == nil {
		return got.Code, 0
	}
	n := 0
	for _, c := range last[httpapitest.IndexOf(header, "left")] {
		n = n*10 + int(c-'0')
	}
	return got.Code, n
}

func TestABurndownCountsOnlyWhatTheReaderMaySee(t *testing.T) {
	// One issue of two undisclosed: a count is a disclosure with the details
	// removed, on the chart and in its file alike, across products and
	// within one.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set(`"visibility" = ?`, "private").
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			who, query string
			code, left int
		}{
			{"private", "product=mine", http.StatusOK, 2},
			{"private", "", http.StatusOK, 2},
			{"reader", "product=mine", http.StatusOK, 1},
			{"reader", "", http.StatusOK, 1},
			{"embargo-reader", "product=mine", http.StatusOK, 1},
			{"triager", "", http.StatusOK, 1},
			// Reading another product is no reading of this one.
			{"outsider", "", http.StatusOK, 0},
			{"outsider", "product=mine", http.StatusNotFound, -1},
			{"approver", "product=mine", http.StatusNotFound, -1},
			{"", "", http.StatusUnauthorized, -1},
		} {
			for name, read := range map[string]func(*testing.T, *httpapitest.Reach, string, string) (int, int){
				"chart": leftNow, "file": leftInFile,
			} {
				code, left := read(t, r, c.who, c.query)
				if code != c.code || left != c.left {
					t.Errorf("%s as %q with %q answered %d with %d left, want %d with %d",
						name, c.who, c.query, code, left, c.code, c.left)
				}
			}
		}
		// The severity narrows the same count.
		if _, left := leftNow(t, r, "private", "product=mine&severity=high"); left != 1 {
			t.Errorf("high and worse left %d, want the one high issue", left)
		}
	})
}

func TestABurndownChoosesByPackageIdentifierAndNamesWhatItChose(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		var body struct {
			Chosen []struct {
				Package   string `json:"package"`
				Ecosystem string `json:"ecosystem"`
			} `json:"chosen"`
			Points []struct {
				Left int `json:"left"`
			} `json:"points"`
		}
		httpapitest.Read(t, r, "private", "/v1/burndown?product=mine&purl=pkg:deb/debian/", &body)
		if len(body.Chosen) != 1 || body.Chosen[0].Package != "pkg:deb/debian/linux-image" ||
			body.Chosen[0].Ecosystem != "deb" {
			t.Errorf("chose %+v, want the kernel's package in deb", body.Chosen)
		}
		if _, left := leftNow(t, r, "private", "product=mine&purl=pkg:deb/debian/linux"); left != 0 {
			t.Errorf("a prefix ending inside a name chose %d, want none: it matches whole segments", left)
		}
	})
}

func TestABurndownIsRefusedWhatItCannotAnswer(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, route := range burndownRoutes {
			for query, says := range map[string]string{
				"purl=sonic-swss":       "package identifier prefix",
				"since=2999-01-01":      "today or earlier",
				"beneath=libswsscommon": "needs a product",
				"severity=urgent":       "",
				"since=2026-02-30":      "",
			} {
				got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, route+"?"+query, "")
				if got.Code != http.StatusUnprocessableEntity || !strings.Contains(got.Body.String(), says) {
					t.Errorf("%s with %s answered %d, want 422 saying %q: %s",
						route, query, got.Code, says, got.Body.String())
				}
			}
		}
	})
}

func TestABurndownFileStatesTheDayZeroItUsedAndWhatWasLeftThen(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		// Opened ten days back, so a day 0 three days back starts with both
		// left and the file's start line pins a count.
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set(`"opened_at" = ?`, time.Now().UTC().AddDate(0, 0, -10)).
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		var body struct {
			Since string `json:"since"`
			Start int    `json:"start"`
		}
		httpapitest.Read(t, r, "private", "/v1/burndown?product=mine&since=2020-01-01", &body)
		got := httpapitest.AsPerson(t, r, "private", http.MethodGet, "/v1/burndown.csv?product=mine&since=2020-01-01", "")
		if !strings.Contains(got.Body.String(), body.Since+", moved from 2020-01-01") {
			t.Errorf("the file does not say its day 0 moved:\n%s", got.Body.String())
		}
		since := time.Now().UTC().AddDate(0, 0, -3).Format(time.DateOnly)
		httpapitest.Read(t, r, "private", "/v1/burndown?product=mine&since="+since, &body)
		if body.Start == 0 {
			t.Fatal("nothing was left at day 0's start, so the line pins nothing")
		}
		got = httpapitest.AsPerson(t, r, "private", http.MethodGet, "/v1/burndown.csv?product=mine&since="+since, "")
		if says := "left at day 0's start," + strconv.Itoa(body.Start); !strings.Contains(got.Body.String(), says) {
			t.Errorf("the file does not say %q:\n%s", says, got.Body.String())
		}
		got = httpapitest.AsPerson(t, r, "private", http.MethodGet, "/v1/burndown.csv?product=mine", "")
		if !strings.Contains(got.Body.String(), ", the day the earliest finding opened") {
			t.Errorf("a file with no day 0 asked names none:\n%s", got.Body.String())
		}
	})
}
