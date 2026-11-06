// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// listedUnder is how many findings a list or its file holds for a query, read
// as somebody, or -1 where it is refused.
func listedUnder(t *testing.T, r *httpapitest.Reach, who, path string) (int, int) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, path, "")
	if got.Code != http.StatusOK {
		return got.Code, -1
	}
	if !strings.Contains(path, ".csv") {
		var body struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return got.Code, body.Total
	}
	read := csv.NewReader(strings.NewReader(got.Body.String()))
	read.FieldsPerRecord = -1
	records, err := read.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	header, rows := 0, 0
	for _, record := range records {
		switch {
		case len(record) > 0 && strings.HasPrefix(record[0], "#"):
		case header == 0:
			header = len(record)
		case header > 0 && len(record) == header:
			rows++
		}
	}
	if header == 0 {
		t.Fatalf("%s has no header row: %s", path, got.Body.String())
	}
	return got.Code, rows
}

func TestTheEcosystemFilterCountsOnlyWhatTheReaderMaySee(t *testing.T) {
	// One of two Debian findings undisclosed: the filter narrows what the
	// reader may see, in the list's total and in its file, in one product
	// and across them.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set(`"visibility" = ?`, "private").
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		lists := map[string]string{
			"one product":          "/v1/products/mine/findings?",
			"one product's file":   "/v1/products/mine/findings.csv?",
			"every product":        "/v1/findings?",
			"every product's file": "/v1/findings.csv?",
		}
		for _, c := range []struct {
			who, query string
			code, rows int
			across     bool
		}{
			{"private", "ecosystem=deb", http.StatusOK, 2, false},
			{"private", "component=linux-image&ecosystem=deb", http.StatusOK, 2, false},
			{"private", "component=linux-image&ecosystem=cargo", http.StatusOK, 0, false},
			{"reader", "ecosystem=deb", http.StatusOK, 1, false},
			{"reader", "component=linux-image&ecosystem=deb", http.StatusOK, 1, false},
			{"embargo-reader", "ecosystem=deb", http.StatusOK, 1, false},
			{"triager", "ecosystem=deb", http.StatusOK, 1, false},
			// Reading another product is no reading of this one.
			{"outsider", "ecosystem=deb", http.StatusOK, 0, true},
			{"outsider", "ecosystem=deb", http.StatusNotFound, -1, false},
			{"", "ecosystem=deb", http.StatusUnauthorized, -1, false},
		} {
			for name, path := range lists {
				if c.across != strings.HasPrefix(path, "/v1/findings") && c.code != http.StatusUnauthorized {
					continue
				}
				code, rows := listedUnder(t, r, c.who, path+c.query)
				if code != c.code || rows != c.rows {
					t.Errorf("%s as %q with %q answered %d with %d, want %d with %d",
						name, c.who, c.query, code, rows, c.code, c.rows)
				}
			}
		}
	})
}
