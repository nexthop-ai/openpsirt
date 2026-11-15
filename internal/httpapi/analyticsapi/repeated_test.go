// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// An occurrence put off twice is listed with how many times, how long the
// deferrals held it in whole days to the nearest, and the furthest date any
// reached, in the list and in the file alike.
func TestAnOccurrencePutOffTwiceIsListedWithHowLongItWasHeld(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		occurrence := r.Scanned(t)
		path := fmt.Sprintf("/v1/products/mine/branches-and-tags/master/variants/broadcom"+
			"/findings/CVE-2026-9999/occurrences/%s/decision", occurrence)
		deferred := func() int64 {
			t.Helper()
			got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, path,
				`{"outcome":"deferred","deferred_until":"`+httpapitest.AheadOfUs+`",`+
					`"reasoning":"Waiting on the vendor's fix."}`)
			if got.Code != http.StatusCreated {
				t.Fatalf("deferring answered %d: %s", got.Code, got.Body.String())
			}
			var made struct {
				DecisionID int64 `json:"decision_id"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
				t.Fatal(err)
			}
			return made.DecisionID
		}

		// The first held four days and was taken back; the second was
		// proposed 3.6 days before the date it runs to, so the occurrence was put
		// off 7.6 days, which is 8 to the nearest day and 7 truncated. A
		// date is stored as a day, so the stretches are moved rather than it.
		now := time.Now().UTC().Truncate(time.Second)
		lastUntil, err := time.Parse(time.DateOnly, httpapitest.AheadOfUs)
		if err != nil {
			t.Fatal(err)
		}
		first := deferred()
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodDelete,
			"/v1/decisions/"+httpapitest.Itoa(first), ""); got.Code >= 300 {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
		}
		second := deferred()
		for _, set := range []struct {
			decision       int64
			proposed, ends time.Time
		}{
			{first, now.AddDate(0, 0, -10), now.AddDate(0, 0, -6)},
			{second, lastUntil.Add(-time.Duration(3.6 * 24 * float64(time.Hour))), time.Time{}},
		} {
			q := r.DB.DB.NewUpdate().Table("decision_occurrence").
				Set(`"proposed_at" = ?`, set.proposed).Where(`"decision_id" = ?`, set.decision)
			if !set.ends.IsZero() {
				q = q.Set(`"ended_at" = ?`, set.ends)
			}
			if _, err := q.Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		want := struct {
			times, days int
			until       string
		}{2, 8, lastUntil.Format(time.RFC3339)}

		var listed struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Times         int    `json:"times"`
				TotalDays     int    `json:"total_days"`
				Standing      bool   `json:"standing"`
				LastUntil     string `json:"last_until"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/deferrals/repeated", &listed)
		if len(listed.Items) != 1 {
			t.Fatalf("%d occurrences are listed as put off repeatedly, want 1: %+v",
				len(listed.Items), listed.Items)
		}
		one := listed.Items[0]
		if one.Vulnerability != "CVE-2026-9999" || one.Times != want.times ||
			one.TotalDays != want.days || one.LastUntil != want.until || !one.Standing {
			t.Errorf("the list says %+v, want %+v and standing", one, want)
		}

		file := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/deferrals/repeated.csv", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := httpapitest.RowsUnder(lines)
		if len(body) != 2 {
			t.Fatalf("the file holds %d rows, want 1", len(body)-1)
		}
		cell := func(column string) string {
			at := httpapitest.IndexOf(body[0], column)
			if at < 0 {
				t.Fatalf("the file has no %s column: %v", column, body[0])
			}
			return body[1][at]
		}
		if cell("times") != "2" || cell("total_days") != "8" || cell("last_until") != want.until ||
			cell("standing") != "true" {
			t.Errorf("the file says times %s, total_days %s, last_until %s, standing %s; want %+v",
				cell("times"), cell("total_days"), cell("last_until"), cell("standing"), want)
		}
	})
}

// Repeated deferrals narrowed to a product, in the list and in the file, are
// that product's alone, and a page of the list is the page asked for with the
// total of the whole list.
func TestRepeatedDeferralsNarrowedToAProductAreThatProductsAlone(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		disclosed, _ := httpapitest.SeedTheirs(t, r)
		deferral := `{"outcome":"deferred","deferred_until":"` + httpapitest.AheadOfUs + `",` +
			`"reasoning":"Waiting on the vendor's fix."}`
		for _, at := range []string{
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/findings/CVE-2026-9999/components/libnl-3-200",
			"/v1/products/theirs/branches-and-tags/master/variants/mellanox/findings/" + disclosed + "/components/libestate",
		} {
			for range 2 {
				got := httpapitest.AsPerson(t, r, "wide-triager", http.MethodPost, at+"/decision", deferral)
				if got.Code != http.StatusCreated {
					t.Fatalf("deferring at %s answered %d: %s", at, got.Code, got.Body.String())
				}
				var made struct {
					DecisionID int64 `json:"decision_id"`
				}
				if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
					t.Fatal(err)
				}
				if got := httpapitest.AsPerson(t, r, "wide-triager", http.MethodDelete,
					"/v1/decisions/"+httpapitest.Itoa(made.DecisionID), ""); got.Code >= 300 {
					t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
				}
			}
		}

		listed := func(query string) ([]string, int) {
			var page struct {
				Items []struct {
					Product string `json:"product"`
				} `json:"items"`
				Total int `json:"total"`
			}
			httpapitest.Read(t, r, "wide-triager", "/v1/deferrals/repeated"+query, &page)
			var products []string
			for _, row := range page.Items {
				products = append(products, row.Product)
			}
			return products, page.Total
		}
		all, total := listed("")
		if len(all) != 2 || total != 2 {
			t.Fatalf("across the estate %v of %d are listed, want one in each product", all, total)
		}
		if page, total := listed("?limit=1&offset=1"); len(page) != 1 || page[0] != all[1] || total != 2 {
			t.Errorf("the second page of one is %v of %d, want %s of 2", page, total, all[1])
		}
		for _, product := range []string{"mine", "theirs"} {
			if got, total := listed("?product=" + product); len(got) != 1 || got[0] != product || total != 1 {
				t.Errorf("narrowed to %s the list is %v of %d, want its one", product, got, total)
			}
			file := httpapitest.AsPerson(t, r, "wide-triager", http.MethodGet,
				"/v1/deferrals/repeated.csv?product="+product, "")
			if file.Code != http.StatusOK {
				t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
			}
			lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			body := httpapitest.RowsUnder(lines)
			at := httpapitest.IndexOf(body[0], "product")
			if at < 0 || len(body) != 2 || body[1][at] != product {
				t.Errorf("narrowed to %s the file holds %v", product, body)
			}
		}
	})
}
