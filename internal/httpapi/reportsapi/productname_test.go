// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"encoding/csv"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestAListNamesAProductByTheNameThatAddressesIt pins `product` as the name a
// route resolves, with the display name beside it, on the lists whose rows
// carry a product read by a query of their own. A label in its place is a
// value a caller can show and cannot filter or link by.
func TestAListNamesAProductByTheNameThatAddressesIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)

		type row struct {
			Product     string `json:"product"`
			ProductName string `json:"product_name"`
		}
		for _, path := range []string{
			"/v1/audit", "/v1/audit/claims", "/v1/effort", "/v1/running-out?days=365",
		} {
			var list struct {
				Items []row `json:"items"`
			}
			httpapitest.Read(t, r, "triager", path, &list)
			if len(list.Items) == 0 {
				t.Errorf("%s answered nothing, so this checked nothing", path)
				continue
			}
			for _, one := range list.Items {
				if one.Product != "mine" || one.ProductName != httpapitest.ShownAs("mine") {
					t.Errorf("%s names the product as %+v, want the address with the label beside it",
						path, one)
				}
			}
		}
	})
}

// TestAFileCarriesTheLabelBesideTheName pins the label columns the files add
// beside the names their lists carry, so a spreadsheet filtered on a name
// and one read by a person are the same file.
func TestAFileCarriesTheLabelBesideTheName(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)

		for _, c := range []struct {
			who, path string
			want      map[string]string
		}{
			{"triager", "/v1/running-out.csv?days=365", map[string]string{
				"product": "mine", "product name": httpapitest.ShownAs("mine"),
				"stream": "master", "stream name": "Master",
				"variant": "broadcom", "variant name": "Broadcom",
			}},
			{"triager", "/v1/audit.csv", map[string]string{
				"product": "mine", "product name": httpapitest.ShownAs("mine"),
			}},
			{"reviewer", "/v1/review-queue.csv", map[string]string{
				"product": "mine", "product name": httpapitest.ShownAs("mine"),
				"proposed by": "triager", "proposed by name": httpapitest.ShownAs("triager"),
			}},
		} {
			got := httpapitest.AsPerson(t, r, c.who, http.MethodGet, c.path, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s answered %d: %s", c.path, got.Code, got.Body.String())
			}
			all, err := csv.NewReader(strings.NewReader(got.Body.String())).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			body := httpapitest.RowsUnder(all)
			if len(body) < 2 {
				t.Errorf("%s holds no row, so this checked nothing", c.path)
				continue
			}
			for column, want := range c.want {
				at := httpapitest.IndexOf(body[0], column)
				if at < 0 {
					t.Errorf("%s has no %q column: %v", c.path, column, body[0])
					continue
				}
				if body[1][at] != want {
					t.Errorf("%s carries %q under %q, want %q", c.path, body[1][at], column, want)
				}
			}
		}
	})
}

// TestABuildsCountsNameItByTheNamesThatAddressIt is the rule on the
// readiness counts, which read the build's names in a query of their own.
func TestABuildsCountsNameItByTheNamesThatAddressIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		var readiness struct {
			Now struct {
				Stream      string `json:"stream"`
				StreamName  string `json:"stream_name"`
				Variant     string `json:"variant"`
				VariantName string `json:"variant_name"`
			} `json:"now"`
		}
		httpapitest.Read(t, r, "triager",
			"/v1/products/mine/streams/master/variants/broadcom/readiness", &readiness)
		now := readiness.Now
		if now.Stream != "master" || now.StreamName != "Master" ||
			now.Variant != "broadcom" || now.VariantName != "Broadcom" {
			t.Errorf("the counts name the build as %+v, want the names with the spellings beside them",
				now)
		}
	})
}

// TestAListNamesABuildByTheNamesThatAddressIt is the same rule for the branch
// or tag and the variant. The cast declares them with a capital, so the
// spelling shown differs from the name a path folds to.
func TestAListNamesABuildByTheNamesThatAddressIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)

		type row struct {
			Stream      string `json:"stream"`
			StreamName  string `json:"stream_name"`
			Variant     string `json:"variant"`
			VariantName string `json:"variant_name"`
		}
		for _, path := range []string{"/v1/running-out?days=365", "/v1/unassigned"} {
			var list struct {
				Items []row `json:"items"`
			}
			httpapitest.Read(t, r, "triager", path, &list)
			if len(list.Items) == 0 {
				t.Errorf("%s answered nothing, so this checked nothing", path)
				continue
			}
			for _, one := range list.Items {
				if one.Stream != "master" || one.StreamName != "Master" ||
					one.Variant != "broadcom" || one.VariantName != "Broadcom" {
					t.Errorf("%s names the build as %+v, want the addresses with the spellings beside them",
						path, one)
				}
			}
		}
	})
}

// TestABuildWithNoDisplayNamesIsNamedByItsNames pins the fallback every
// endpoint shares: a product, branch or tag, or variant with no display name
// is labeled by its name, on every list alike.
func TestABuildWithNoDisplayNamesIsNamedByItsNames(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		for _, table := range []string{"product", "stream", "variant"} {
			if _, err := r.DB.DB.NewUpdate().Table(table).
				Set("display_name = ?", "").Where("1 = 1").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}

		type row struct {
			Product     string `json:"product"`
			ProductName string `json:"product_name"`
			Stream      string `json:"stream"`
			StreamName  string `json:"stream_name"`
			Variant     string `json:"variant"`
			VariantName string `json:"variant_name"`
		}
		named := func(what string, one row, build bool) {
			if one.Product != "" && one.ProductName != one.Product {
				t.Errorf("%s labels product %q as %q", what, one.Product, one.ProductName)
			}
			if build && (one.Stream == "" || one.StreamName != one.Stream ||
				one.Variant == "" || one.VariantName != one.Variant) {
				t.Errorf("%s labels the build as %+v, want each label to be its name", what, one)
			}
		}
		for _, list := range []struct {
			path  string
			build bool
		}{
			{"/v1/running-out?days=365", true},
			{"/v1/unassigned", true},
			{"/v1/audit", false},
			{"/v1/audit/claims", false},
			{"/v1/effort", false},
		} {
			var got struct {
				Items []row `json:"items"`
			}
			httpapitest.Read(t, r, "triager", list.path, &got)
			if len(got.Items) == 0 {
				t.Errorf("%s answered nothing, so this checked nothing", list.path)
				continue
			}
			for _, one := range got.Items {
				if one.Product == "" && !list.build {
					t.Errorf("%s names no product", list.path)
				}
				named(list.path, one, list.build)
			}
		}

		var readiness struct {
			Now row `json:"now"`
		}
		httpapitest.Read(t, r, "triager",
			"/v1/products/mine/streams/master/variants/broadcom/readiness", &readiness)
		named("readiness", readiness.Now, true)
	})
}
