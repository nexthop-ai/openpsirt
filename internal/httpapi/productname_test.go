// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/csv"
	"net/http"
	"strings"
	"testing"
)

// TestAListNamesAProductByTheNameThatAddressesIt pins `product` as the name a
// route resolves, with the display name beside it, on the lists whose rows
// carry a product read by a query of their own. A label in its place is a
// value a caller can show and cannot filter or link by.
func TestAListNamesAProductByTheNameThatAddressesIt(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)

		type row struct {
			Product     string `json:"product"`
			ProductName string `json:"product_name"`
		}
		for _, path := range []string{
			"/v1/audit", "/v1/effort", "/v1/running-out?days=365",
		} {
			var list struct {
				Items []row `json:"items"`
			}
			read(t, r, "triager", path, &list)
			if len(list.Items) == 0 {
				t.Errorf("%s answered nothing, so this checked nothing", path)
				continue
			}
			for _, one := range list.Items {
				if one.Product != "mine" || one.ProductName != shownAs("mine") {
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
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)

		for _, c := range []struct {
			who, path string
			want      map[string]string
		}{
			{"triager", "/v1/running-out.csv?days=365", map[string]string{
				"product": "mine", "product name": shownAs("mine"),
				"stream": "master", "stream name": "Master",
				"variant": "broadcom", "variant name": "Broadcom",
			}},
			{"triager", "/v1/audit.csv", map[string]string{
				"product": "mine", "product name": shownAs("mine"),
			}},
			{"reviewer", "/v1/review-queue.csv", map[string]string{
				"product": "mine", "product name": shownAs("mine"),
				"proposed by": "triager", "proposed by name": shownAs("triager"),
			}},
		} {
			got := asPerson(t, r, c.who, http.MethodGet, c.path, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s answered %d: %s", c.path, got.Code, got.Body.String())
			}
			all, err := csv.NewReader(strings.NewReader(got.Body.String())).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			body := rowsUnder(all)
			if len(body) < 2 {
				t.Errorf("%s holds no row, so this checked nothing", c.path)
				continue
			}
			for column, want := range c.want {
				at := indexOf(body[0], column)
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
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		var readiness struct {
			Now struct {
				Stream      string `json:"stream"`
				StreamName  string `json:"stream_name"`
				Variant     string `json:"variant"`
				VariantName string `json:"variant_name"`
			} `json:"now"`
		}
		read(t, r, "triager",
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
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

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
			read(t, r, "triager", path, &list)
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
