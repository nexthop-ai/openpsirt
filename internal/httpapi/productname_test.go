// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
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
