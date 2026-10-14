// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestABuildNeverScannedIsTheProductsBusinessOnly(t *testing.T) {
	// The route answers somebody who may not see the product, about the work
	// they hold. A build nothing was scanned for says "nothing scanned" to a
	// reader of the product, and to anybody else what a product nobody
	// declared says.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		product, err := catalog.NewStore(r.DB.DB).ProductByName(t.Context(), "mine")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := catalog.NewStore(r.DB.DB).DeclareVariant(t.Context(), product.ID,
			"never-scanned", true); err != nil {
			t.Fatal(err)
		}
		at := "/v1/products/mine/streams/master/variants/never-scanned/components/mine"
		nobody := httpapitest.AsPerson(t, r, "outsider", http.MethodGet,
			"/v1/products/nobody-declared/streams/master/variants/never-scanned/components/mine", "")

		stranger := httpapitest.AsPerson(t, r, "outsider", http.MethodGet, at, "")
		httpapitest.RefusedWith(t, stranger, http.StatusNotFound)
		if stranger.Body.String() != nobody.Body.String() {
			t.Errorf("a stranger is told %s about a declared build, and %s about an undeclared product",
				stranger.Body.String(), nobody.Body.String())
		}
		reader := httpapitest.AsPerson(t, r, "reader", http.MethodGet, at, "")
		httpapitest.RefusedWith(t, reader, http.StatusNotFound)
		if !httpapitest.Contains(reader.Body.String(), "nothing has been scanned") {
			t.Errorf("a reader of the product is told %s", reader.Body.String())
		}
	})
}
