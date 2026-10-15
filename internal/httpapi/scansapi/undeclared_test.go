// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAScanDocumentNamesTheMissingPartAsTheReceiptsDo(t *testing.T) {
	// A branch or a variant the product does not declare is answered in the
	// words the receipts list answers it in, naming the part that is missing.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, build := range []struct{ stream, variant, missing string }{
			{"no-such-branch", "broadcom", "no-such-branch"},
			{"master", "no-such-variant", "no-such-variant"},
		} {
			at := "/v1/products/mine/streams/" + build.stream + "/variants/" + build.variant + "/scans"
			receipts := httpapitest.AsPerson(t, r, "reader", http.MethodGet, at, "")
			document := httpapitest.AsPerson(t, r, "reader", http.MethodGet, at+"/1/documents/1", "")
			if document.Code != http.StatusNotFound || receipts.Code != http.StatusNotFound {
				t.Fatalf("%s: the document answered %d and the receipts %d, want 404 for both",
					build.missing, document.Code, receipts.Code)
			}
			if document.Body.String() != receipts.Body.String() {
				t.Errorf("%s: the document answered %s and the receipts %s",
					build.missing, document.Body.String(), receipts.Body.String())
			}
			if !strings.Contains(document.Body.String(), build.missing) {
				t.Errorf("the refusal %s does not name %s", document.Body.String(), build.missing)
			}
		}
	})
}
