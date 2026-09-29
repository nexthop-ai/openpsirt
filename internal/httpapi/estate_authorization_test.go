// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A role held across every product reaches every product, including the one
// nobody granted it against by name — and reaches it at its own visibility and
// no further.
//
// The second half is the one worth pinning. The queries already carry a flag
// meaning "every product", and it means *no narrowing at all*: visibility
// included. An estate grant that set it would have handed somebody granted
// disclosed reading every undisclosed finding in the deployment (REQ-43).
func TestARoleHeldEverywhereReachesEveryProductAtItsOwnVisibility(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// Both products, where a per-product reader reaches only the one they
		// were granted. "theirs" is the product nobody named in their grant.
		for _, product := range []string{"mine", "theirs"} {
			if got := r.As(t, "estate-reader", http.MethodGet,
				"/v1/products/"+product+"/streams"); got != http.StatusOK {
				t.Errorf("a role held everywhere reads %q as %d, not 200", product, got)
			}
			// The per-product reader is the contrast: granted on "mine" alone,
			// so "theirs" is invisible rather than merely unreadable.
			want := http.StatusOK
			if product == "theirs" {
				want = http.StatusNotFound
			}
			if got := r.As(t, "reader", http.MethodGet,
				"/v1/products/"+product+"/streams"); got != want {
				t.Errorf("a per-product reader reads %q as %d, not %d", product, got, want)
			}
		}

		// Exports are named by REQ-43 because they are what gets missed: a
		// list narrowed correctly and an export that was not is a disclosure
		// nothing on the screen reports. Asserted on the body, because a 200
		// over an empty result set says nothing at all.
		disclosed, undisclosed := httpapitest.SeedTheirs(t, r)
		for _, path := range []string{
			"/v1/findings.csv",
			"/v1/products/theirs/findings.csv",
		} {
			body := httpapitest.AsPerson(t, r, "estate-reader", http.MethodGet, path, "")
			if body.Code != http.StatusOK {
				t.Errorf("a role held everywhere reads %s as %d, not 200", path, body.Code)
				continue
			}
			if !strings.Contains(body.Body.String(), disclosed) {
				t.Errorf("%s omits the disclosed finding the estate role reaches", path)
			}
			if strings.Contains(body.Body.String(), undisclosed) {
				t.Errorf("%s exported an undisclosed finding to a role granted disclosed reading only", path)
			}
		}
	})
}
