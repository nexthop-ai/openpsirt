package httpapi_test

import (
	"net/http"
	"testing"
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
	twoReach(t, func(t *testing.T, r *reach) {
		// Both products, where a per-product reader reaches only the one they
		// were granted. "theirs" is the product nobody named in their grant.
		for _, product := range []string{"mine", "theirs"} {
			if got := r.as(t, "estate-reader", http.MethodGet,
				"/v1/products/"+product+"/streams"); got != http.StatusOK {
				t.Errorf("a role held everywhere reads %q as %d, not 200", product, got)
			}
			// The per-product reader is the contrast: granted on "mine" alone,
			// so "theirs" is invisible rather than merely unreadable.
			want := http.StatusOK
			if product == "theirs" {
				want = http.StatusNotFound
			}
			if got := r.as(t, "reader", http.MethodGet,
				"/v1/products/"+product+"/streams"); got != want {
				t.Errorf("a per-product reader reads %q as %d, not %d", product, got, want)
			}
		}

		// Counts and exports are named by REQ-43 because they are what gets
		// missed: a list narrowed correctly and a count that was not is a
		// disclosure nothing on the screen reports.
		for _, path := range []string{
			"/v1/findings",
			"/v1/findings.csv",
			"/v1/products/theirs/findings.csv",
		} {
			if got := r.as(t, "estate-reader", http.MethodGet, path); got != http.StatusOK {
				t.Errorf("a role held everywhere reads %s as %d, not 200", path, got)
			}
		}
	})
}
