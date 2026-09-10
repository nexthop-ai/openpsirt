package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
)

func TestNoRouteSaysWhetherAnIdentityHasAnAccount(t *testing.T) {
	// walked rather than spot-checked. The rule had been applied to the
	// assignment writes and to handing work back, and missed on the read
	// beside them — the third time the same shape had been found. So this
	// asserts the invariant across every route carrying an {identity}, and
	// a route added later is caught by being added to this table.
	//
	// Two ways to satisfy it. A route open to any credential answers a
	// name nobody holds exactly as it answers a name somebody holds whose
	// work the caller cannot see. A route only an administrator may call
	// refuses everybody else *before* the name is resolved, so the refusal
	// carries nothing — an administrator already knows who has an account.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		routes := []struct {
			what   string
			method string
			path   string
			body   string
		}{
			{"what they are dealing with", http.MethodGet,
				"/v1/people/%s/assignments", ""},
			{"handing their work on", http.MethodPost,
				"/v1/people/%s/assignments/hand-back", `{"to":""}`},
			{"withdrawing a role", http.MethodDelete,
				"/v1/people/%s/roles/mine/public-read", ""},
			{"revoking their token", http.MethodDelete,
				"/v1/people/%s/tokens/theirs", ""},
			{"ending their sessions", http.MethodDelete,
				"/v1/people/%s/sessions", ""},
		}

		// "reader" holds an account here; the other name has never been seen.
		const held, unheld = "reader", "nobody-has-this-name"

		// Every credential the deployment recognizes, including one holding
		// nothing on any product — which is what found this.
		for _, who := range []string{"reader", "triager", "private-triage"} {
			for _, route := range routes {
				known := asPerson(t, r, who, route.method,
					fmt.Sprintf(route.path, held), route.body)
				unknown := asPerson(t, r, who, route.method,
					fmt.Sprintf(route.path, unheld), route.body)

				if known.Code != unknown.Code {
					t.Errorf("%s as %s: a name somebody holds answers %d and a name nobody holds %d",
						route.what, who, known.Code, unknown.Code)
				}
				if known.Body.String() != unknown.Body.String() {
					t.Errorf("%s as %s: the two answers read differently\n  held: %s\nunheld: %s",
						route.what, who, known.Body.String(), unknown.Body.String())
				}
			}
		}
	})
}
