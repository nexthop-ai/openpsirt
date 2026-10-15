// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A NUL character in typed input is refused naming the input, wherever the
// input is: the query builder refuses a string holding one, so carried through
// it fails the request with nothing to say why.
func TestANULInTypedInputIsRefusedNamingTheInput(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, c := range []struct {
			what, method, path, body, names string
		}{
			{"a query parameter", http.MethodGet, "/v1/products/mine/holders?q=pl%00at", "",
				"query parameter q holds a NUL character"},
			{"a path value", http.MethodGet, "/v1/products/pl%00at/holders", "",
				"path value product holds a NUL character"},
			{"a string in a JSON body", http.MethodPost, "/v1/teams",
				`{"name":"plat\u0000form","display_name":"Platform"}`,
				"body.name holds a NUL character"},
			{"a key in a JSON body", http.MethodPost, "/v1/teams",
				`{"name":"platform","display_name":"Platform","x\u0000":1}`,
				"a key in body holds a NUL character"},
		} {
			got := httpapitest.AsPerson(t, r, "admin", c.method, c.path, c.body)
			if got.Code != http.StatusBadRequest {
				t.Errorf("%s holding a NUL answered %d: %s", c.what, got.Code, got.Body.String())
				continue
			}
			if !strings.Contains(got.Body.String(), c.names) {
				t.Errorf("%s holding a NUL was refused without saying %q: %s", c.what, c.names, got.Body.String())
			}
		}
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"platform","display_name":"Platform"}`); made.Code >= 300 {
			t.Errorf("a team named without a NUL answered %d: %s", made.Code, made.Body.String())
		}
	})
}
