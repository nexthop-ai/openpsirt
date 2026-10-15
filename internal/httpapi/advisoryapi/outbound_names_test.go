// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestADestinationNamingAnUnknownProductOrTeamIsRefusedAndNotRecorded(t *testing.T) {
	// A destination scoped to a product or a team names one that exists,
	// and is refused in the words every route uses for a name nobody holds.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		const secret = "sixteen-characters-at-least"
		for _, c := range []struct{ scope, want string }{
			{`"product":"no-such-product"`, "no product is declared by that name"},
			{`"team":"no-such-team"`, "no team is known as no-such-team"},
		} {
			got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/outbound",
				`{"name":"scoped","kind":"*","url":"https://hooks.example.test/t/abc",`+
					`"secret":"`+secret+`",`+c.scope+`}`)
			if got.Code != http.StatusNotFound || !strings.Contains(got.Body.String(), c.want) {
				t.Errorf("%s answered %d %s, want 404 saying %q", c.scope, got.Code, got.Body.String(), c.want)
			}
		}
		listed := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/outbound", "")
		if strings.Contains(listed.Body.String(), `"scoped"`) {
			t.Errorf("a refused destination was recorded: %s", listed.Body.String())
		}
	})
}
