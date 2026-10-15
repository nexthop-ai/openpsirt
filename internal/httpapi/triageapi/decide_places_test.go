// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAJudgmentCoversThePlacesItNamesAndRefusesOneTheFindingIsNotAt(t *testing.T) {
	// Narrowed to the places named, and a name nothing matches refuses the
	// whole judgment: somebody who meant to cover six places and mistyped one
	// does not quietly cover five.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedShared(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-1/components/libyang"
		first := finding.PlaceIdentity("libyang", "docker-a")
		second := finding.PlaceIdentity("libyang", "docker-b")
		decide := func(places ...string) string {
			return `{"outcome":"not-applicable","justification":"vulnerable_code_not_present",` +
				`"reasoning":"The schema parser is not built.","places":["` +
				strings.Join(places, `","`) + `"]}`
		}
		decisions := func() int {
			n, err := r.DB.DB.NewSelect().Table("decision").Count(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			return int(n)
		}

		var one struct {
			Recorded int `json:"recorded"`
			Left     int `json:"left"`
		}
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at+"/decision", decide(first))
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding one named place answered %d: %s", got.Code, got.Body.String())
		}
		if err := json.Unmarshal(got.Body.Bytes(), &one); err != nil {
			t.Fatal(err)
		}
		if one.Recorded != 1 || one.Left != 1 {
			t.Errorf("a judgment naming one of two places recorded %d and left %d", one.Recorded, one.Left)
		}

		before := decisions()
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			at+"/decision", decide(second, "no-such-place")), http.StatusUnprocessableEntity)
		if after := decisions(); after != before {
			t.Errorf("a refused judgment wrote %d decisions", after-before)
		}
	})
}
