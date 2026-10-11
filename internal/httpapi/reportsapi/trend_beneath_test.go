// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// oneBuild is the selection a subtree is askable over: a product, a branch and
// a variant naming exactly one build.
const oneBuild = "product=mine&stream=master&variant=broadcom"

// trendRoutes are the two answers drawn from one trend: the chart and its
// export. Both resolve the component the same way and refuse the same way.
var trendRoutes = []string{"/v1/trend", "/v1/trend.csv"}

func TestATrendBeneathAComponentTheBuildDoesNotHoldIsNotFound(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ShipsUnderTwoNamespaces(t, httpapitest.SeededLib)
		for _, route := range trendRoutes {
			for _, beneath := range []string{
				"beneath=nothing-here",
				// A namespace the build does not carry, which is what a stale
				// link to a component names.
				"beneath=libnl-3-200&beneath_version=3.7.0&beneath_ecosystem=deb&beneath_namespace=ubuntu",
			} {
				got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
					route+"?"+oneBuild+"&"+beneath, "")
				if got.Code != http.StatusNotFound {
					t.Errorf("%s with %s answered %d, want 404: %s",
						route, beneath, got.Code, got.Body.String())
				}
				if !strings.Contains(got.Body.String(), "does not hold a component") {
					t.Errorf("%s with %s does not say what is missing: %s",
						route, beneath, got.Body.String())
				}
			}
		}
	})
}

func TestATrendBeneathAComponentTheBuildHoldsIsAnswered(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ShipsUnderTwoNamespaces(t, httpapitest.SeededLib)
		for _, route := range trendRoutes {
			for _, beneath := range []string{
				"beneath=libswsscommon",
				"beneath=libnl-3-200&beneath_version=3.7.0&beneath_ecosystem=deb&beneath_namespace=sonic",
			} {
				got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
					route+"?"+oneBuild+"&"+beneath, "")
				if got.Code != http.StatusOK {
					t.Errorf("%s with %s answered %d: %s", route, beneath, got.Code, got.Body.String())
				}
			}
		}
	})
}

func TestATrendBeneathANameMeaningSeveralComponentsOffersTheChoices(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ShipsUnderTwoNamespaces(t, httpapitest.SeededLib)
		for _, route := range trendRoutes {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
				route+"?"+oneBuild+"&beneath=libnl-3-200&beneath_version=3.7.0", "")
			if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), `"namespace":"sonic"`) {
				t.Errorf("%s beneath a name held twice answered %d, want 409 offering both: %s",
					route, got.Code, got.Body.String())
			}
		}
	})
}

func TestATrendBeneathAComponentAnswersAnUnreadableProductAlikeWhateverItHolds(t *testing.T) {
	// The outsider reads another product and not this one. Whether the build
	// holds the name is a fact about this product, so the refusal is the one a
	// product nobody declared gets, word for word.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ShipsUnderTwoNamespaces(t, httpapitest.SeededLib)
		for _, route := range trendRoutes {
			undeclared := httpapitest.AsPerson(t, r, "outsider", http.MethodGet,
				route+"?product=nobody-declared-this&stream=master&variant=broadcom&beneath=libswsscommon", "")
			httpapitest.RefusedWith(t, undeclared, http.StatusNotFound)
			for _, beneath := range []string{
				"beneath=libswsscommon", "beneath=nothing-here", "beneath=libnl-3-200",
			} {
				got := httpapitest.AsPerson(t, r, "outsider", http.MethodGet,
					route+"?"+oneBuild+"&"+beneath, "")
				if got.Code != undeclared.Code || got.Body.String() != undeclared.Body.String() {
					t.Errorf("%s with %s answered %d %s, where a product nobody declared answers %d %s",
						route, beneath, got.Code, got.Body.String(),
						undeclared.Code, undeclared.Body.String())
				}
			}
		}
	})
}

func TestATrendBeneathAComponentNamingNoProductIsRefusedWhateverTheName(t *testing.T) {
	// Across every product the builds counted include ones the caller may not
	// read, so the name is never looked up there.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ShipsUnderTwoNamespaces(t, httpapitest.SeededLib)
		for _, route := range trendRoutes {
			for _, who := range []string{"triager", "outsider"} {
				for _, beneath := range []string{"beneath=libswsscommon", "beneath=nothing-here"} {
					got := httpapitest.AsPerson(t, r, who, http.MethodGet, route+"?"+beneath, "")
					if got.Code != http.StatusUnprocessableEntity ||
						!strings.Contains(got.Body.String(), "needs a product") {
						t.Errorf("%s with %s as %s answered %d, want 422 asking for a product: %s",
							route, beneath, who, got.Code, got.Body.String())
					}
				}
			}
		}
	})
}
