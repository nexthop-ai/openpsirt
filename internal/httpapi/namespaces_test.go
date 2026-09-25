// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// seededTwin is seededLib described again under a namespace of the producer's
// own: one name, one version, one ecosystem, and a second component.
var seededTwin = graph.Described{
	Purl: "pkg:deb/sonic/libnl-3-200@3.7.0?arch=amd64", Name: "libnl-3-200", Version: "3.7.0",
}

// shipsUnderTwoNamespaces is a build holding one package under two
// namespaces, with the issue open at the components named.
func (r *reach) shipsUnderTwoNamespaces(t *testing.T, carrying ...graph.Described) {
	t.Helper()
	reported := make([]finding.Reported, 0, len(carrying))
	for _, component := range carrying {
		reported = append(reported, finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
			Component: component,
		})
	}
	r.scan(t, "two-namespaces", graph.Snapshot{
		Root:       seededRoot,
		Components: []graph.Described{seededConsumer, seededLib, seededTwin},
		Dependencies: []graph.Dependency{
			{Parent: seededRoot, Child: seededConsumer},
			{Parent: seededConsumer, Child: seededLib},
			{Parent: seededConsumer, Child: seededTwin},
		},
	}, reported)
}

const twoNamespacesAt = "/v1/products/mine/streams/master/variants/broadcom"

func TestAPackageUnderTwoNamespacesIsReachedByNamingOne(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.shipsUnderTwoNamespaces(t, seededLib)
		around := twoNamespacesAt + "/components/libnl-3-200/around?version=3.7.0&ecosystem=deb"

		got := asPerson(t, r, "triager", http.MethodGet, around, "")
		if got.Code != http.StatusConflict {
			t.Fatalf("a name, version and ecosystem held twice answered %d, want 409: %s",
				got.Code, got.Body.String())
		}
		for _, namespace := range []string{`"namespace":"debian"`, `"namespace":"sonic"`} {
			if !strings.Contains(got.Body.String(), namespace) {
				t.Errorf("the refusal does not offer %s, so it offers no way out: %s",
					namespace, got.Body.String())
			}
		}

		for _, namespace := range []string{"debian", "sonic"} {
			got = asPerson(t, r, "triager", http.MethodGet, around+"&namespace="+namespace, "")
			if got.Code != http.StatusOK {
				t.Errorf("naming the %s namespace answered %d: %s",
					namespace, got.Code, got.Body.String())
			}
		}
	})
}

func TestAFindingOpenUnderOneOfTwoNamespacesNeedsNoChoice(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.shipsUnderTwoNamespaces(t, seededLib)
		got := asPerson(t, r, "triager", http.MethodGet, twoNamespacesAt+
			"/findings/CVE-2026-9999/components/libnl-3-200?version=3.7.0", "")
		if got.Code != http.StatusOK {
			t.Errorf("a finding open at one of the two answered %d, want 200: %s",
				got.Code, got.Body.String())
		}
	})
}

func TestAFindingOpenUnderBothNamespacesOffersBoth(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.shipsUnderTwoNamespaces(t, seededLib, seededTwin)
		at := twoNamespacesAt + "/findings/CVE-2026-9999/components/libnl-3-200?version=3.7.0"

		got := asPerson(t, r, "triager", http.MethodGet, at, "")
		if got.Code != http.StatusConflict {
			t.Fatalf("a finding open at both answered %d, want 409: %s",
				got.Code, got.Body.String())
		}
		body := got.Body.String()
		if !strings.Contains(body, `"carrying"`) ||
			!strings.Contains(body, `"namespace":"debian"`) ||
			!strings.Contains(body, `"namespace":"sonic"`) {
			t.Errorf("the refusal does not offer both carrying components: %s", body)
		}

		got = asPerson(t, r, "triager", http.MethodGet, at+"&ecosystem=deb&namespace=sonic", "")
		if got.Code != http.StatusOK {
			t.Errorf("naming the namespace answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestEveryRouteNamingAFindingsComponentTakesTheNamespace(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.shipsUnderTwoNamespaces(t, seededLib, seededTwin)
		finding := twoNamespacesAt + "/findings/CVE-2026-9999/components/libnl-3-200"
		routes := []struct {
			what, method, path string
		}{
			{"the reach", http.MethodGet, finding + "/reach?version=3.7.0"},
			{"a tag", http.MethodPut, finding + "/tags/waiting-on-vendor?version=3.7.0"},
			{"the issues at the component", http.MethodGet,
				twoNamespacesAt + "/components/libnl-3-200/issues?version=3.7.0"},
		}
		for _, route := range routes {
			got := asPerson(t, r, "triager", route.method, route.path, "")
			if got.Code != http.StatusConflict {
				t.Errorf("%s with no namespace answered %d, want 409: %s",
					route.what, got.Code, got.Body.String())
			}
			got = asPerson(t, r, "triager", route.method,
				route.path+"&ecosystem=deb&namespace=sonic", "")
			if got.Code >= 300 {
				t.Errorf("%s naming the namespace answered %d: %s",
					route.what, got.Code, got.Body.String())
			}
		}
	})
}
