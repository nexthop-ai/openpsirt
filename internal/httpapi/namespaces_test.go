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

// namedRoute is a route that addresses a finding or a component by its name,
// with a request it accepts.
type namedRoute struct {
	what, method, path, body string
	// finding is whether the route narrows to what carries the issue, which
	// the routes naming only a component do not.
	finding bool
}

// namedRoutes is every route addressing a finding or a component by name.
func namedRoutes() []namedRoute {
	finding := twoNamespacesAt + "/findings/CVE-2026-9999/components/libnl-3-200"
	component := twoNamespacesAt + "/components/libnl-3-200"
	return []namedRoute{
		{"the finding", http.MethodGet, finding + "?version=3.7.0", "", true},
		{"the reach", http.MethodGet, finding + "/reach?version=3.7.0", "", true},
		{"a tag", http.MethodPut, finding + "/tags/waiting-on-vendor?version=3.7.0", "", true},
		{"an assignment", http.MethodPut, finding + "/assignment?version=3.7.0", `{}`, true},
		{"a decision", http.MethodPost, finding + "/decision?version=3.7.0",
			`{"outcome":"wont-fix","reasoning":"Not worth it."}`, true},
		{"the issues at the component", http.MethodGet, component + "/issues?version=3.7.0", "", false},
		{"a decision about the component", http.MethodPost, component + "/decisions?version=3.7.0",
			`{"vulnerabilities":["CVE-2026-9999"],"outcome":"wont-fix",` +
				`"selected_by":"everything here","reasoning":"Not worth it."}`, false},
	}
}

// Each route is asked on a build of its own: the two components share a place,
// so a decision recorded through one route stands against the next.
func TestEveryRouteNamingAFindingsComponentTakesTheNamespace(t *testing.T) {
	for _, route := range namedRoutes() {
		t.Run(route.what, func(t *testing.T) {
			twoReach(t, func(t *testing.T, r *reach) {
				r.shipsUnderTwoNamespaces(t, seededLib, seededTwin)
				got := asPerson(t, r, "triager", route.method, route.path, route.body)
				if got.Code != http.StatusConflict {
					t.Errorf("with no namespace it answered %d, want 409: %s",
						got.Code, got.Body.String())
				}
				got = asPerson(t, r, "triager", route.method,
					route.path+"&ecosystem=deb&namespace=sonic", route.body)
				if got.Code >= 300 {
					t.Errorf("naming the namespace it answered %d: %s", got.Code, got.Body.String())
				}
			})
		})
	}
}

func TestARouteNamingAFindingOpenAtOneOfTwoNeedsNoNamespace(t *testing.T) {
	for _, route := range namedRoutes() {
		if !route.finding {
			continue
		}
		t.Run(route.what, func(t *testing.T) {
			twoReach(t, func(t *testing.T, r *reach) {
				r.shipsUnderTwoNamespaces(t, seededLib)
				got := asPerson(t, r, "triager", route.method, route.path, route.body)
				if got.Code >= 300 {
					t.Errorf("at the one carrying it, it answered %d: %s",
						got.Code, got.Body.String())
				}
			})
		})
	}
}

func TestADecisionReachesABuildThatNamesThePackageUnderAnotherNamespace(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.shipsUnderTwoNamespaces(t, seededLib, seededTwin)
		// Only the distribution's namespace in the other build.
		r.scannedAlso(t, "mellanox", "3.8.0")
		got := asPerson(t, r, "triager", http.MethodPost, twoNamespacesAt+
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"+
			"?version=3.7.0&ecosystem=deb&namespace=sonic",
			`{"outcome":"wont-fix","reasoning":"Not worth it.",`+
				`"also":[{"stream":"master","variant":"mellanox","version":"3.8.0"}]}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding across a build naming it under another namespace answered %d: %s",
				got.Code, got.Body.String())
		}
		if !strings.Contains(got.Body.String(), `"variant":"mellanox"`) {
			t.Errorf("the other build is missing from what was recorded: %s", got.Body.String())
		}
	})
}

func TestAListNarrowedBeneathAComponentTakesTheNamespace(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.shipsUnderTwoNamespaces(t, seededLib, seededTwin)
		at := "/v1/products/mine/findings?stream=master&variant=broadcom" +
			"&beneath=libnl-3-200&beneath_version=3.7.0"
		got := asPerson(t, r, "triager", http.MethodGet, at, "")
		if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), `"namespace":"sonic"`) {
			t.Errorf("a name held twice answered %d, want 409 offering both: %s",
				got.Code, got.Body.String())
		}
		got = asPerson(t, r, "triager", http.MethodGet,
			at+"&beneath_ecosystem=deb&beneath_namespace=sonic", "")
		if got.Code != http.StatusOK {
			t.Errorf("naming the namespace answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestTheListsLinkingToAFindingSayWhichComponentItIs(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.shipsUnderTwoNamespaces(t, seededLib, seededTwin)
		build := "/v1/products/mine/streams/master/variants/broadcom"
		finding := build + "/findings/CVE-2026-9999/components/libnl-3-200"
		// Before anything is handed out, the unassigned list holds both.
		unassigned := asPerson(t, r, "triager", http.MethodGet, "/v1/unassigned?product=mine", "")
		for _, want := range []string{`"namespace":"debian"`, `"namespace":"sonic"`} {
			if !strings.Contains(unassigned.Body.String(), want) {
				t.Errorf("the unassigned list does not say %s, so its link cannot pick the component: %s",
					want, unassigned.Body.String())
			}
		}
		// A claim, so the list of decisions has one to name; and the work
		// handed to the triager, so their own tree has something in it.
		if got := asPerson(t, r, "triager", http.MethodPost,
			finding+"/decision?version=3.7.0&ecosystem=deb&namespace=sonic",
			`{"outcome":"wont-fix","reasoning":"Not worth it."}`); got.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", got.Code, got.Body.String())
		}
		for _, namespace := range []string{"debian", "sonic"} {
			if got := asPerson(t, r, "assigner", http.MethodPut,
				finding+"/assignment?version=3.7.0&ecosystem=deb&namespace="+namespace,
				`{"person":"triager"}`); got.Code >= 300 {
				t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
			}
		}
		// What blocks a release names its rows' components among much else, so
		// the rows themselves are read.
		var readiness struct {
			Blocking []struct {
				Namespace string `json:"namespace"`
			} `json:"blocking"`
		}
		read(t, r, "triager", build+"/readiness", &readiness)
		if len(readiness.Blocking) == 0 || readiness.Blocking[0].Namespace == "" {
			t.Errorf("what blocks a release does not say which component a row is: %+v", readiness)
		}
		for _, list := range []struct{ what, who, path, want string }{
			// A claim and a blocking row stand for a place, which both
			// components share, so each names one of them.
			{"the decisions", "triager", "/v1/decisions?product=mine", `"namespace":"`},

			{"the tree of one's own work", "triager", build + "/components/mine", ""},
		} {
			got := asPerson(t, r, list.who, http.MethodGet, list.path, "")
			if got.Code != http.StatusOK {
				t.Errorf("%s answered %d: %s", list.what, got.Code, got.Body.String())
				continue
			}
			wants := []string{`"namespace":"debian"`, `"namespace":"sonic"`}
			if list.want != "" {
				wants = []string{list.want}
			}
			for _, want := range wants {
				if !strings.Contains(got.Body.String(), want) {
					t.Errorf("%s does not say %s, so its link cannot pick the component: %s",
						list.what, want, got.Body.String())
				}
			}
		}
	})
}

func TestALinkNamingAVersionOpensTheTwinTheIssueIsOpenAt(t *testing.T) {
	// apko describes a package once more as a directory with no identifier.
	// The lookup reads a version with no ecosystem as naming that twin, and
	// the issue is open at the other one.
	twoReach(t, func(t *testing.T, r *reach) {
		bare := graph.Described{Name: "libnl-3-200", Version: "3.7.0"}
		r.scan(t, "bare-twin", graph.Snapshot{
			Root:       seededRoot,
			Components: []graph.Described{seededConsumer, seededLib, bare},
			Dependencies: []graph.Dependency{
				{Parent: seededRoot, Child: seededConsumer},
				{Parent: seededConsumer, Child: seededLib},
				{Parent: seededLib, Child: bare},
			},
		}, []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
			Component: seededLib,
		}})
		got := asPerson(t, r, "triager", http.MethodGet, twoNamespacesAt+
			"/findings/CVE-2026-9999/components/libnl-3-200?version=3.7.0", "")
		if got.Code != http.StatusOK {
			t.Errorf("the finding named by its version answered %d, want 200: %s",
				got.Code, got.Body.String())
		}
	})
}
