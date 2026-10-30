// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const (
	hubQueue = "/v1/products/mine/code-findings"
	hubBuild = "/v1/products/mine/branches-and-tags/master/variants/broadcom"
)

// hubListed is the code finding queue as the hub's tests read it: the rules
// listed, sorted, and the open count.
type hubListed struct {
	Items []struct {
		Occurrence string `json:"occurrence"`
		Rule       string `json:"rule"`
	} `json:"items"`
	Total  int            `json:"total"`
	States map[string]int `json:"states"`
}

func (l hubListed) rules() []string {
	out := make([]string, 0, len(l.Items))
	for _, each := range l.Items {
		out = append(out, each.Rule)
	}
	sort.Strings(out)
	return out
}

func hubQueueOf(t *testing.T, r *httpapitest.Reach, who, query string) hubListed {
	t.Helper()
	var out hubListed
	httpapitest.Read(t, r, who, hubQueue+query, &out)
	return out
}

func sameRules(got, want []string) bool {
	return slices.Equal(got, want)
}

func TestTheQueueKeepsTheCodeFindingsOnASourcePackageByAnyOfItsNames(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		for _, c := range []struct {
			query string
			want  []string
		}{
			// The source, a binary built from no repository and the binary
			// the code finding is placed on answer alike: one source package.
			{"?component=mine-src", []string{"clang-tidy/leak"}},
			{"?component=MINE-SRC", []string{"clang-tidy/leak"}},
			{"?component=mine-tools", []string{"clang-tidy/leak"}},
			{"?component=libmine1&component_version=2.0", []string{"clang-tidy/leak"}},
			{"?component=libmine1&component_version=9.9", nil},
			{"?component=zlib1g", []string{"cppcheck/bad"}},
			{"?component=sonic-image", []string{"semgrep/bad"}},
			{"?component=nosuch", nil},
			// Beside another narrowing, both hold.
			{"?component=mine-src&series=cppcheck/default", nil},
		} {
			got := hubQueueOf(t, r, "security-testing-reader", c.query)
			if !sameRules(got.rules(), c.want) || got.Total != len(c.want) || got.States["open"] != len(c.want) {
				t.Errorf("%s lists %v, %d in all and %d open; want %v, every count following",
					c.query, got.rules(), got.Total, got.States["open"], c.want)
			}
		}
		// Narrowed in the data layer: a reader of no security testing work
		// in the product counts none however the queue is narrowed.
		if got := hubQueueOf(t, r, "reader", "?component=mine-src"); got.Total != 0 || got.States["open"] != 0 {
			t.Errorf("a reader of no security testing work reads %+v on the component; want nothing", got)
		}
	})
}

func TestTheQueueKeepsTheCodeFindingsBeneathAComponentOnOneBuild(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		const build = "&branch_or_tag=master&variant=broadcom"
		for _, c := range []struct {
			beneath string
			want    []string
		}{
			{"sonic-image", []string{"clang-tidy/leak", "cppcheck/bad", "semgrep/bad"}},
			{"libmine1", []string{"clang-tidy/leak", "cppcheck/bad"}},
			{"LIBMINE1", []string{"clang-tidy/leak", "cppcheck/bad"}},
			{"zlib1g", []string{"cppcheck/bad"}},
			{"mine-tools", nil},
		} {
			got := hubQueueOf(t, r, "security-testing-reader", "?beneath="+c.beneath+build)
			if !sameRules(got.rules(), c.want) || got.Total != len(c.want) || got.States["open"] != len(c.want) {
				t.Errorf("beneath %s lists %v, %d in all and %d open; want %v, every count following",
					c.beneath, got.rules(), got.Total, got.States["open"], c.want)
			}
		}
		if got := hubQueueOf(t, r, "security-testing-reader", "?beneath=libmine1&component=zlib1g"+build); !sameRules(got.rules(), []string{"cppcheck/bad"}) {
			t.Errorf("beneath the library and on the compression library lists %v; want cppcheck's alone", got.rules())
		}
		// A name the build does not hold is not a clean subtree.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet,
			hubQueue+"?beneath=nosuch"+build, ""), http.StatusNotFound)
		// The file is the list.
		w := httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet,
			"/v1/products/mine/code-findings.json?beneath=zlib1g"+build, "")
		if w.Code != http.StatusOK {
			t.Fatalf("the file beneath a component answered %d: %s", w.Code, w.Body.String())
		}
		if body := w.Body.String(); !strings.Contains(body, "cppcheck/bad") || strings.Contains(body, "clang-tidy/leak") {
			t.Errorf("the file beneath the compression library is %s; want cppcheck's code finding alone", body)
		}
	})
}

// hubNode is a tree row as the hub's tests read it.
type hubNode struct {
	Component string `json:"component"`
	On        *int   `json:"code_findings"`
	Beneath   *int   `json:"code_findings_beneath"`
}

func (n hubNode) counts() [2]int {
	if n.On == nil || n.Beneath == nil {
		return [2]int{-1, -1}
	}
	return [2]int{*n.On, *n.Beneath}
}

func TestTheTreeCountsOpenCodeFindingsOnAndBeneathEachNode(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		var top struct {
			Root  hubNode   `json:"root"`
			Items []hubNode `json:"items"`
		}
		httpapitest.Read(t, r, "security-testing-reader", hubBuild+"/components?code_findings=true", &top)
		// The root's own are the unplaced: their files are in no repository a
		// component was built from.
		if got := top.Root.counts(); got != [2]int{1, 3} {
			t.Errorf("the root carries %v; want 1 on it, unplaced, and 3 beneath", got)
		}
		want := map[string][2]int{"libmine1": {1, 2}, "mine-tools": {0, 0}}
		for _, node := range top.Items {
			if got := node.counts(); got != want[node.Component] {
				t.Errorf("%s carries %v; want %v", node.Component, got, want[node.Component])
			}
		}
		var around struct {
			Above []hubNode `json:"above"`
			Below []hubNode `json:"below"`
		}
		httpapitest.Read(t, r, "security-testing-reader", hubBuild+"/components/libmine1/around?code_findings=true", &around)
		if len(around.Below) != 1 || around.Below[0].counts() != [2]int{1, 1} {
			t.Errorf("below the library is %+v; want the compression library carrying its one", around.Below)
		}
		if len(around.Above) != 1 || around.Above[0].counts() != [2]int{1, 3} {
			t.Errorf("above the library is %+v; want the root carrying the build's three", around.Above)
		}
		var found struct {
			Items []hubNode `json:"items"`
		}
		httpapitest.Read(t, r, "security-testing-reader", hubBuild+"/components?q=zlib&code_findings=true", &found)
		if len(found.Items) != 1 || found.Items[0].counts() != [2]int{1, 1} {
			t.Errorf("a search for zlib finds %+v; want the compression library carrying its one", found.Items)
		}
		// Not asked, not counted.
		var plain struct {
			Root hubNode `json:"root"`
		}
		httpapitest.Read(t, r, "security-testing-reader", hubBuild+"/components", &plain)
		if plain.Root.On != nil || plain.Root.Beneath != nil {
			t.Errorf("a tree read without asking carries code findings %+v", plain.Root)
		}
	})
}

// hubCounted is the code finding counts of a component.
type hubCounted struct {
	Series []struct {
		Series   string         `json:"series"`
		States   map[string]int `json:"states"`
		Unplaced int            `json:"unplaced"`
	} `json:"series"`
	Builds []struct {
		BranchOrTag string `json:"branch_or_tag"`
		Variant     string `json:"variant"`
		Version     string `json:"version"`
		Open        int    `json:"open"`
	} `json:"builds"`
}

func TestAComponentsCodeFindingsAreCountedPerSeriesAndPerBuild(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		// Confirmed is no longer open, so the compression library's build
		// counts nothing open while its series counts one confirmed.
		cppcheck := hubQueueOf(t, r, "security-testing-reader", "?component=zlib1g").Items[0].Occurrence
		if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost,
			hubBuild+"/code-findings/"+cppcheck+"/decision", `{"outcome":"confirmed","reasoning":"real"}`); w.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", w.Code, w.Body.String())
		}
		for _, c := range []struct {
			component string
			open      map[string]int
			unplaced  map[string]int
			version   string
		}{
			{"mine-src", map[string]int{"clang-tidy/default": 1}, nil, "2.0"},
			{"Mine-Tools", map[string]int{"clang-tidy/default": 1}, nil, "2.0"},
			{"sonic-image", map[string]int{"semgrep/default": 1}, map[string]int{"semgrep/default": 1}, ""},
			{"zlib1g", nil, nil, ""},
		} {
			var got hubCounted
			httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/components/"+c.component+"/code-finding-counts", &got)
			if len(got.Series) != 3 {
				t.Fatalf("%s counts %d series; want every series of the product", c.component, len(got.Series))
			}
			for _, each := range got.Series {
				if each.States["open"] != c.open[each.Series] || each.Unplaced != c.unplaced[each.Series] {
					t.Errorf("%s in %s counts %d open and %d unplaced; want %d and %d", c.component, each.Series,
						each.States["open"], each.Unplaced, c.open[each.Series], c.unplaced[each.Series])
				}
				queued := hubQueueOf(t, r, "security-testing-reader", "?state=open&component="+c.component+"&series="+each.Series)
				if queued.Total != each.States["open"] {
					t.Errorf("%s in %s counts %d open where the queue lists %d", c.component, each.Series,
						each.States["open"], queued.Total)
				}
			}
			if c.open == nil {
				if len(got.Builds) != 0 {
					t.Errorf("%s per build is %+v; want no build, since nothing is open", c.component, got.Builds)
				}
				continue
			}
			if len(got.Builds) != 1 || got.Builds[0].Open != 1 || got.Builds[0].Version != c.version {
				t.Errorf("%s per build is %+v; want the one build at %q with its one open", c.component, got.Builds, c.version)
			}
		}
	})
}

func TestACodeFindingIsCountedOverTimeUntilItIsClosedAsFixed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		// Opened ten days ago, so the week before this one holds both of
		// those beneath the library.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"opened_at" = ?`, time.Now().UTC().Add(-10*24*time.Hour)).
			Where(`"kind" = ?`, kind.Analysis).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		listed := hubQueueOf(t, r, "security-testing-reader", "?component=libmine1")
		if len(listed.Items) != 1 {
			t.Fatalf("the library's queue is %+v; want its one code finding", listed)
		}
		codeFinding := hubBuild + "/code-findings/" + listed.Items[0].Occurrence
		cppcheck := hubQueueOf(t, r, "security-testing-reader", "?component=zlib1g").Items[0].Occurrence
		// A decision answers a code finding and closes nothing.
		if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost,
			hubBuild+"/code-findings/"+cppcheck+"/decision", `{"outcome":"confirmed","reasoning":"real"}`); w.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", w.Code, w.Body.String())
		}
		httpapitest.ApplyRunIn(t, r, "clang-tidy/default", time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRun(false))
		body := httpapitest.FixedBody(t, r, codeFinding, "the leak is closed")
		if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, codeFinding+"/fixed", body); w.Code != http.StatusOK {
			t.Fatalf("closing as fixed answered %d: %s", w.Code, w.Body.String())
		}
		var trend struct {
			Items []struct {
				NotFixed int `json:"not_fixed"`
				Opened   int `json:"opened"`
				Fixed    int `json:"fixed"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "security-testing-reader", hubBuild+"/components/libmine1/code-finding-trend?weeks=2", &trend)
		if len(trend.Items) != 2 {
			t.Fatalf("two weeks are %d points", len(trend.Items))
		}
		if got := trend.Items[0].NotFixed; got != 2 {
			t.Errorf("a week ago %d were not fixed beneath the library; want 2", got)
		}
		if got := trend.Items[1]; got.NotFixed != 1 || got.Fixed != 1 || got.Opened != 0 {
			t.Errorf("this week is %+v; want the confirmed one still counted and the other fixed", got)
		}
		httpapitest.Read(t, r, "security-testing-reader", hubBuild+"/components/zlib1g/code-finding-trend?weeks=2", &trend)
		if got := trend.Items[1]; got.NotFixed != 1 || got.Fixed != 0 {
			t.Errorf("beneath the compression library this week is %+v; want its one, untouched by its own fix elsewhere", got)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet,
			hubBuild+"/components/nosuch/code-finding-trend", ""), http.StatusNotFound)
	})
}

// hubMatch is one entry of the component chooser.
type hubMatch struct {
	Product      string `json:"product"`
	Component    string `json:"component"`
	Issues       *int   `json:"issues"`
	CodeFindings *int   `json:"code_findings"`
}

func TestTheChooserCountsEachFamilyOnlyWhereTheReaderReadsIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		at := func(n *int) int {
			if n == nil {
				return -1
			}
			return *n
		}
		for _, c := range []struct {
			who          string
			term         string
			issues, code int
		}{
			{"code-finding-handler", "mine", 1, 1},
			{"security-testing-reader", "MINE", -1, 1},
			{"reader", "mine", 1, -1},
			{"private", "libmine", 1, -1},
			{"code-finding-handler", "zlib", 0, 1},
			{"code-finding-handler", "sonic", 0, 1},
		} {
			var got struct {
				Items []hubMatch `json:"items"`
			}
			httpapitest.Read(t, r, c.who, "/v1/components?q="+c.term, &got)
			if len(got.Items) != 1 || got.Items[0].Product != "mine" {
				t.Errorf("%s finds %+v for %q; want one source package in mine", c.who, got.Items, c.term)
				continue
			}
			if one := got.Items[0]; at(one.Issues) != c.issues || at(one.CodeFindings) != c.code {
				t.Errorf("%s reads %s with %d issues and %d code findings; want %d and %d (-1 is absent)",
					c.who, one.Component, at(one.Issues), at(one.CodeFindings), c.issues, c.code)
			}
		}
		// The exact name leads, and a product read nothing in is not searched.
		var got struct {
			Items []hubMatch `json:"items"`
		}
		httpapitest.Read(t, r, "code-finding-handler", "/v1/components?q=mine-src", &got)
		if len(got.Items) != 1 || got.Items[0].Component != "mine-src" {
			t.Errorf("the source's own name finds %+v; want mine-src", got.Items)
		}
		httpapitest.Read(t, r, "approver", "/v1/components?q=mine", &got)
		if len(got.Items) != 0 {
			t.Errorf("somebody reading nothing finds %+v", got.Items)
		}
	})
}

// hubTree is the tree's first screen with code findings counted.
func hubTree(t *testing.T, r *httpapitest.Reach) (hubNode, map[string][2]int) {
	t.Helper()
	var top struct {
		Root  hubNode   `json:"root"`
		Items []hubNode `json:"items"`
	}
	httpapitest.Read(t, r, "security-testing-reader", hubBuild+"/components?code_findings=true", &top)
	items := map[string][2]int{}
	for _, node := range top.Items {
		items[node.Component] = node.counts()
	}
	return top.Root, items
}

// hubNotFixed is the code findings not fixed this week at and under a
// component, by the trend.
func hubNotFixed(t *testing.T, r *httpapitest.Reach, component string) int {
	t.Helper()
	var trend struct {
		Items []struct {
			NotFixed int `json:"not_fixed"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, "security-testing-reader", hubBuild+"/components/"+component+"/code-finding-trend?weeks=1", &trend)
	if len(trend.Items) != 1 {
		t.Fatalf("one week is %d points", len(trend.Items))
	}
	return trend.Items[0].NotFixed
}

func TestUnderTheRootIsTheWholeBuildWhereNoEdgeLeavesTheRoot(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// No edge from the root: the library and its tools hang from
		// nothing, and the root adopts them.
		httpapitest.HubCodeFindingsUnder(t, r, []graph.Dependency{
			{Parent: httpapitest.HubLib, Child: httpapitest.HubZlib},
		})
		all := []string{"clang-tidy/leak", "cppcheck/bad", "semgrep/bad"}
		root, items := hubTree(t, r)
		if got := root.counts(); got != [2]int{1, 3} {
			t.Errorf("the root carries %v; want 1 on it and the build's 3 beneath", got)
		}
		if got := items["libmine1"]; got != [2]int{1, 2} {
			t.Errorf("the adopted library carries %v; want 1 on it and 2 beneath", got)
		}
		got := hubQueueOf(t, r, "security-testing-reader", "?beneath=sonic-image&branch_or_tag=master&variant=broadcom")
		if !sameRules(got.rules(), all) || got.Total != 3 {
			t.Errorf("beneath the root lists %v, %d in all; want the build's three, as its badge counts", got.rules(), got.Total)
		}
		if got := hubNotFixed(t, r, "sonic-image"); got != 3 {
			t.Errorf("the root's trend counts %d not fixed; want the build's three", got)
		}
	})
}

func TestACodeFindingOnAFormerRootIsOnTheBuild(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		// The root is scanned again at a new version and no run has placed
		// anything since: semgrep's code finding stays on sonic-image 1.0.
		httpapitest.HubRootRescanned(t, r)
		root, _ := hubTree(t, r)
		if got := root.counts(); got != [2]int{1, 3} {
			t.Errorf("the rescanned root carries %v; want its former root's 1 on it and the build's 3 beneath", got)
		}
		build := "&branch_or_tag=master&variant=broadcom"
		got := hubQueueOf(t, r, "security-testing-reader", "?beneath=sonic-image"+build)
		if !sameRules(got.rules(), []string{"clang-tidy/leak", "cppcheck/bad", "semgrep/bad"}) {
			t.Errorf("beneath the rescanned root lists %v; want the build's three", got.rules())
		}
		if got := hubQueueOf(t, r, "security-testing-reader", "?component=sonic-image"); !sameRules(got.rules(), []string{"semgrep/bad"}) {
			t.Errorf("the rescanned root's own lists %v; want semgrep's, on the former root", got.rules())
		}
		var counted hubCounted
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/components/sonic-image/code-finding-counts", &counted)
		for _, each := range counted.Series {
			want := 0
			if each.Series == "semgrep/default" {
				want = 1
			}
			if each.States["open"] != want || each.Unplaced != want {
				t.Errorf("the rescanned root in %s counts %d open and %d unplaced; want %d of each",
					each.Series, each.States["open"], each.Unplaced, want)
			}
		}
		var found struct {
			Items []hubMatch `json:"items"`
		}
		httpapitest.Read(t, r, "code-finding-handler", "/v1/components?q=sonic", &found)
		if len(found.Items) != 1 || found.Items[0].CodeFindings == nil || *found.Items[0].CodeFindings != 1 {
			t.Errorf("the chooser finds %+v for the rescanned root; want its one code finding", found.Items)
		}
		if got := hubNotFixed(t, r, "sonic-image"); got != 3 {
			t.Errorf("the rescanned root's trend counts %d not fixed; want the build's three", got)
		}
	})
}

func TestANameReachesOnlyWhatTheProductsBuildsShip(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		// The other product ships the hub library's source under a binary
		// name this product never ships.
		httpapitest.HubTheirsShipsTheSource(t, r)
		if got := hubQueueOf(t, r, "security-testing-reader", "?component=libtheirs"); got.Total != 0 || len(got.Items) != 0 {
			t.Errorf("a name only another product ships lists %v here; want nothing", got.rules())
		}
		var counted hubCounted
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/components/libtheirs/code-finding-counts", &counted)
		for _, each := range counted.Series {
			if each.States["open"] != 0 {
				t.Errorf("a name only another product ships counts %d open in %s; want none", each.States["open"], each.Series)
			}
		}
		if got := hubQueueOf(t, r, "security-testing-reader", "?component=mine-src"); !sameRules(got.rules(), []string{"clang-tidy/leak"}) {
			t.Errorf("the source's own name lists %v; want the library's code finding", got.rules())
		}
	})
}

func TestUnplacedCountsOnlyWhatIsOnTheBuildItself(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		// A binary built from a source named as the root is, from a
		// repository of its own: the root's name reaches it, and a code
		// finding on it is placed, never on the build itself.
		tools := graph.Described{
			Purl: "pkg:deb/debian/sonic-tools@1.0", Name: "sonic-tools", Version: "1.0",
			UpstreamName: "sonic-image", UpstreamVersion: "1.0", Repository: "https://github.com/acme/sonic",
		}
		root := httpapitest.HubRoot
		r.ScanAt(t, httpapitest.SeededBuild, "hub-sonic-tools", graph.Snapshot{
			Root: root,
			Components: []graph.Described{
				httpapitest.HubLib, httpapitest.HubTools, httpapitest.HubZlib, tools,
			},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: httpapitest.HubLib}, {Parent: root, Child: httpapitest.HubTools},
				{Parent: httpapitest.HubLib, Child: httpapitest.HubZlib}, {Parent: root, Child: tools},
			},
		}, nil)
		httpapitest.ApplyRunIn(t, r, "gcc/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.RunInRepository("gcc", "https://github.com/acme/sonic", "tool.c", 3))
		var counted hubCounted
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/components/sonic-image/code-finding-counts", &counted)
		want := map[string][2]int{"semgrep/default": {1, 1}, "gcc/default": {1, 0}}
		for _, each := range counted.Series {
			if got := [2]int{each.States["open"], each.Unplaced}; got != want[each.Series] {
				t.Errorf("the root's name in %s counts %d open and %d unplaced; want %v",
					each.Series, got[0], got[1], want[each.Series])
			}
		}
	})
}
