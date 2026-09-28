// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weblink_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// The web application's route table, which the interface's router is built
// from. Read from its file rather than copied, because a copy is a second
// definition that goes stale.
const table = "../../web/src/app/routes.json"

// route is one entry of the table: the pattern the router matches and the
// query parameters a link may set on it.
type route struct {
	Path  string   `json:"path"`
	Query []string `json:"query"`
}

func routes(t *testing.T) map[string]route {
	t.Helper()
	raw, err := os.ReadFile(table)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]route
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v", table, err)
	}
	if len(out) == 0 {
		t.Fatalf("%s names no route, so this checked nothing", table)
	}
	return out
}

// unrouted says why an address is not one the web application answers, or
// nothing where it is. A segment of the pattern starting with a colon matches
// any one non-empty segment; everything else matches itself. A fragment is the
// screen's business and is not checked.
func unrouted(table map[string]route, address string) string {
	address, _, _ = strings.Cut(address, "#")
	path, query, _ := strings.Cut(address, "?")
	asked, err := url.ParseQuery(query)
	if err != nil {
		return "its query does not parse: " + err.Error()
	}
	for _, each := range table {
		if !matches(each.Path, path) {
			continue
		}
		for key := range asked {
			known := false
			for _, listed := range each.Query {
				known = known || listed == key
			}
			if !known {
				return "the screen at " + each.Path + " does not read " + strconv.Quote(key)
			}
		}
		return ""
	}
	return "no route matches " + path
}

func matches(pattern, path string) bool {
	want := strings.Split(pattern, "/")
	got := strings.Split(path, "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if strings.HasPrefix(want[i], ":") {
			if got[i] == "" {
				return false
			}
			continue
		}
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

// The check an address is held to, with one input it must report and one it
// must not for each way an address goes wrong.
func TestAnAddressIsHeldToTheRouteTable(t *testing.T) {
	known := routes(t)
	for _, tc := range []struct {
		address  string
		reported bool
	}{
		{"/review-queue?mine=1", false},
		{"/review-queue?tab=mine", true},
		{"/assignments", true},
		{"/queue?mine=1", true},
		{"/products/p/streams/s/variants/v/findings/CVE-1/components/c", false},
		{"/products/p/streams/s/variants/v/findings/CVE-1/components/a/b", true},
		{"/products/p/streams/s/variants/v/findings//components/c", true},
		{"/products/p/streams/s/variants/v/tree?at=c", true},
		{"/products/p/streams/s/variants/v/components?at=c", false},
		{"/issues/CVE-1#thread", false},
	} {
		why := unrouted(known, tc.address)
		if tc.reported && why == "" {
			t.Errorf("%s was accepted, and the web application does not answer it", tc.address)
		}
		if !tc.reported && why != "" {
			t.Errorf("%s was reported (%s), and the web application answers it", tc.address, why)
		}
	}
}

// Awkward on purpose: a separator of every kind an address has, so a part
// left unescaped moves a segment or starts a query and fails the match. The
// fragment mark comes last, because everything after it is not checked.
const odd = "a/b c?d&f=g%#e"

// Every address the server builds is one the web application answers, asking
// only for what the screen there reads.
//
// An address the router does not know lands on the not-found screen, and a
// parameter the screen does not read opens it on its default. Either way
// somebody told about a thing is shown something else, silently.
func TestEveryBuiltAddressIsARouteTheApplicationServes(t *testing.T) {
	known := routes(t)
	built := map[string]func() string{
		"Home":                weblink.Home,
		"ReviewQueue":         weblink.ReviewQueue,
		"ReviewQueueMine":     weblink.ReviewQueueMine,
		"ReviewQueueReaffirm": weblink.ReviewQueueReaffirm,
		"Work":                weblink.Work,
		"WorkTeam":            func() string { return weblink.WorkTeam(odd) },
		"WorkPerson":          func() string { return weblink.WorkPerson(odd) },
		"Settings":            weblink.Settings,
		"System":              weblink.System,
		"Obligations":         weblink.Obligations,
		"Claim":               func() string { return weblink.Claim(7) },
		"Decision":            func() string { return weblink.Decision(7) },
		"Issue":               func() string { return weblink.Issue(odd) },
		"ProductFindings":     func() string { return weblink.ProductFindings(odd, odd) },
		"InboxWaiting":        func() string { return weblink.InboxWaiting(odd) },
		"InboxReport":         func() string { return weblink.InboxReport(odd, odd) },
		"Finding":             func() string { return weblink.Finding(odd, odd, odd, odd, odd, odd) },
		"Inventories":         func() string { return weblink.Inventories(odd, odd, odd) },
		"InventoryChanges":    func() string { return weblink.InventoryChanges(odd, odd, odd, 7) },
		"Report":              func() string { return weblink.Report(odd, odd) },
	}

	// Every builder the package exports has a sample above, and every sample
	// names a builder, so one added without a sample fails here rather than
	// going unchecked.
	exported := builders(t)
	for _, name := range exported {
		if _, sampled := built[name]; !sampled {
			t.Errorf("weblink.%s builds an address and nothing here builds one with it", name)
		}
	}
	for name := range built {
		if !contains(exported, name) {
			t.Errorf("a sample is kept for weblink.%s, which the package does not export", name)
		}
	}

	for _, name := range exported {
		build, sampled := built[name]
		if !sampled {
			continue
		}
		address := build()
		if why := unrouted(known, address); why != "" {
			t.Errorf("weblink.%s built %s: %s", name, address, why)
		}
	}
}

// builders is every exported function the package declares, read from its
// source so that a new one is seen without anybody listing it.
func builders(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	set := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(set, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.IsExported() {
				names = append(names, fn.Name.Name)
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("the package exports no builder, so this checked nothing")
	}
	sort.Strings(names)
	return names
}

func contains(list []string, name string) bool {
	for _, each := range list {
		if each == name {
			return true
		}
	}
	return false
}

// handSpelled is every string literal in one Go source file that spells an
// address into the web application: one opening on a segment some route opens
// with, and the front page's "/" where it is handed to the function that makes
// a link absolute. An API path is under /v1, and so is everything joined onto
// one, and a route handed to the API router carries braces, so none of those
// is one.
func handSpelled(name string, source []byte, opening map[string]bool) ([]string, int, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return nil, 0, err
	}
	var found []string
	examined := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		if joined, ok := node.(*ast.BinaryExpr); ok && joined.Op == token.ADD && underAPI(joined) {
			return false
		}
		if call, ok := node.(*ast.CallExpr); ok && linksFront(call) {
			found = append(found, "/")
		}
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		examined++
		text, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.HasPrefix(text, "/") || strings.Contains(text, "{") {
			return true
		}
		first := strings.TrimPrefix(text, "/")
		first, _, _ = strings.Cut(first, "/")
		first, _, _ = strings.Cut(first, "?")
		if opening[first] {
			found = append(found, text)
		}
		return true
	})
	return found, examined, nil
}

// linksFront says whether a call hands the literal "/" to the function that
// makes a path into an absolute link. A bare "/" is too common a string to
// read as an address anywhere else.
func linksFront(call *ast.CallExpr) bool {
	name, ok := call.Fun.(*ast.Ident)
	if !ok || name.Name != "link" {
		return false
	}
	for _, arg := range call.Args {
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `"/"` {
			return true
		}
	}
	return false
}

// underAPI says whether a joined string opens on the API's prefix.
func underAPI(joined *ast.BinaryExpr) bool {
	left := joined.X
	for {
		inner, ok := left.(*ast.BinaryExpr)
		if !ok || inner.Op != token.ADD {
			break
		}
		left = inner.X
	}
	lit, ok := left.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	text, err := strconv.Unquote(lit.Value)
	return err == nil && strings.HasPrefix(text, "/v1/")
}

// openings is the first segment of every route that has one.
func openings(known map[string]route) map[string]bool {
	out := map[string]bool{}
	for _, each := range known {
		first, _, _ := strings.Cut(strings.TrimPrefix(each.Path, "/"), "/")
		if first != "" {
			out[first] = true
		}
	}
	return out
}

func TestAHandSpelledAddressIsFound(t *testing.T) {
	opening := openings(routes(t))
	for _, tc := range []struct {
		source string
		found  bool
	}{
		{`package x; var link = "/review-queue?mine=1"`, true},
		{`package x; var link = "/products/" + product + "/findings"`, true},
		{`package x; var link = fmt.Sprintf("/claims/%d", id)`, true},
		{`package x; var api = "/v1/products/{product}/findings"`, false},
		{`package x; var api = "/findings/{vulnerability}/components/{component}"`, false},
		{`package x; var api = "/v1/products/" + product + "/findings?" + q`, false},
		{`package x; var link = base + "/products/" + product`, true},
		{`package x; var file = "/etc/openpsirt"`, false},
		{`package x; var link = weblink.Claim(id)`, false},
		{`package x; var front = link(baseURL, "/")`, true},
		{`package x; var front = link(baseURL, weblink.Home())`, false},
		{`package x; var parts = strings.Split(path, "/")`, false},
	} {
		found, _, err := handSpelled("x.go", []byte(tc.source), opening)
		if err != nil {
			t.Fatal(err)
		}
		if tc.found != (len(found) > 0) {
			t.Errorf("%s: found %v, and it should have been %v", tc.source, found, tc.found)
		}
	}
}

// No address into the web application is spelled anywhere in the server but
// here. One spelled by hand is one nothing holds to the route table.
func TestNoAddressIsSpelledOutsideThisPackage(t *testing.T) {
	opening := openings(routes(t))
	files, literals := 0, 0
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if filepath.Base(path) == "weblink" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path) //nolint:gosec // G304: every path is a walk of this tree
			if err != nil {
				return err
			}
			found, examined, err := handSpelled(path, source, opening)
			if err != nil {
				return err
			}
			files++
			literals += examined
			for _, each := range found {
				t.Errorf("%s spells %s by hand; build it with a weblink function", path, each)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files == 0 || literals == 0 {
		t.Fatal("no Go source or no string in it was read, so this checked nothing")
	}
}
