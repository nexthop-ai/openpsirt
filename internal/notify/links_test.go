// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The window a condition's link asks for is one the sheet it opens offers.
//
// A link that asks for more is refused and falls back. The address parser
// bounds what it will take and a sheet that cannot read the number opens on
// its own default — which for the report behind the unagreed-risk condition is
// a quarter, while the count that raised it covers the whole record. An
// administrator was told a control had failed and shown a page that could not
// contain the failure at any setting the screen offered.
//
// Read out of the two files rather than shared as a constant, because there is
// no constant either language can see. Both are literals at their own call
// site, which is what makes them greppable, and a third spelling kept beside
// them to satisfy a test would be a third thing to keep right.
func TestAConditionAsksForAWindowItsReportOffers(t *testing.T) {
	asked := regexp.MustCompile(`/reports/([a-z-]+)\?days=" \+ ([a-zA-Z]+)`)
	source, err := os.ReadFile("health.go")
	if err != nil {
		t.Fatal(err)
	}
	links := asked.FindAllStringSubmatch(string(source), -1)
	if len(links) == 0 {
		t.Fatal("no condition links a report with a window, so this checked nothing")
	}

	// The constant the link is built from, so the test reads the number that
	// travels rather than one written here beside it.
	named := regexp.MustCompile(`(?m)^const ([a-zA-Z]+) = "(\d+)"$`)
	values := map[string]string{}
	for _, found := range named.FindAllStringSubmatch(string(source), -1) {
		values[found[1]] = found[2]
	}

	// The sheet each report slug names, by the address the catalog gives it.
	sheets := map[string]string{"rubber-stamp": "../../web/src/screens/reports/Scrutiny.tsx"}
	offers := regexp.MustCompile(`const WINDOWS = \[([0-9, ]+)\]`)

	for _, link := range links {
		slug, constant := link[1], link[2]
		days, spelled := values[constant]
		if !spelled {
			t.Errorf("the link to %s asks for %s, which is not a number in this file",
				slug, constant)
			continue
		}
		sheet, known := sheets[slug]
		if !known {
			t.Errorf("a condition links /reports/%s with a window and this test does "+
				"not know which sheet that is", slug)
			continue
		}
		screen, err := os.ReadFile(sheet) //nolint:gosec // G304: every path here is a literal above
		if err != nil {
			t.Fatal(err)
		}
		windows := offers.FindStringSubmatch(string(screen))
		if windows == nil {
			t.Fatalf("%s no longer declares the windows it offers, so this checked nothing",
				sheet)
		}
		found := false
		for _, each := range strings.Split(windows[1], ",") {
			if strings.TrimSpace(each) == days {
				found = true
			}
		}
		if !found {
			t.Errorf("the condition opens /reports/%s at %s days and the sheet offers %s: "+
				"a window it will not take falls back to the sheet's own default, which is "+
				"the narrowing the link exists to get past", slug, days, windows[1])
		}
	}
}

// Every address a notification or an act opens is a screen the web application
// has, asking only for what that screen reads.
//
// An address the router does not know redirects to the front page, and a
// parameter the screen does not read opens it on its default. Either way
// somebody told about a thing is shown something else, silently.
func TestANotificationLinkOpensAScreenWithWhatItReads(t *testing.T) {
	app, err := os.ReadFile("../../web/src/app/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	table := regexp.MustCompile(`(?s)export const ROUTES = \{(.*?)\} as const`).
		FindSubmatch(app)
	if table == nil {
		t.Fatal("App.tsx declares no route table, so this checked nothing")
	}
	routes := map[string]bool{}
	for _, found := range regexp.MustCompile("[\"`](/[a-z-]*|\\$\\{build\\})").
		FindAllSubmatch(table[1], -1) {
		first := strings.TrimPrefix(string(found[1]), "/")
		if first == "${build}" {
			first = "products"
		}
		routes[first] = true
	}
	if len(routes) == 0 {
		t.Fatal("the route table names no address, so this checked nothing")
	}

	// The screens whose parameters a link sets, by the first part of the
	// address. A screen missing here is checked for its route alone.
	screens := map[string]string{
		"review-queue": "../../web/src/screens/Queue.tsx",
		"work":         "../../web/src/screens/Work.tsx",
	}
	reads := map[string]map[string]bool{}
	for first, file := range screens {
		screen, err := os.ReadFile(file) //nolint:gosec // G304: every path here is a literal above
		if err != nil {
			t.Fatal(err)
		}
		read := map[string]bool{}
		for _, found := range regexp.MustCompile(`params\.get\("([a-z]+)"\)`).
			FindAllStringSubmatch(string(screen), -1) {
			read[found[1]] = true
		}
		if len(read) == 0 {
			t.Fatalf("%s reads no parameter, so this checked nothing", file)
		}
		reads[first] = read
	}

	here, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	there, err := filepath.Glob("../httpapi/*.go")
	if err != nil {
		t.Fatal(err)
	}
	linked := regexp.MustCompile(`Link:\s*(?:fmt\.Sprintf\()?"(/[^"]*)"`)
	links, parameters := 0, 0
	for _, file := range append(here, there...) {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		source, err := os.ReadFile(file) //nolint:gosec // G304: every path here is a glob of this tree
		if err != nil {
			t.Fatal(err)
		}
		for _, found := range linked.FindAllStringSubmatch(string(source), -1) {
			links++
			address, query, _ := strings.Cut(found[1], "?")
			first, _, _ := strings.Cut(strings.TrimPrefix(address, "/"), "/")
			if !routes[first] {
				t.Errorf("%s links %s, and the web application has no /%s", file, found[1], first)
				continue
			}
			read, known := reads[first]
			if !known || query == "" {
				continue
			}
			asked, err := url.ParseQuery(strings.ReplaceAll(query, "%s", "v"))
			if err != nil {
				t.Errorf("%s: %s: %v", file, found[1], err)
				continue
			}
			for key := range asked {
				parameters++
				if !read[key] {
					t.Errorf("%s links %s, and the screen there does not read %q", file, found[1], key)
				}
			}
		}
	}
	if links == 0 || parameters == 0 {
		t.Fatal("no link sets a parameter a screen reads, so this checked nothing")
	}
}
