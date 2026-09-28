// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"net/url"
	"os"
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

// Every address a notification opens the review queue at asks for what the
// queue reads.
//
// The queue reads its narrowing from the address, and a parameter it does not
// read opens it on its default: the approver queue, which leaves out the
// reader's own claims. An alert telling somebody their claim was sent back
// would then open on everybody else's work.
func TestAQueueLinkAsksForWhatTheQueueReads(t *testing.T) {
	screen, err := os.ReadFile("../../web/src/screens/Queue.tsx")
	if err != nil {
		t.Fatal(err)
	}
	read := map[string]bool{}
	for _, found := range regexp.MustCompile(`params\.get\("([a-z]+)"\)`).
		FindAllStringSubmatch(string(screen), -1) {
		read[found[1]] = true
	}
	if len(read) == 0 {
		t.Fatal("the queue reads no parameter, so this checked nothing")
	}

	linked := regexp.MustCompile(`"/review-queue(\?[^"]*)?"`)
	links := 0
	for _, file := range []string{"stale.go", "lapsed.go"} {
		source, err := os.ReadFile(file) //nolint:gosec // G304: every path here is a literal
		if err != nil {
			t.Fatal(err)
		}
		for _, found := range linked.FindAllStringSubmatch(string(source), -1) {
			links++
			query, err := url.ParseQuery(strings.TrimPrefix(found[1], "?"))
			if err != nil {
				t.Errorf("%s: %s: %v", file, found[0], err)
				continue
			}
			for key := range query {
				if !read[key] {
					t.Errorf("%s links %s, and the queue does not read %q", file, found[0], key)
				}
			}
		}
	}
	if links == 0 {
		t.Fatal("no notification links the queue, so this checked nothing")
	}
}
