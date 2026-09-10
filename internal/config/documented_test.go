package config

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every setting this reads is documented, and everything documented is read.
//
// **A setting nobody wrote down is one an operator finds by reading the
// source**, which for a deployment they run in production is not an answer.
// The other direction is worse: a documented setting that nothing reads is a
// line somebody follows, sets, restarts for, and gets no change from — and
// there is nothing in the running system to tell them so.
//
// Both were true when this was written, by care alone. This is what keeps them
// true, and it is the same shape as the checks that hold the design tokens and
// the API reference to the code.
//
// The source is read rather than the package being asked, because the names
// are literals at their call sites: that is what makes them greppable, and a
// list built beside them to satisfy a test is a second list to keep right.
func TestEverySettingIsWrittenDown(t *testing.T) {
	read := regexp.MustCompile(`(?:env|r\.duration|r\.number|r\.boolean)\("([A-Z0-9_]+)"`)
	reads := map[string]bool{}
	// Named one by one rather than walked: every path here is a literal, which
	// is what keeps a file-reading test from being a file-reading primitive.
	config, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	ingest, err := os.ReadFile("ingest.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range [][]byte{config, ingest} {
		for _, found := range read.FindAllStringSubmatch(string(source), -1) {
			reads[found[1]] = true
		}
	}
	if len(reads) == 0 {
		t.Fatal("no settings were found in the source, so this checked nothing")
	}

	page, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	written := map[string]bool{}
	for _, found := range regexp.MustCompile(`OPENPSIRT_([A-Z0-9_]+)`).
		FindAllStringSubmatch(string(page), -1) {
		written[found[1]] = true
	}

	var missing, invented []string
	for name := range reads {
		if !written[name] {
			missing = append(missing, envPrefix+name)
		}
	}
	for name := range written {
		if !reads[name] {
			invented = append(invented, envPrefix+name)
		}
	}
	sort.Strings(missing)
	sort.Strings(invented)
	if len(missing) > 0 {
		t.Errorf("read and not documented, so an operator would have to find %s in the source:\n  %s",
			plural(len(missing)), strings.Join(missing, "\n  "))
	}
	if len(invented) > 0 {
		t.Errorf("documented and read by nothing, so setting %s changes nothing and says nothing:\n  %s",
			plural(len(invented)), strings.Join(invented, "\n  "))
	}
}

func plural(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
