// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// spelledOut matches a decision correlated to a finding's place written out
// by hand rather than composed from DecisionAt.
var spelledOut = regexp.MustCompile(`de\.place_identity\s*=\s*f\.place_identity`)

// correlationsSpelledOut is every line of Go source that correlates a
// decision to a finding's place by hand, as "file:line".
func correlationsSpelledOut(name, source string) []string {
	var found []string
	for i, line := range strings.Split(source, "\n") {
		if spelledOut.MatchString(line) {
			found = append(found, name+":"+strconv.Itoa(i+1))
		}
	}
	return found
}

func TestTheDetectorFindsACorrelationSpelledOut(t *testing.T) {
	if got := correlationsSpelledOut("a.go",
		"WHERE de.vulnerability_id = f.vulnerability_id\n  AND de.place_identity = f.place_identity"); len(got) != 1 || got[0] != "a.go:2" {
		t.Errorf("a correlation written out was reported as %v", got)
	}
	if got := correlationsSpelledOut("b.go", `WHERE `+"`+DecisionAt(\"?\")+`"); len(got) != 0 {
		t.Errorf("a composed correlation was reported as %v", got)
	}
}

func TestEveryDecisionIsCorrelatedToItsFindingThroughOneSpelling(t *testing.T) {
	// A place identity carries no product, so a copy of the correlation that
	// drops the product matches a decision made in every other product that
	// ships the same component. One spelling is what keeps a copy from
	// drifting that way.
	root := filepath.Join("..")
	examined := 0
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "migrations" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		examined++
		spelled := correlationsSpelledOut(path, string(source))
		// The one spelling itself, and nothing else in its file.
		if strings.HasSuffix(filepath.ToSlash(path), "finding/narrow.go") && len(spelled) > 0 {
			spelled = spelled[1:]
		}
		found = append(found, spelled...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if examined == 0 {
		t.Fatal("no Go source was found, so this checked nothing")
	}
	for _, at := range found {
		t.Errorf("%s correlates a decision to a finding by hand; compose finding.DecisionAt", at)
	}
}
