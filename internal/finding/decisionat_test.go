// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// samePlace matches two rows compared by place identity, in either order, with
// or without quotes around either side, capturing both aliases.
var samePlace = regexp.MustCompile(`"?(\w+)"?\."?place_identity"?\s*=\s*"?(\w+)"?\."?place_identity\b`)

// decidedIssue matches a finding's issue compared with the issue a decision is
// read as, in either order.
var decidedIssue = regexp.MustCompile(`"?\bdv"?\."?issue_id"?\s*=\s*"?\w+"?\."?vulnerability_id\b|` +
	`"?\w+"?\."?vulnerability_id"?\s*=\s*"?dv"?\."?issue_id\b`)

// notADecisionAtAFinding is the place comparisons that are not a decision
// correlated to a finding, by file and by the pair of aliases compared, with
// what each compares.
var notADecisionAtAFinding = map[string]map[[2]string]string{
	"finding/disclaim.go": {
		{"f", "lt"}: "two rows of one build at one place",
	},
	"finding/register.go": {
		{"d3", "de"}: "a decision against another of its product at its place",
		{"d2", "de"}: "a decision against another of its product at its place",
	},
	"triage/reaffirm_many.go": {
		{"de", "newer"}: "a decision against another of its product at its place",
	},
}

// pairOf is two aliases in a fixed order, so a comparison reads the same
// whichever side it was written on.
func pairOf(a, b string) [2]string {
	if b < a {
		a, b = b, a
	}
	return [2]string{a, b}
}

// correlation is one place comparison or decided-issue comparison found in a
// line of source.
type correlation struct {
	at    string
	pair  [2]string
	issue bool
}

// correlationsSpelledOut is every comparison in Go source that correlates a
// decision with a finding by hand, or compares two rows by place, with where
// it is as "file:line".
func correlationsSpelledOut(name, source string) []correlation {
	var found []correlation
	for i, line := range strings.Split(source, "\n") {
		at := name + ":" + strconv.Itoa(i+1)
		for _, match := range samePlace.FindAllStringSubmatch(line, -1) {
			found = append(found, correlation{at: at, pair: pairOf(match[1], match[2])})
		}
		if decidedIssue.MatchString(line) {
			found = append(found, correlation{at: at, issue: true})
		}
	}
	return found
}

func TestTheDetectorFindsACorrelationSpelledOut(t *testing.T) {
	spelled := []string{
		"AND de.place_identity = f.place_identity",
		"AND f.place_identity = de.place_identity",
		"AND f2.place_identity = de.place_identity",
		`ON "pd".place_identity = f.place_identity`,
		`AND "fc"."place_identity" = "de"."place_identity"`,
		"AND dv.issue_id = f.vulnerability_id",
		"WHERE fc.vulnerability_id = dv.issue_id",
		`ON "pf"."vulnerability_id" = "dv"."issue_id"`,
	}
	for _, line := range spelled {
		if got := correlationsSpelledOut("a.go", "x\n"+line); len(got) != 1 || got[0].at != "a.go:2" {
			t.Errorf("%q was reported as %v", line, got)
		}
	}
	composed := []string{
		"WHERE `+DecisionAt(\"?\")+`",
		"WHERE `+finding.DecisionAtPlace(\"f\")+`",
		"ColumnExpr(`dv.issue_id AS \"vulnerability_id\"`)",
		`JOIN "vulnerability" AS "dv" ON "dv"."id" = "de"."vulnerability_id"`,
		`JOIN "finding" AS "f" ON "f"."vulnerability_id" = "ri"."issue_id"`,
		`Where("de.place_identity IN (?)", bun.List(identities))`,
	}
	for _, line := range composed {
		if got := correlationsSpelledOut("b.go", line); len(got) != 0 {
			t.Errorf("%q was reported as %v", line, got)
		}
	}
}

func TestEveryDecisionIsCorrelatedToItsFindingThroughOneSpelling(t *testing.T) {
	// A place identity carries no product, so a copy of the correlation that
	// drops the product matches a decision made in every other product that
	// ships the same component. One spelling is what keeps a copy from
	// drifting that way.
	root := filepath.Join("..")
	examined, compared := 0, 0
	excepted := map[string]map[[2]string]bool{}
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
		source, err := os.ReadFile(path) //nolint:gosec // G304: this repository's own source
		if err != nil {
			return err
		}
		examined++
		name := filepath.ToSlash(path)
		for _, each := range correlationsSpelledOut(name, string(source)) {
			compared++
			if !each.issue {
				if file, ok := exceptionFile(name); ok {
					if _, listed := notADecisionAtAFinding[file][each.pair]; listed {
						if excepted[file] == nil {
							excepted[file] = map[[2]string]bool{}
						}
						excepted[file][each.pair] = true
						continue
					}
				}
			}
			found = append(found, each.at)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if examined == 0 {
		t.Fatal("no Go source was found, so this checked nothing")
	}
	if compared == 0 {
		t.Fatal("no place comparison was found anywhere, so the detector read nothing")
	}
	for _, at := range found {
		t.Errorf("%s correlates a decision to a finding by hand; compose finding.DecisionAt or its family", at)
	}
	var stale []string
	for file, pairs := range notADecisionAtAFinding {
		for pair := range pairs {
			if !excepted[file][pair] {
				stale = append(stale, file+" "+pair[0]+"/"+pair[1])
			}
		}
	}
	sort.Strings(stale)
	for _, each := range stale {
		t.Errorf("%s is listed as compared by place and no longer is; remove it from the list", each)
	}
}

// exceptionFile is the key a path is listed under, if any.
func exceptionFile(path string) (string, bool) {
	for file := range notADecisionAtAFinding {
		if strings.HasSuffix(path, "/"+file) {
			return file, true
		}
	}
	return "", false
}
