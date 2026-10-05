// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	// chartSets matches a variable the chart's Deployment sets.
	chartSets = regexp.MustCompile(`(?m)^\s*- name: (OPENPSIRT_[A-Z0-9_]+)\s*$`)
	// tableNames matches a variable named in a row of the values table.
	tableNames = regexp.MustCompile("(?m)^\\|[^|\\n]*\\|\\s*`(OPENPSIRT_[A-Z0-9_]+)`\\s*\\|")
)

// valuesSection is the Helm page's table of values and the variables they set.
const valuesSection = "## Values and variables"

// chartVariableProblems joins the variables a chart template sets against the
// ones a page's values table lists, in both directions. It returns how many of
// each it found, so a caller can tell an empty join from a clean one.
func chartVariableProblems(template, page string) (problems []string, set, listed int) {
	setBy := map[string]bool{}
	for _, m := range chartSets.FindAllStringSubmatch(template, -1) {
		setBy[m[1]] = true
	}
	table := ""
	if at := strings.Index(page, valuesSection); at >= 0 {
		table = page[at+len(valuesSection):]
		if next := strings.Index(table, "\n## "); next >= 0 {
			table = table[:next]
		}
	}
	listedIn := map[string]bool{}
	for _, m := range tableNames.FindAllStringSubmatch(table, -1) {
		listedIn[m[1]] = true
	}
	for name := range setBy {
		if !listedIn[name] {
			problems = append(problems, name+" is set by the chart and not listed under "+valuesSection)
		}
	}
	for name := range listedIn {
		if !setBy[name] {
			problems = append(problems, name+" is listed under "+valuesSection+" and the chart does not set it")
		}
	}
	sort.Strings(problems)
	return problems, len(setBy), len(listedIn)
}

func TestEveryVariableTheChartSetsIsListedOnTheHelmPage(t *testing.T) {
	root := filepath.Join("..", "..")
	template, err := os.ReadFile(filepath.Join(root, "deploy", "helm", "openpsirt", "templates", "deployment.yaml")) //nolint:gosec // this repository's own chart
	if err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(filepath.Join(root, "docs", "helm.md")) //nolint:gosec // this repository's own documents
	if err != nil {
		t.Fatal(err)
	}
	problems, set, listed := chartVariableProblems(string(template), string(page))
	if set == 0 {
		t.Fatal("no variable the chart sets was found, so this checked nothing")
	}
	if listed == 0 {
		t.Fatal("no variable was found in the Helm page's values table, so this checked nothing")
	}
	for _, problem := range problems {
		t.Error(problem)
	}
}

func TestChartVariableProblemsReportsEachDirection(t *testing.T) {
	template := "env:\n  - name: OPENPSIRT_ONE\n    value: x\n  - name: OPENPSIRT_TWO\n    value: y\n"
	page := "# Helm\n\n" + valuesSection + "\n\n| Value | Variable |\n|---|---|\n" +
		"| `one` | `OPENPSIRT_ONE` |\n| `three` | `OPENPSIRT_THREE` |\n\n## After\n\n| `two` | `OPENPSIRT_TWO` |\n"
	problems, set, listed := chartVariableProblems(template, page)
	if set != 2 || listed != 2 {
		t.Fatalf("found %d set and %d listed, want 2 and 2", set, listed)
	}
	want := []string{
		"OPENPSIRT_THREE is listed under " + valuesSection + " and the chart does not set it",
		"OPENPSIRT_TWO is set by the chart and not listed under " + valuesSection,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}

	clean := "# Helm\n\n" + valuesSection + "\n\n| `one` | `OPENPSIRT_ONE` |\n| `two` | `OPENPSIRT_TWO` |\n"
	if problems, _, _ := chartVariableProblems(template, clean); len(problems) != 0 {
		t.Fatalf("a table listing exactly what the chart sets was reported: %v", problems)
	}
}
