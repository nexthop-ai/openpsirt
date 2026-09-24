// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package build_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// line is one line of a YAML file: how far it is indented and what it says.
type line struct {
	indent int
	text   string
}

// yamlLines is the non-blank, non-comment lines of text.
func yamlLines(text string) []line {
	var lines []line
	for _, raw := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, line{indent: len(raw) - len(strings.TrimLeft(raw, " ")), text: trimmed})
	}
	return lines
}

// under is the lines nested beneath the key at path, a key per level.
func under(lines []line, path ...string) []line {
	scope, from := lines, -1
	for _, key := range path {
		found := false
		for i := from + 1; i < len(scope); i++ {
			if from >= 0 && scope[i].indent <= scope[from].indent {
				break
			}
			if scope[i].text == key+":" {
				from, found = i, true
				break
			}
		}
		if !found {
			return nil
		}
	}
	var nested []line
	for _, l := range scope[from+1:] {
		if l.indent <= scope[from].indent {
			break
		}
		nested = append(nested, l)
	}
	return nested
}

// holds reports whether a list beneath a key carries item.
func holds(list []line, item string) bool {
	for _, l := range list {
		if l.text == "- "+item {
			return true
		}
	}
	return false
}

// vetGaps is every way the linter configuration in text stops covering what
// go vet does. The gate runs no go vet of its own, so the linter's govet is
// the whole of that analysis.
func vetGaps(text string) []string {
	lines := yamlLines(text)
	var gaps []string
	if !holds(under(lines, "linters", "enable"), "govet") {
		gaps = append(gaps, "govet is not an enabled linter")
	}
	// Any govet settings at all can narrow the analyzers: disable, enable,
	// disable-all. Reaching for one is a decision the vet coverage rides on,
	// so it is refused here rather than read.
	if under(lines, "linters", "settings", "govet") != nil {
		gaps = append(gaps, "govet has settings of its own, which can narrow the analyzers go vet runs")
	}
	for _, l := range under(lines, "run") {
		if l.text == "tests: false" {
			gaps = append(gaps, "test files are excluded, and go vet reads them")
		}
	}
	if !holds(under(lines, "run", "build-tags"), "measure") {
		gaps = append(gaps, `the "measure" tag is not passed, so nothing compiles the measurement file`)
	}
	// The default skips any file marked generated, which go vet reads.
	exclusions := under(lines, "linters", "exclusions")
	generated := false
	for _, l := range exclusions {
		switch {
		case l.text == "generated: disable":
			generated = true
		case strings.Contains(l.text, "govet") || strings.Contains(l.text, "_test"):
			gaps = append(gaps, "an exclusion takes files or findings away from govet: "+l.text)
		}
	}
	if !generated {
		gaps = append(gaps, "generated files are excluded, and go vet reads them")
	}
	return gaps
}

// The linter is the only vet the gate runs.
func TestTheLinterRunsEveryCheckGoVetDoes(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("..", "..", ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(yamlLines(string(text))) == 0 {
		t.Fatal("the linter configuration is empty, so this checked nothing")
	}
	for _, gap := range vetGaps(string(text)) {
		t.Error(gap)
	}
}

// The check, given a configuration that covers go vet and one that narrows
// it every way it can.
func TestANarrowedVetIsReportedAndACompleteOneIsNot(t *testing.T) {
	const complete = `version: "2"
run:
  build-tags:
    - measure
linters:
  default: none
  exclusions:
    generated: disable
  enable:
    - govet
    - staticcheck
  settings:
    errcheck:
      exclude-functions:
        - (io.Closer).Close
`
	if gaps := vetGaps(complete); len(gaps) != 0 {
		t.Errorf("a configuration covering go vet was reported: %v", gaps)
	}

	const narrowed = `version: "2"
run:
  tests: false
  build-tags:
    - integration
linters:
  default: none
  enable:
    - staticcheck
  settings:
    govet:
      disable:
        - printf
`
	if gaps := vetGaps(narrowed); len(gaps) != 5 {
		t.Errorf("reported %d of the five ways this narrows go vet: %v", len(gaps), gaps)
	}

	const excluding = `version: "2"
run:
  build-tags:
    - measure
linters:
  default: none
  exclusions:
    generated: disable
    rules:
      - path: _test.go
        linters:
          - govet
  enable:
    - govet
`
	if gaps := vetGaps(excluding); len(gaps) != 2 {
		t.Errorf("an exclusion rule over govet and test files was reported as %v", gaps)
	}
}
