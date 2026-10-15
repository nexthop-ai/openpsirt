// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command unclaimed reports requirements that no design document names.
//
// The chain this repository is organized around runs one way: code satisfies a
// design document, a design document names the requirements it implements, and
// a requirement says what the product must cover. That chain is what makes an
// audit possible, and this checks that it is whole. A requirement no design
// document names can still be cited by code — behavior that runs, is reasoned
// about in comments, and appears in no document describing the system.
//
// A requirement that is not built yet is not exempt. The design document for
// its area says so, in words, the way several already do — "nothing is purged
// and nothing is partitioned", "the install and operate guides are not
// written". That is the difference between a gap somebody rediscovers by
// clicking and a plan somebody can read.
//
// Ranges count. A document that says "satisfies REQ-01 to REQ-03" has named
// all three.
//
// Deliberately crude, like the unreachable gate beside it: it matches
// identifiers rather than understanding them, so naming a requirement anywhere
// in a design document counts as naming it. That errs toward saying nothing,
// which is the right direction for a check that fails a build — and it means
// the rule that naming a requirement means describing it is a person's to
// enforce, not this program's.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Everything is read through the working directory as a file system rather
// than by path. A build-time tool that reads wherever it is pointed is a shape
// worth not having, and stating it this way makes it structural instead of a
// convention somebody has to keep — the analysis gate is right to complain
// about the other spelling.
var here = os.DirFS(".")

// Section 3 of REQUIREMENTS.md holds the requirements. Section 4 and after hold
// what is out of scope and what was rejected, neither of which a design
// document is expected to implement.
const (
	inForceFrom = "## 3. Requirements"
	inForceTo   = "## 4. Out of scope"
)

// A row in the requirements table: "| REQ-01 | ... | ... |".
var row = regexp.MustCompile(`(?m)^\| ([A-Z]{3}-\d+) \| (.*)$`)

// An identifier anywhere in prose, and the range form the documents use.
var (
	one   = regexp.MustCompile(`\b[A-Z]{3}-\d+\b`)
	spans = regexp.MustCompile(`\b([A-Z]{3})-(\d+)\s+to\s+([A-Z]{3})-(\d+)`)
)

func main() {
	decisions, err := fs.ReadFile(here, "REQUIREMENTS.md")
	if err != nil {
		fmt.Fprintln(os.Stderr, "unclaimed:", err)
		os.Exit(2)
	}
	want, width, err := requirementsIn(string(decisions))
	if err != nil {
		fmt.Fprintln(os.Stderr, "unclaimed:", err)
		os.Exit(2)
	}

	named, err := namedByDesigns(width)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unclaimed:", err)
		os.Exit(2)
	}

	var missing []string
	for _, id := range want {
		if !named[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		fmt.Printf("every one of the %d requirements is named by a design document\n",
			len(want))
		return
	}

	byArea := map[string][]string{}
	for _, id := range missing {
		byArea[id[:3]] = append(byArea[id[:3]], id)
	}
	areas := make([]string, 0, len(byArea))
	for area := range byArea {
		areas = append(areas, area)
	}
	sort.Strings(areas)

	fmt.Fprintf(os.Stderr, "%d of %d requirements are named by no design document:\n",
		len(missing), len(want))
	for _, area := range areas {
		fmt.Fprintf(os.Stderr, "  %s  %s\n", area, strings.Join(byArea[area], " "))
	}
	fmt.Fprintln(os.Stderr, "\nA requirement is named where the document that describes its area says how")
	fmt.Fprintln(os.Stderr, "it is met — or, where it is not built, says that. Neither is optional: the")
	fmt.Fprintln(os.Stderr, "chain from code to design to requirement is what makes this auditable.")
	os.Exit(1)
}

// requirementsIn is every requirement in force in the text of REQUIREMENTS.md,
// in the order it lists them, with the widest number each area's identifiers
// carry. A requirement recorded as withdrawn is left out: it is history rather
// than an obligation, and asking a design document to describe it would be
// asking for a description of something that is not there. A section holding
// no requirement is refused, since reading nothing would check nothing.
func requirementsIn(text string) ([]string, map[string]int, error) {
	from, to := strings.Index(text, inForceFrom), strings.Index(text, inForceTo)
	if from < 0 || to < 0 || to < from {
		return nil, nil, fmt.Errorf("REQUIREMENTS.md has no section of requirements")
	}
	var want []string
	width := map[string]int{}
	for _, match := range row.FindAllStringSubmatch(text[from:to], -1) {
		id, body := match[1], match[2]
		if strings.HasPrefix(strings.TrimSpace(strings.TrimLeft(body, "*")), "Withdrawn") {
			continue
		}
		want = append(want, id)
		if n := len(id) - 4; n > width[id[:3]] {
			width[id[:3]] = n
		}
	}
	if len(want) == 0 {
		return nil, nil, fmt.Errorf("the section of requirements holds no requirement in force, so this checked nothing")
	}
	return want, width, nil
}

// namedByDesigns collects every requirement identifier the design documents name.
//
// Design documents only. A requirement named in a commit message or a code
// comment is not described anywhere permanent — a comment describes one
// function rather than the system.
func namedByDesigns(width map[string]int) (map[string]bool, error) {
	designs, err := fs.Glob(here, "DESIGN-*.md")
	if err != nil {
		return nil, err
	}
	named := map[string]bool{}
	for _, path := range designs {
		body, err := fs.ReadFile(here, path)
		if err != nil {
			return nil, err
		}
		for id := range identifiersIn(string(body), width) {
			named[id] = true
		}
	}
	return named, nil
}

// identifiersIn is every requirement one document names, ranges expanded.
//
// Separate from the file reading so it can be asked directly. A range is how
// the documents state a run of them — "REQ-23 to REQ-25" names all three — and
// expanding one is the step that decides whether a decision claimed only by a
// range endpoint is claimed by a document or merely near one.
func identifiersIn(text string, width map[string]int) map[string]bool {
	named := map[string]bool{}
	for _, id := range one.FindAllString(text, -1) {
		named[id] = true
	}
	for _, span := range spans.FindAllStringSubmatch(text, -1) {
		// Never across areas. "REQ-70 to SEC-02" is two identifiers in a
		// sentence rather than a run, and expanding it would claim every
		// number between them under whichever prefix came first.
		if span[1] != span[3] {
			continue
		}
		first, _ := strconv.Atoi(span[2])
		last, _ := strconv.Atoi(span[4])
		for n := first; n <= last; n++ {
			named[fmt.Sprintf("%s-%0*d", span[1], width[span[1]], n)] = true
		}
	}
	return named
}
