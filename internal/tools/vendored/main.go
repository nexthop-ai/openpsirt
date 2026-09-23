// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command vendored checks the license of every file somebody else wrote that
// the tree carries.
//
// The dependency license check walks Go modules and the interface's packages,
// which is what is imported. What is copied in is checked by nothing there: a
// version suite taken from another project, a specification's example
// document, a publisher's advisory, a table transcribed from a reference
// implementation. Each is recorded in NOTICE by hand, and a habit is not a
// control.
//
// So the files that look like somebody else's are found in the tree, and each
// has to be accounted for in one list: where it came from and what it may be
// kept under. What finds them is deliberately broad — every fixture, and every
// file carrying a copyright or a license statement that is not this project's
// — because a file this misses is one nobody is asked about. The hard half is
// that a data file states its license in its own words where it states one at
// all, so the list is where somebody writes down what they read, and the gate
// holds them to having written it.
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/tools/provenance"
)

// entry is one file held in the tree, and what it may be kept under.
type entry = provenance.Entry

// held is the list the tree is held to.
var held = provenance.Held

// The names the list is written in.
const (
	ours         = provenance.Ours
	publicDomain = provenance.PublicDomain
	cweTerms     = provenance.CWETerms
)

var dataLicenses = []string{"CC0-1.0", "CC-BY-4.0", publicDomain, cweTerms}

// unattributed is the licenses that ask nothing of a recipient, so a file
// under one is not named in NOTICE. Every other license here asks for
// attribution.
var unattributed = map[string]bool{"CC0-1.0": true, publicDomain: true, ours: true}

// Marks of somebody else's text. A copyright line, a license stated in the
// form SPDX gives it, a document's data license, and a comment saying NOTICE
// records the file.
var marks = []*regexp.Regexp{
	regexp.MustCompile(`\bCopyright\s+(?:\([cC]\)\s*|©\s*)?(?:\d{4}|[A-Z])`),
	regexp.MustCompile(`SPDX-License-Identifier:`),
	regexp.MustCompile(`"dataLicense"`),
	regexp.MustCompile("`NOTICE` records"),
}

// ownLicense is the identifier naming this tree's own license and nothing
// else.
var ownLicense = regexp.MustCompile(`SPDX-License-Identifier:\s*Apache-2\.0\s*(?:\*/)?\s*$`)

// itself is where this program and the list it reads live, both of which
// spell every mark it looks for.
var itself = map[string]bool{"internal/tools/vendored": true, "internal/tools/provenance": true}

// Our own name, which a copyright line naming is not somebody else's.
const owner = "Nexthop Systems Inc."

// A path NOTICE names: a file under one of the tree's top-level directories.
// Taken from where the path begins, so a directory named partway along one is
// not read as the start of a second.
var named = regexp.MustCompile(`(?:^|[^A-Za-z0-9_./-])((?:internal|testdata|web|cmd|deploy)/[A-Za-z0-9_./-]*[A-Za-z0-9_])`)

func main() {
	allowed := strings.Split(os.Getenv("ALLOWED_LICENSES"), ",")
	if len(allowed) == 0 || strings.TrimSpace(allowed[0]) == "" {
		fmt.Fprintln(os.Stderr, "vendored: ALLOWED_LICENSES is unset; run it through make")
		os.Exit(2)
	}
	listed, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vendored: listing the tree:", err)
		os.Exit(2)
	}
	var tracked []string
	for _, each := range bytes.Split(listed, []byte{0}) {
		if len(each) > 0 {
			tracked = append(tracked, string(each))
		}
	}
	notice, err := os.ReadFile("NOTICE")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vendored:", err)
		os.Exit(2)
	}
	found, faults := check(tracked, os.ReadFile, held, string(notice), append(allowed, dataLicenses...))
	for _, fault := range faults {
		fmt.Fprintln(os.Stderr, fault)
	}
	if len(faults) > 0 {
		os.Exit(1)
	}
	fmt.Printf("every file somebody else wrote is accounted for, under a license it may be kept under "+
		"(%d found over %d files, %d held)\n", found, len(tracked), len(held))
}

// check finds the files that have to be accounted for and holds the list to
// them, in both directions. It returns how many it found, and what is wrong.
func check(tracked []string, read func(string) ([]byte, error), held []entry,
	notice string, allowed []string) (int, []string) {

	var faults []string
	in := map[string]bool{}
	for _, each := range tracked {
		in[each] = true
	}
	holds := map[string]entry{}
	for _, each := range held {
		holds[each.Path] = each
	}
	inNotice := map[string]bool{}
	for _, each := range noticed(notice) {
		inNotice[each] = true
	}
	permitted := map[string]bool{ours: true}
	for _, each := range allowed {
		permitted[strings.TrimSpace(each)] = true
	}

	found := 0
	for _, each := range tracked {
		why, err := needed(each, read)
		if err != nil {
			faults = append(faults, fmt.Sprintf("%s: %v", each, err))
			continue
		}
		if why == "" {
			continue
		}
		found++
		if _, ok := holds[each]; !ok {
			faults = append(faults, fmt.Sprintf(
				"%s %s, and nothing says where it came from or what it may be kept under: "+
					"add it to internal/tools/provenance/held.go", each, why))
		}
	}
	if found == 0 {
		faults = append(faults, "no file in the tree looked like somebody else's, so this checked nothing")
	}

	for _, each := range held {
		if !in[each.Path] {
			faults = append(faults, fmt.Sprintf("%s is held and is not in the tree", each.Path))
		}
		if !keepable(each.License, permitted) {
			faults = append(faults, fmt.Sprintf("%s is under %s, which is not a license this tree may carry",
				each.Path, each.License))
		}
		if each.License != ours && each.Source == "" {
			faults = append(faults, fmt.Sprintf("%s says nothing about where it came from", each.Path))
		}
		if !asksNothing(each.License) && !inNotice[each.Path] {
			faults = append(faults, fmt.Sprintf("%s is under %s, which asks for attribution, and NOTICE does not name it",
				each.Path, each.License))
		}
	}

	paths := noticed(notice)
	if len(paths) == 0 {
		faults = append(faults, "NOTICE names no file, so the half of this reading it checked nothing")
	}
	for _, each := range paths {
		one, ok := holds[each]
		switch {
		case !in[each]:
			faults = append(faults, fmt.Sprintf("NOTICE names %s, which is not in the tree", each))
		case !ok:
			faults = append(faults, fmt.Sprintf("NOTICE names %s, and the list does not hold it", each))
		case one.License == ours:
			faults = append(faults, fmt.Sprintf("NOTICE names %s, and the list holds it as ours", each))
		}
	}
	sort.Strings(faults)
	return found, faults
}

// needed says why a file has to be accounted for, or nothing where it does
// not.
//
// NOTICE and LICENSE are the statements themselves. A markdown file is prose
// about the tree, and the fixture READMEs describe licenses in words. This
// program's own source, and the list it reads, spell every mark it looks for.
func needed(file string, read func(string) ([]byte, error)) (string, error) {
	base := path.Base(file)
	if file == "NOTICE" || file == "LICENSE" || strings.HasSuffix(base, ".md") ||
		itself[path.Dir(file)] {
		return "", nil
	}
	if strings.HasPrefix(file, "testdata/") || strings.Contains(file, "/testdata/") {
		return "is a fixture", nil
	}
	content, err := read(file)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(content) {
		return "", nil
	}
	lines := strings.Split(string(content), "\n")
	// A file carrying our copyright is ours, and the license identifier
	// beside it naming this tree's own license says nothing more. Any other
	// identifier in it is still somebody else's terms.
	mine := false
	for _, line := range lines {
		if strings.Contains(line, "Copyright "+owner) {
			mine = true
		}
	}
	for _, line := range lines {
		if strings.Contains(line, owner) || (mine && ownLicense.MatchString(line)) {
			continue
		}
		for _, mark := range marks {
			if mark.MatchString(line) {
				return fmt.Sprintf("says %q", strings.TrimSpace(mark.FindString(line))), nil
			}
		}
	}
	return "", nil
}

// noticed is every path NOTICE names, once each.
func noticed(notice string) []string {
	seen := map[string]bool{}
	var paths []string
	for _, match := range named.FindAllStringSubmatch(notice, -1) {
		each := match[1]
		if !seen[each] {
			seen[each] = true
			paths = append(paths, each)
		}
	}
	return paths
}

// keepable says whether a license expression is one this tree may carry: any
// one of the alternatives an OR offers, or every term an AND joins.
func keepable(expression string, permitted map[string]bool) bool {
	for _, alternative := range strings.Split(expression, " OR ") {
		all := true
		for _, term := range strings.Split(alternative, " AND ") {
			if !permitted[strings.Trim(strings.TrimSpace(term), "()")] {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}

// asksNothing says whether a license asks nothing of a recipient.
func asksNothing(license string) bool {
	return unattributed[license]
}
