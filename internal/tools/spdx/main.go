// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command spdx holds every source file in the tree to a copyright line and a
// license identifier at its head.
//
// The identifier is what a scanner reads to say which license a file is
// under, file by file, without reading LICENSE and guessing the rest applies.
// A file carrying somebody else's work says so in the same line: the list of
// such files decides the expression each one states, so this gate and the one
// holding that list cannot disagree about a file.
//
// Run with -fix it writes the header into every file missing one. A file
// carrying a header that is wrong is reported and left alone, because which
// of the two is right is a person's to read.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/provenance"
)

// owner is who holds the copyright in what this project wrote.
const owner = "Nexthop Systems Inc."

// own is the license this tree is under.
const own = "Apache-2.0"

// style is how one kind of file writes a comment.
type style int

const (
	none style = iota
	// slashes is a line comment of two slashes.
	slashes
	// block is a comment between a slash-star and a star-slash, one per line.
	block
	// hashes is a line comment of one hash.
	hashes
)

// generated is files a third party's tool writes whole, which a header would
// be taken off every time they are written.
var generated = map[string]string{
	"web/src/api/schema.d.ts": "written whole by openapi-typescript from the API document",
}

// styleOf is how a file writes a comment, or none where it is not source.
func styleOf(file string) style {
	base := path.Base(file)
	switch {
	case base == "Makefile" || strings.HasPrefix(base, "Makefile.") ||
		base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile."):
		return hashes
	}
	switch path.Ext(base) {
	case ".go", ".ts", ".tsx", ".js", ".mjs", ".cjs":
		return slashes
	case ".css":
		return block
	case ".sh", ".py":
		return hashes
	}
	return none
}

// covered says whether a file is held to a header, and why not where it is
// not.
func covered(file string) (bool, string) {
	if strings.HasPrefix(file, "testdata/") || strings.Contains(file, "/testdata/") {
		return false, "a fixture"
	}
	if why, is := generated[file]; is {
		return false, why
	}
	return styleOf(file) != none, ""
}

// licenseOf is the expression a file states: this tree's own, joined with the
// terms of whatever somebody else's work it carries.
func licenseOf(file string, held []provenance.Entry) string {
	for _, each := range held {
		if each.Path != file {
			continue
		}
		switch each.License {
		case provenance.Ours, own:
			return own
		}
		if strings.Contains(each.License, " ") {
			return own + " AND (" + each.License + ")"
		}
		return own + " AND " + each.License
	}
	return own
}

// header is the lines a file of this style opens with.
func header(s style, license string) []string {
	copyright := "Copyright " + owner
	identifier := "SPDX-License-Identifier: " + license
	switch s {
	case slashes:
		return []string{"// " + copyright, "// " + identifier}
	case block:
		return []string{"/* " + copyright + " */", "/* " + identifier + " */"}
	default:
		return []string{"# " + copyright, "# " + identifier}
	}
}

// preamble is how many lines at the head of a file have to stay first: an
// interpreter line, and the parser directives a Dockerfile reads only from its
// top.
func preamble(lines []string, s style) int {
	at := 0
	if at < len(lines) && strings.HasPrefix(lines[at], "#!") {
		at++
	}
	for s == hashes && at < len(lines) {
		lower := strings.ToLower(strings.TrimSpace(lines[at]))
		if !strings.HasPrefix(lower, "# syntax=") && !strings.HasPrefix(lower, "# escape=") &&
			!strings.HasPrefix(lower, "# check=") {
			break
		}
		at++
	}
	return at
}

// fault is what is wrong with one file's head, or nothing.
//
// The header comes first, after anything that has to stay first, and a blank
// line or the end of the file follows it. Where an identifier appears
// elsewhere in the file's opening lines the header is wrong rather than
// missing, and writing a second one would leave the file stating two.
func fault(content []byte, s style, license string) (string, bool) {
	lines := strings.Split(string(content), "\n")
	at := preamble(lines, s)
	// Set off from what has to stay first by blank lines, as stamping writes
	// it.
	for at > 0 && at < len(lines) && strings.TrimSpace(lines[at]) == "" {
		at++
	}
	want := header(s, license)
	matches := at+len(want) <= len(lines)
	for i := 0; matches && i < len(want); i++ {
		matches = strings.TrimRight(lines[at+i], " \r") == want[i]
	}
	if matches {
		after := at + len(want)
		if after < len(lines) && strings.TrimSpace(lines[after]) != "" {
			return "its header is not followed by a blank line", false
		}
		return "", false
	}
	for i := 0; i < len(lines) && i < at+10; i++ {
		if strings.Contains(lines[i], "SPDX-License-Identifier:") {
			return fmt.Sprintf("its header does not read %q", strings.Join(want, " / ")), false
		}
	}
	return "it has no license identifier", true
}

// stamped is content with the header written in.
func stamped(content []byte, s style, license string) []byte {
	lines := strings.Split(string(content), "\n")
	at := preamble(lines, s)
	head := append(header(s, license), "")
	if at > 0 {
		head = append([]string{""}, head...)
	}
	out := append(append(append([]string{}, lines[:at]...), head...), lines[at:]...)
	return []byte(strings.Join(out, "\n"))
}

func main() {
	fix := flag.Bool("fix", false, "write the header into every file missing one")
	flag.Parse()

	listed, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "spdx: listing the tree:", err)
		os.Exit(2)
	}
	var faults []string
	examined, written := 0, 0
	for _, each := range bytes.Split(listed, []byte{0}) {
		file := string(each)
		if file == "" {
			continue
		}
		if in, _ := covered(file); !in {
			continue
		}
		content, err := os.ReadFile(file) //nolint:gosec // G304: a path git lists in this checkout
		if err != nil {
			faults = append(faults, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		examined++
		s := styleOf(file)
		license := licenseOf(file, provenance.Held)
		wrong, missing := fault(content, s, license)
		switch {
		case wrong == "":
		case missing && *fix:
			// The file exists, so its mode is kept; the one given here applies
			// only to a file being created.
			//nolint:gosec // G703: a path git lists in this checkout, read just above
			if err := os.WriteFile(file, stamped(content, s, license), 0o600); err != nil {
				faults = append(faults, fmt.Sprintf("%s: %v", file, err))
				continue
			}
			written++
		default:
			faults = append(faults, fmt.Sprintf("%s: %s", file, wrong))
		}
	}
	if examined == 0 {
		faults = append(faults, "no source file was found, so this checked nothing")
	}
	for _, fault := range faults {
		fmt.Fprintln(os.Stderr, fault)
	}
	if len(faults) > 0 {
		if !*fix {
			fmt.Fprintln(os.Stderr, "run 'make spdx-fix' to write the header into files missing one")
		}
		os.Exit(1)
	}
	if *fix {
		fmt.Printf("wrote the header into %d of %d source files\n", written, examined)
		return
	}
	fmt.Printf("every source file states its copyright and license (%d files)\n", examined)
}
